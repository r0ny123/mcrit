# Scaling MCRIT 1-vs-N matching: research log

Running log of the investigation into making 1-vs-N function matching stay fast as the
corpus grows. Newest findings are appended; dead ends are kept deliberately, because the
reason an option was rejected is the part that is expensive to rediscover.

## 1. Where the cost actually is

A 1-vs-N query (`MatcherSample.getMatchesForSample`, `MatcherQuery.getMatchesForSmdaReport`)
runs five stages, in `MatcherInterface._getMatchesRoutineInner`:

| # | Stage | Code | Grows with corpus because |
|---|-------|------|---------------------------|
| 1 | PicHash lookup | `_getPicHashMatches` -> `storage.getPicHashMatchesBySampleId` | a pichash held by many samples returns one tuple per holder |
| 2 | Band candidate generation | `_createMinHashCandidateGroups` -> `storage.getCandidatesForMinHashes` | band posting lists lengthen linearly with the number of indexed functions |
| 3 | Matching-cache fetch | `_createMatchingCache` -> `storage.createMatchingCache` | one signature fetched per distinct candidate |
| 4 | Pairwise scoring | `_performMinHashMatching(Vectorized)` | one comparison per (query function, candidate) pair |
| 5 | Result assembly | `_craftResultDict` / `_summarizeMatches` | one `MatchedSampleEntry` per matched sample |

Every one of the five is linear in corpus size. That is the whole problem: there is no
single hot spot to optimise, the *shape* of the computation is wrong. Constant-factor work
already in the tree (numpy candidate accumulation, vectorised scoring, the incremental
matching cache, threaded cache fetch, the pair budget) lowers the slope but cannot change it.

### The deeper reason: the output is O(N)

If a million corpus samples all statically link zlib and the query links zlib too, then a
million samples genuinely "match". Stage 5 is linear because *the answer is linear*. No
index can fix that; the API has to stop asking for it. Every system that does this at scale
returns top-K, and the engineering question is how to find the right K without scoring N.

## 2. What the literature says

### Two-stage retrieval ("retrieve then rerank") is the consensus answer

- **CEBin** (ISSTA 2024, [arXiv:2402.18818](https://arxiv.org/abs/2402.18818)) is the closest
  analogue in our own domain: large-scale binary code similarity detection. It uses an
  embedding-based **retrieval** stage to narrow the candidate pool, then a **comparison**
  stage doing pairwise work only on that shortlist. It reports identifying a similar
  function out of *millions* of candidates in seconds, "several orders of magnitude"
  faster than pairwise baselines, at 85.46% recall on 1-day vulnerability detection.
  This is direct evidence that the two-stage shape - not a better index alone - is what
  buys the scale.
- The same architecture is standard in IR and recommendation (cheap recall stage feeding an
  expensive precision stage), and reduces reranker cost from O(N) to O(K).

**Consequence for MCRIT:** the second stage already exists and is already correct -
`MatcherVsGroup` matches one sample against an explicit list of samples. What is missing is
a cheap stage 1 that produces that list without touching the whole corpus.

### Billion-scale ANN indexes (FAISS / ScaNN / HNSW / DiskANN / SPANN / Milvus / Qdrant / Vespa)

These solve *vector* nearest-neighbour search over dense embeddings. MCRIT's signatures are
not dense vectors: a MinHash signature is 64 one-byte fields compared for **exact field
equality**, and the similarity estimated is Jaccard, not cosine or L2. Feeding MinHash
signatures to a cosine/L2 ANN index does not estimate the same quantity, so adopting one
means changing what "similar" means - which the goal forbids ("no degradation in matching
quality"). They are the right tool if and only if MCRIT moves to learned embeddings, which
is a different project with a different quality argument.

MCRIT already *has* the right index structure for Jaccard/MinHash: LSH banding over an
inverted index. Replacing it with an ANN library would be trading a correct index for a
fashionable one.

### LSHBloom (arXiv:2411.04257) - rejected, solves a different problem

Replaces per-band posting lists with per-band Bloom filters, which is far more memory
efficient at extreme scale. But a Bloom filter answers *membership* ("does a near-duplicate
of this exist?"), and cannot enumerate *which* corpus functions matched. MCRIT must return
the matches, not merely detect them. Usable at most as a cheap negative pre-filter; it
cannot replace the posting lists.

### The skew problem is a solved problem in IR

Candidate-set explosion at scale is the classic long-posting-list problem of full-text
search, and the classic answers apply directly:

- **IDF weighting** - a band hash held by a large fraction of the corpus carries almost no
  information about *which* samples are similar. A library function shared by every sample
  is the binary-similarity equivalent of a stopword.
- **Document-frequency cutoff / stopword elimination** - skip the posting lists that are so
  long they cannot discriminate. Bounds stage-1 cost by construction.
- **WAND / MaxScore early termination** - process posting lists so that lists which cannot
  change the current top-K are skipped entirely.

These bound stage-1 work *independently of N*, which is exactly the property the goal needs.

## 3. Working hypothesis (to be confirmed by measurement, not assumed)

1. Band posting-list lengths are heavily skewed (Zipfian), so a small number of
   non-discriminative band hashes account for most candidate volume.
2. Many corpus functions share byte-identical MinHash signatures. Since a score depends only
   on the two signatures, scoring one representative per distinct signature is **exactly**
   equivalent to scoring every member - making that share of stage 4 provably redundant.
3. Therefore: a top-K sample shortlist built from *discriminative* band hashes only, followed
   by the existing exact `MatcherVsGroup` against those K samples, can hold latency roughly
   flat in N while leaving the reported matches for those K samples bit-identical.

`benchmarks/analyze_corpus.py` measures (1) and (2); `benchmarks/bench_matching.py` measures
the per-stage growth curve that (3) has to beat.
