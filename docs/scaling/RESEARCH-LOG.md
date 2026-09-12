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

---

## 4. Measurements

### The corpus

- **Real**: 257 Malpedia samples disassembled with SMDA -> 280,804 functions, 185,387 of them
  hashed (the rest fall below `MINHASH_FN_MIN_INS`). A further ~1.5k samples were pulled from
  the Malpedia API in the background; the API enforces a cumulative quota, so the fetch is
  paced and resumable rather than parallel.
- **Synthetic**: grown from that real population by `benchmarks/synth_corpus.py`, which draws
  functions-per-sample from the real empirical distribution and signatures from a
  preferential-attachment urn calibrated so the distinct-signature count follows the Heaps'
  law *measured* on the real corpus. Validated against the law it targets to within 1.6%.

### Corpus structure (257 real samples, `benchmarks/analyze_corpus.py`)

| Distribution | p50 | p90 | p99 | p99.9 | max |
|---|---|---|---|---|---|
| band posting lists | 1 | 9 | 42 | 181 | **3,598** |
| pichash posting lists | 1 | 4 | 20 | 96 | **16,976** |
| minhash signature groups | 1 | 5 | 22 | 70 | 458 |

The median band hash is held by a single function and the maximum by thousands: the skew the
whole design turns on. 185,387 hashed functions carry only **75,323 distinct signatures**.

`benchmarks/measure_growth.py` fits **V(n) = 1412.8 * n^0.7247** over samples, extrapolating to
~31.5M distinct signatures at a million samples against ~750M functions - a **~24x** signature
dedup factor there, versus 2.46x at 257 samples.

### The baseline does not scale (fixed query set, same corpus, growing)

| corpus | median 1-vs-N | sample 148 candidate pairs | sample 148 matched samples |
|---|---|---|---|
| 257 | 0.268 s | 20,744 | 35 |
| 993 | 0.520 s | 33,328 | 568 |
| 10,000 | 3.128 s | 361,325 | 5,930 |

From 993 to 10,000 samples the corpus grew 10x; candidate pairs grew **10.8x**, matched samples
**10.4x**, and latency **6.0x** (latency ~ corpus^0.78). Extrapolated to a million samples that
is ~2 minutes per query, which is the reported problem exactly.

Note what the middle columns say: the growth is not an inefficiency, it is the *answer* getting
bigger. 5,930 matched samples is not a result anybody reads.

### Two-stage matching at 10,000 samples

| configuration | median | vs stock |
|---|---|---|
| one-stage (stock) | 3.128 s | - |
| two-stage, shortlist 100 | 0.814 s | 3.8x |
| two-stage, shortlist 100 + df cutoff 1000 | 0.696 s | **4.5x** |

Per stage, on the widest query (sample 148, 754 query functions), stock vs two-stage:
matching-cache fetch 0.923 s -> 0.069 s, scoring 0.411 s -> 0.048 s, result assembly
0.930 s -> 0.058 s. Those three stopped scaling with the corpus; what remains is stage 1.

### Quality (`benchmarks/compare_quality.py`, 10,000 samples, vs unrestricted)

- **top-10 sample recall 1.000**, **top-25 sample recall 1.000**
- **0.9945** of surviving function matches keep a bit-identical score
- overall sample recall 0.67 - which is the shortlist doing its job, not a defect: sample 148's
  5,930 matched samples become 99

## 5. Things that were wrong, and how measurement caught them

- **The quality metric itself.** `matched.percent.score_weighted` is nested; reading a flat key
  returned 0.0 for every sample, so "top-10 recall" was comparing two arbitrary orderings and
  reported 0.60 for a shortlist that was in fact keeping all ten. Fixed, and the reader now
  raises rather than defaulting to 0.0.
- **Ranking the shortlist by vote count.** MCRIT scores a matched sample by the *percentage* of
  it that matched, so a small sample whose few functions all match outranks a large one sharing
  them. Count-ranking dropped exactly those. Now ranked by count and coverage, interleaved.
- **Ignoring PicHash evidence in the vote.** A sample can be reported through exact matches
  alone; ranking on band votes alone dropped samples the unrestricted matcher ranked highly.
- **Filtering the cutoff with `$size`.** Correct but nearly worthless - mongod reads every
  document to measure it. Measured at 10k: cutoffs of 20000/5000 gave 0.822 s/0.890 s against
  0.814 s for no cutoff. Storing `df` with a (band_hash, df) index gave 0.807 s/0.696 s.
- **Boxing candidates twice.** Accumulation is numpy, was boxed to Python sets, and the
  shortlist unboxed them again. The restriction pass also re-resolved every candidate's sample.
  Vectorising both took the restriction from 1.063 s to 0.009 s.
- **Assuming one contiguous id run per sample.** True on the normal path, false when writers
  interleave counter reservations - which happened on this corpus and silently disabled the
  shortlist. Spans are now stored per run, exact for any layout.

## 6. Operational notes (things that cost real time here)

- **mongod aborts rather than degrades when it runs out of file descriptors.** The container's
  default `nofile` is 1024; WiredTiger hits EMFILE while creating a collection and takes the
  whole server down with a panic, which looks like data loss. Run it with
  `--ulimit nofile=20000:20000` and keep client pools small (`maxPoolSize`), especially in
  harnesses that build a fresh client per measured run.
- **Malpedia's API enforces a cumulative quota, not just a rate.** Concurrency makes it worse:
  8 threads produced 1,378 rate-limit failures against 136 successes. One or two threads under
  a global pace, with the sample listing cached so a restart during a cooldown does not die on
  its first call, fetches reliably.
