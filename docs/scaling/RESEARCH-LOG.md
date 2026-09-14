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

## 5b. A mistake worth recording: dropping disassembly before hashing

While building the full real corpus, disk ran low and I dropped the `xcfg` collection mid-run
to reclaim it, on the belief that disassembly is retrievable detail the matching path never
reads. **That belief was wrong, and it cost the run.** `xcfg` is the *input* to minhash
computation - `Worker.calculateMinHashes` reads `FunctionEntry.xcfg` through
`_attachXcfgBlobs` - so removing it before a sample is hashed leaves that sample permanently
unhashable. The damage was silent: no error, no failed job, just 3.97M of 5.2M functions
carrying neither disassembly nor a minhash, and a corpus that would have quietly under-reported
every match had it been measured.

It was recoverable because the failure had a clean boundary - every sample hashed before the
drop was fine, everything after it was not - so the 2,540 affected samples were deleted (they
had no band entries either, never having been hashed) and the validated 2,016-sample corpus was
re-verified against its earlier numbers before anything else was done to it.

The underlying defect was in the harness, not the impulse. Two-phase indexing (add everything,
then hash everything) exists because per-sample hashing spawns a process pool per sample and
measured 3.1 s a sample; but it also holds the disassembly of *every* sample in the run at once,
and `xcfg` is ~70% of the stored bytes - 4.28 GB for 3.3M functions on a host with 8 GB free.
`benchmarks/bench_matching.py` now adds, hashes and drops **per chunk**, which keeps the pool
amortised while bounding peak disk to one chunk's disassembly. MCRIT's own
`updateMinHashesForSample` already had the right shape; the harness had optimised it away.

Two general lessons, both cheap to state and expensive to learn:

- *"The query path never reads it"* is not the same as *"nothing needs it"*. Ask what **writes**
  depend on it too.
- Reclaiming disk under pressure is exactly when a destructive shortcut looks reasonable. The
  same pressure is what makes it a bad time to reason about what is safe to delete.

## 5c. The pattern behind the mistakes, and the checks that would have caught them

Six defects were introduced and fixed during this work. Listing them separately undersells what
they have in common, which is more useful than any one of them:

| What was assumed | What was true | How it failed |
|---|---|---|
| Disassembly is retrievable detail the query path never reads | It is the *input* to minhash computation | 3.97M functions silently unhashable |
| The PicHash cutoff bounds the work | It counted holders with `$group`, touching one index entry per holder including for rejected hashes | the stage kept growing, 1.80x per 1.49x corpus |
| A rebuild is complete when it finishes | The flag said complete from the moment the collection was emptied | an interrupted rebuild left a trusted, empty index |
| Upserts are fast | No index existed yet, so each one scanned the collection | ~35 upserts/s against ~9,400/s once indexed |
| The counts disagree, so maintenance is broken | The verification was reading while the indexer wrote | a real bug reported where none existed |
| The test passes, so the code is right | pymongo returns a fresh `Collection` per attribute access, so the patch did nothing | two tests that passed against code with the bug |

**The common cause is one thing: trusting a plausible model of the system instead of checking
it.** Every entry above is a reasonable belief that happened to be false, and in every case the
check that would have settled it was cheap.

**The sharpest sub-pattern is silence.** A dropped xcfg, a half-built index behind a complete
flag, a missing pichash count - none of these raise. They under-report matches and leave a
database that looks healthy. In a system whose job is to *find* things, the dangerous failure is
not the crash, it is the quiet absence. So the question to ask of any new index or filter here
is not "does this work" but "if this were wrong, would anything say so".

**The most expensive one was a repeat.** The PicHash `$group` is the same defect as the band
`$size` filter, which had already been diagnosed, fixed and written down in this very document -
and then not looked for in the analogous path. Fixing a bug without asking where else its shape
occurs costs more than the original bug.

The cheap checks, in the order they pay off:

1. **Ask what *writes* depend on it**, not only what reads it, before deleting anything.
2. **Check whether anything is writing** before trusting a verification.
3. **Verify the test can fail** - against the unfixed code, or by proving the mechanism bites.
4. **Grep for the shape of a bug you just fixed** before closing it out.
5. **Run it small first.** Both the chunked indexer and the pichash count index were smoke-tested
   on a throwaway database before being run against the real corpus; both times that was the
   step that confirmed the invariant rather than assuming it.

## 5d. A seventh defect, found after the results were published

The three real-corpus points were reported, committed and pushed. Refitting them from the raw
JSON afterwards - to derive the exponents rather than transcribe them - produced k = +0.68 on
the median instead of the published +1.25. One of the two numbers was wrong.

The JSON recorded corpus sizes of 1,571 / 5,089 / 7,328. The summary quoted 2,016 / 2,996 /
5,243. The harness had been taking its x-axis from `index.getStatus()`, which sums the
denormalised per-family counters - and `_updateFamilyStats` logs a warning and *skips its
decrement* when a family document is missing, so the 2,540 samples deleted during the xcfg
recovery were never subtracted from them.

The drift is measurable today: the counters claim 7,414 samples against 5,322 that exist, an
overstatement of 2,092. It is also constant, which is what made the published numbers
recoverable rather than merely suspect. Subtracting it reproduces the quoted sizes: 5,089 ->
2,997 against 2,996 quoted, 7,328 -> 5,236 against 5,243, and on the current corpus it lands
exactly. An independent artefact agrees: the range rebuild at the third point covered 4,760
samples, consistent with 5,236 of which 476 have no functions.

So the published results stand - the quoted sizes were counted, not read from `/status` - but
the JSON preserved the wrong one of the two numbers, and nothing in the pipeline noticed the two
sources disagreeing by 40%.

Three things are worth extracting:

- **A derived number and a displayed number must come from the same place.** The summary counted;
  the JSON asked `/status`. Both were written by the same run, and they disagreed for months of
  wall-clock without complaint. The fix is not "use the right one" but to record both and warn
  when they differ, which the harness now does.
- **Denormalised counters are a silent-failure shape**, the same one as 5c: an incremental
  counter with a skip path that only logs. `recomputeFamilyStats` (upstream, #151) exists
  precisely because this drifts, which is evidence the failure is endemic rather than incidental
  to this corpus.
- **Re-deriving a published result is a check, not ceremony.** This surfaced only because the
  exponents were recomputed from files instead of being trusted, and that happened after the work
  was called finished. The result survived; the instrument did not.

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
