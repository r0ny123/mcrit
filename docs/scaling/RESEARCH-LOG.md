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

## 5e. Three more defects, and the one that measurement could never have found

Growing the corpus from 5,236 to 7,244 samples for the fourth measurement point surfaced three
further defects. The first two are ordinary scale bugs. The third is the interesting one.

**`LogBucket` KeyError.** The table is precomputed for `0..99,999`; `FuzzyStatPairShingler` feeds
it `max_block_size`, `num_ins_C`, `num_ins_S` and `num_calls`, none of them bounded - though
`stack_size` *is* clamped at its call site, so the bound was known and applied in one place only.
A basic block of 108,837 bytes raised, the exception propagated out of the hashing pool, and the
indexing job died after 951 samples. One oversized function makes an entire corpus unindexable,
and the odds of containing one rise with corpus size. Clamped at the single lookup; no value
inside the table moves, so no existing MinHash changes.

**`updateMinHashes` UnboundLocalError.** `minhashes` was bound only inside the batch loop, so
`return len(minhashes)` raised whenever the loop did not run - that is, whenever there was
nothing left to hash, which is the normal state of a resumed index. Finishing successfully failed
exactly like crashing. Reading the callers before fixing turned up a second defect in the same
statement: it returned the *last batch's* size rather than the total, under-reporting every
multi-workpack run. A one-line `minhashes = []` would have fixed the crash and left that in
place - the quieter and more dangerous of the two.

**The shortlist ranking read the whole corpus, and no benchmark could have shown it.**
`_rankShortlist` ranks candidates by coverage as well as by vote count, so it needs a function
count per candidate - and it fetched the count of *every sample in the corpus*, once per matching
job. At 7,244 samples that map is 5,034 entries and costs nothing. Four measurement points across
3.59x of growth show no trace of it, because there is no trace to show: the cost is invisible
until the corpus is large enough that it is fatal, and then it is a wall rather than a gradient.
At 10^9 samples it is a 10^9-entry dict built per query.

It was found by asking "what in this code is shaped like the corpus" instead of "what does the
profile say". That is a different activity from benchmarking, and this project had been doing only
the second. **A benchmark can only find costs that are already visible at the size you can
afford to run.** Every other defect in this log was caught by measurement; this one was
structurally out of measurement's reach, and it was the most consequential for the stated goal.

The general form, worth keeping: *before claiming a design scales, enumerate every data structure
whose size follows the corpus and check whether the request path touches it.* The five query
stages had all been bounded deliberately. This one was introduced by the fix for the others, in
support code nobody thought of as the query path, and it sat there through four rounds of
benchmarking.

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

## 7. Concurrency, and three ways the harness lied before it told the truth

Every earlier number in this log is one query at a time. That was a deliberate simplification
and it stopped being defensible once the result was going into a pull request: the first thing a
maintainer asks about a change to the matching path is what happens when ten people query at
once, and "we never measured that" is not an answer. `benchmarks/bench_concurrency.py` closes it.

### Deciding what "concurrent" means before measuring it

The choice that mattered was not the tooling but reading how MCRIT actually runs a job.
`SpawningWorker._executeJobPayload` spawns `python -m mcrit singlejobworker`, then *blocks on
`console_handle.wait()`* before its poll loop claims the next job. One worker is therefore one
job at a time, in a dedicated OS process, and concurrency in a real deployment means running
several worker processes. That settles a question that would otherwise have been guessed:
threads would have measured GIL contention that production never experiences, and a thread pool
would have been the wrong shape rather than merely a different one.

So each level is C independent processes started with the "spawn" method, each building its own
`MinHashIndex`. What that model leaves out is the REST hop, the queue round trip, and the
per-job interpreter start-up - all constants that fall equally on both configurations. The
start-up constant was measured rather than waved at, at **1.65 s**, and it turned out to be the
most surprising number in the exercise: a two-stage query is 1.27 s, so a production
single-job worker spends more time starting Python than matching. That is an argument for a
resident worker pool, and nothing in a serial latency measurement would have suggested it.

### The result

Peak on this 4-core, 15.7 GB box: **3.19 req/s two-stage against 0.259 one-stage, 12.3x**. Both
saturate the same four cores (3.99 of 4 busy at concurrency 16), so the design does not raise the
ceiling; it lowers the price of a query, from **16.32 CPU-seconds to 1.36**, and throughput
follows that ratio almost exactly. Full tables in `SUMMARY.md`.

Two things are worth extracting beyond the headline.

**The baseline saturates mongod as well as the CPU; two-stage does not.** WiredTiger's read
tickets queued for 332 seconds across the one-stage runs at concurrency 16, and for **0.02
seconds** across two-stage's. The CPU split says the same thing from the other side: one-stage
spends half its per-request CPU inside mongod, two-stage a fifth of a far smaller number. The
baseline has two walls; bounding the work removed one of them entirely.

**The advantage widens, then narrows, and the narrowing is the same effect the cold-cache runs
found.** 13.7x at one query, 18.5x at two, 11.1x at sixteen. Past saturation two-stage's
per-request CPU inflates 30% while the baseline's does not, because two-stage's win comes from
touching very little and is therefore the configuration with the most locality to lose when
sixteen workers evict each other. The measurement that reads as a weakness under load is the
same property that reads as a strength when the cache is warm.

### Three defects in the harness, found before they became results

Worth recording because all three produced plausible output rather than an error, which is the
failure mode this log keeps collecting.

**A read-only check that was too slow to run.** The first proof of read-only-ness counted every
collection with `count_documents({})`. On this corpus that scans 28.7 million `_id` entries
across 35 collections, and the run simply sat there - I had it diagnosed as a deadlock in the
worker pool, and went looking in the wrong place, before noticing the last line printed was the
snapshot. The fix is not "count faster" but noticing that counting was the wrong witness anyway:
`dbstats.objects` is an exact total for free, and mongod's per-namespace `top` counters catch the
in-place update that no count would have shown.

**`self._stop` on a `threading.Thread` subclass.** The resource sampler stored its stop flag as
`self._stop`, which is a name `threading.Thread` already owns - `join()` calls it. The thread
ran correctly, sampled correctly, and then made the process unjoinable, so the failure surfaced
at the *end* of a level as `TypeError: 'Event' object is not callable` rather than where the
mistake was.

**The query mix depended on the concurrency level.** Requests were handed out round-robin over
three query samples whose costs span 5x, with a fixed count per worker. With four requests per
worker, concurrency 1 ran six `win.zloader` against three each of the others - 50/25/25 - while
concurrency 16 ran even thirds. Each level was internally consistent and the throughput curve
looked entirely reasonable; it was partly a curve of *which queries ran*, and the worst-skewed
level was concurrency 1, the baseline every speedup on the level is divided by. The harness now
rounds each level up to whole passes over the query set, and the one-stage run was redone.

None of the three would have announced itself in the output. The one that would have survived
into the pull request is the third, because its symptom was a plausible number.

### Measuring on a shared box, and admitting it in the data

The first attempt produced a two-stage p50 of **93.95 s** against a published serial median of
1.60 s. Nothing was wrong with the harness: other work on the same host was churning the same
3 GB WiredTiger cache, and `currentOp` showed a 75-second `getmore` on `real.functions` under an
`IXSCAN` that normally costs milliseconds. Rather than trusting a quiet-looking box, the harness
now records machine-wide busy CPU minus the workers' own minus mongod's, and reports it per
level as `foreign_cpu_fraction`. In the runs that were kept it is **0.0% for two-stage and at
most 2.0% for one-stage**, which is the difference between a measurement and an anecdote.

### Read-only, proven rather than promised

The corpus is shared and must not change. The matching path was audited for writes first - every
storage method it reaches only reads, and the matching cache lives in the matcher's memory rather
than being persisted - but the audit also predicted one thing the code does write:
`_ensureIndexAndUnknownFamily` runs on every storage construction and sends `$max` and
`$setOnInsert` upserts at `counters` and `families`. On a populated database those match existing
documents and modify nothing, but mongod counts the command, so the first honest run came back
**VIOLATED** with 8 updates against `real.counters` and 4 against `real.families`.

Excusing that as idempotent would have been an argument, not a proof, so the three small
collections involved are now hashed whole at each end of the run. Both published runs end with
counts, `dbstats` and every other namespace's write counters identical, and the digests of
`counters`, `families` and `settings` unchanged - 282 no-op write commands that moved no byte.
The check is in the JSON, and the harness exits non-zero if it ever fails.

## 8. Partitioning the PicHash count rebuild, and a diagnosis that was half wrong

The query path had been bounded; offline maintenance had not. The PicHash count rebuild was the
one operation with a measured superlinear exponent - k ~ +2.2, 211.9 s at 5,243 samples against
437.1 s at 7,244 - so it is where the same treatment was owed. What follows is worth recording
mostly for how the diagnosis went, because the obvious answer was wrong, the interesting answer
was only 11% of the cost, and the measurement at the end disagreed with the measurement that
started the work.

### Reading the code before touching it

The rebuild was one `$group` over every pichash followed by one upsert per distinct hash. Three
candidate causes, in the order they occurred to me:

1. **"It scans the whole functions collection."** This is the intuitive answer and it is false.
   `explain` on the 7,244-sample corpus shows the pipeline's cursor stage as `PROJECTION_COVERED`
   over `IXSCAN _pichash_1`: mongod pushes the projection into the index and never fetches a
   document. It reads a 184 MB index, not 6.0 GB of records. Had I optimised from taste I would
   have "fixed" the scan and measured nothing.
2. **The `$group` accumulator.** Blocking, and one entry per *distinct* hash - 2,337,173 of them
   over 8,657,357 functions. `internalDocumentSourceGroupMaxMemoryBytes` is 104,857,600 here, so
   it spills. Vocabulary follows the corpus, so this only gets worse.
3. **The upserts.** They arrive in the group's output order, which is not key order, so each one
   matches and inserts at a random position in an index that is itself growing.

The fix came from what (1) left lying around rather than from (2) or (3) directly: a covered
index scan arrives **sorted**, and the old code discarded that. Sorted means equal hashes are
adjacent, which means counting them is a run length in two local variables rather than a hash
table the size of the vocabulary - and it means the output is ascending, so the writes can be
plain inserts that fill the new index at its right edge instead of dirtying it at random.

Partitioning then falls out: the scan is cut into bounded `find`s of `STORAGE_REBUILD_PARTITION_SIZE`
index keys, each resumed by a keyset bound on the last key seen, so nothing accumulates and no
cursor has to live for the length of a multi-hour rebuild.

### Two edges that only exist because of partitioning

A partition boundary can land inside a run. Emitting the trailing run would undercount it, so it
is not emitted: the next partition restarts *inclusively* at its key and counts it from the
beginning. That re-reads at most one run per partition, which is what keeps the scan linear -
the unit test asserts `keys read <= keys + partitions * longest run`, so an implementation that
was correct but quadratic would fail rather than merely be slow.

Inclusive restart has its own failure: a hash held by more functions than a partition holds keys
would make every partition identical and the loop would never advance. That case is counted with
an indexed `count_documents` over the hash's own contiguous index range instead. It needs a hash
with more than 500,000 holders to occur, so it is covered by the fake-collection tests and not by
anything running against a real corpus.

The subtler hazard is not in the arithmetic. Keyset paging uses `$gte`/`$gt`, and **MongoDB
brackets comparisons by BSON type**: pointed at a corpus holding a pichash that is not a string,
the scan would stop at the end of the string bracket and silently produce a short index, and a
missing count document is *excluded* by the cutoff's filter - so exact matches would quietly stop
being found. `_encodePichash` only ever writes `hex()`, and all 8,657,357 non-null values in the
real corpus are strings, but "only ever" is a property of today's code. So the rebuild checks
itself: the holders it counted must equal an independent count of the functions carrying a
pichash, and if they disagree it discards its work and runs the grouped implementation. A
violated precondition costs time, not correctness.

### What the measurement said, including the part that disagrees

`benchmarks/bench_index_rebuild.py`, four corpus sizes projected out of the real corpus, three
repeats, both implementations back to back, indexes compared entry by entry:

| samples | distinct hashes | grouped | partitioned | speedup | spills | spilled |
|---|---|---|---|---|---|---|
| 1,000 | 393,858 | 51.9 s | 10.8 s | 4.81x | 0 | - |
| 2,000 | 722,815 | 91.2 s | 20.8 s | 4.38x | 2 | 11.5 MB |
| 4,000 | 1,486,935 | 188.8 s | 43.6 s | 4.33x | 3 | 23.4 MB |
| 7,244 | 2,337,173 | 301.6 s | 73.1 s | 4.12x | 4 | 36.7 MB |

Three things came out of splitting the total into its read and write halves, which is the one
analysis that made the result legible:

- **The spill is real and it is minor.** It starts between 1,000 and 2,000 samples and grows
  monotonically, exactly as the diagnosis predicted. It also sits inside a 32.6 s read phase
  inside a 301.6 s rebuild. Candidate (2) was correct and accounted for about 11% of the cost.
- **The upsert loop was the expensive half**: 269.0 s of 301.6 s at the largest size. Upserts run
  at 8,106-8,762/s across the whole range; ascending inserts at 38,765-42,878/s. Candidate (3)
  was the answer, and it is the one I ranked last.
- **Neither rate degrades with size.** Fitted against distinct hashes - the quantity both
  implementations produce one document for - grouped is +0.99 and partitioned +1.08. Both linear.

So **the k ~ +2.2 did not reproduce**, and the result of this work is a 4.1x constant factor and
a bounded memory shape, not a repaired exponent. Writing it up the other way round would have
been easy and wrong.

### Why the instrument is the likeliest explanation, and the half of it I could check

The scratch corpora are projections holding only `_pichash` - 209 MB at the largest size against
2,317 MB for the real functions collection, with an 87 MB index against 184 MB (`$out` builds an
index in one sorted pass, so it is denser than one grown by incremental insertion). They fit
inside a 3 GB WiredTiger cache; the real corpus does not. A cost that appears only when the
working set stops being resident cannot show up here.

Half of that is checkable without a second full corpus. Both read phases were run against `real`
itself, read-only - a raw client rather than a `MongoDbStorage`, because `_getDb` ensures indexes
on first use and a corpus that must not be modified must not be handed to code that writes on
construction - with every collection's document count recorded before and after and asserted
equal. Result: 33.76 s grouped and 13.69 s partitioned against 32.62 s and 12.83 s on the
projection, both reporting exactly 2,337,173 hashes. The projection is faithful for the read
phase, which is what the covered-scan argument predicts. Whatever it hides is in the write phase,
where the real database's other 4.9 GB compete for the same cache - and confirming that needs two
full-fidelity corpora, about 5 GB of disk the machine did not have.

### The general lesson, which is not the one I expected

The log already has "a benchmark can only find costs that are already visible at the size you can
afford to run" (5e). This is the mirror image: **a benchmark can also fail to reproduce a cost
that was real, when the corpus you can afford to run has a different shape from the one that
produced it.** The earlier number was not wrong; it was taken on a database that no longer fits
twice on this disk. The defensible move is to publish both, say which one the fix is entitled to
claim, and name the experiment that would settle it - rather than quietly keeping the exponent
that makes the change look better.

## 9. Deduplicating the matching-cache fetch, and a measurement that nearly lied

Scoring had been deduplicated by signature; the fetch feeding it had not. The open question was
whether the fetch could also read *fewer documents*, not merely decode fewer signatures.

**It cannot, without a schema change.** Each document the fetch reads carries `sample_id` as well
as the signature, and `sample_id` is per-function attribution - it is what a match is reported
with, and `sample_id_to_func_ids` is what the PicHash filter subtracts from. Asking storage for
"the distinct signatures of these function ids" needs a signature-keyed index that does not
exist. So what was left to deduplicate is the hex decode and the retained bytes: one
`bytes.fromhex` per candidate function became one per distinct signature, and every function
carrying a signature now shares one object.

### The dedup factor on a candidate set is not the corpus dedup factor

The corpus-wide figure at 257 samples was 2.46x. On the 7,244-sample real corpus, the *candidate
sets* of the three standing query samples deduplicate **3.99x to 29.59x**. That is not a
surprise once stated: a candidate set is assembled by band collision, and band collision is the
thing that correlates with holding the same signature. It does mean the corpus figure understates
what the fetch stood to gain, and that the right number to quote for a fetch is the one measured
on a candidate set. The fetch now logs its own.

### Measuring the wrong two things

The first version of `bench_cache_fetch.py` compared the production fetch against a hand-written
per-function loop, and reported the deduplicated path **2x faster** at 126k ids. That number was
wrong and flattering: the production path slices the id set and fetches the slices from a thread
pool, and the hand-written baseline did neither. It measured threading, not deduplication.
Rewriting the baseline as *the production fetch with only the slice decode swapped* dropped the
same comparison to 1.19x. The lesson is the ordinary one and it keeps recurring here: a baseline
that is not the code being replaced measures the difference between two implementations, not the
change.

A second version of the same mistake was avoided rather than made: `tracemalloc` taxes every
allocation, so timing under it would have flattered the strategy that allocates least - which is
precisely the strategy under test. Time and memory are measured in separate passes.

### The honest end-to-end result: nothing measurable

Isolated, the deduplicated fetch is 7%-50% faster and allocates 0%-24% less, never slower, with
the gain scaling with the candidate set. End to end, over the same three queries, three repeats,
both configurations, **the matching-cache fetch stage and the total do not move**: 10.193 s ->
10.487 s (knobs at 0) and 0.269 s -> 0.270 s (two-stage), summed over the three queries, against
a run-to-run spread several times larger than the effect. The stage also contains per-function
cache-object construction that this change does not touch and that dominates it.

That is worth recording as a result, not hiding as a disappointment. The change removes work that
is proportional to the candidate set, and the candidate set is what grows with the corpus; the
cost it adds is a dict lookup per distinct signature, which grows far more slowly. It is a
reduction in corpus-shaped work whose absolute size at 7,244 samples is below the noise floor of
the instrument - which is the same category as the shortlist-ranking defect in 5e, found by
asking what is shaped like the corpus rather than by reading a profile.

### `$group` in mongod: measured, rejected

Grouping by signature server-side would take the repeated signature off the wire too. Measured as
the `aggregated` strategy: **slower** (2.807 s against 1.538 s at 126k ids; 6.269 s against
3.793 s at 397k), though it does allocate less on the widest set (124.8 MB against 136.8 MB), so
the wire saving is real and simply smaller than what the aggregation costs. The comparison is
also not clean - the aggregation runs as one unsliced cursor against a sliced, threaded find - so
what is rejected is this implementation of the idea, not the idea. The find path stays.

## 10. An outside review, checked against the code, and the ceiling it moved

On 2026-09-24 a ten-item review of mcrit, mcritweb and docker-mcrit came in from another model
run. Every claim was checked against the current upstream heads (familiary/mcrit `ab56c34`,
familiary/mcritweb `e4bfa55`, familiary/docker-mcrit `aac38ad`), the scaling stack, and the live
7,244-sample corpus, read-only. The review was mostly right about what the code says and mostly
wrong about what to do first.

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 1 | band posting lists grow without limit | true, already fixed on the stack | `STORAGE_BAND_BUCKET_SIZE` (fork #45, upstream #196) and the df cutoff (fork #44, upstream #195); both default off |
| 2 | posting lists read as int32 | true, fixed here (section 11) | `np.array(hit["function_ids"], dtype=np.int32)` on upstream main and every stack branch |
| 3 | minhash stored as hex text | true, not worth a migration | 93.8 of 906.7 bytes of an average function document (10.3%); binary would save about 5% |
| 4 | McritClient has no timeouts or session | true | 55 bare `requests.*` calls on upstream main, no `Session(`, no `timeout=`, no branch adds either; gunicorn's `-t 300` does not reach a stuck thread under `gthread` |
| 5 | mcritweb fetches samples one by one | true, half done | server side is upstream #213 (issue #207); mcritweb side is mcritweb #221, both open |
| 6 | fixed sleeps after edits | true, low value | three sleeps of 0.3-1 s, only on the family and sample edit forms |
| 7 | SQLite has no WAL or busy timeout | half true | no WAL; Python's `sqlite3.connect` already waits 5 s by default |
| 8 | secret-key creation races | true but narrow | `O_CREAT \| O_TRUNC` without `O_EXCL`; only bites on a first boot with no key configured, gunicorn runs without `--preload` |
| 9 | jQuery UI 1.13.1 carries CVE-2022-31160 | true, not exploitable here | the CVE is in the checkboxradio widget, which mcritweb never initialises; bump anyway |
| 10 | docker-mcrit lacks healthchecks and worker scaling | true | no healthcheck on `mcritweb` or `nginx`; `mcrit-worker` has a fixed `container_name`, so `--scale` fails |

What the review missed is the thing the rest of this log is about: the one-stage match cost grows
as corpus^1.40 on real data and two-stage stays flat, and upstream still runs one-stage. Merging
the stack is worth more than anything on the list.

### The 16 MB wall was measured on one band out of twenty

Checking claim 1 meant reading posting-list sizes off the live corpus, and they did not agree with
the ceiling quoted in SUMMARY.md, TUNING.md, the changelog and three code comments.
That figure took the longest list in `band_0` - 18,968 ids - and extrapolated. Across all twenty
bands the longest list holds **36,183 ids** (386,971 bytes, `band_14`), nearly twice as many
(`benchmarks/measure_id_and_list_headroom.py`, `measurements/headroom_7k.json`). The per-band
maxima range from 18,968 to 36,183; `band_0` happens to sit at the bottom.

The capacity side was off too. 10.42 bytes per id came from that short list, but every BSON array
element carries its own index as a string key, and the keys lengthen as the list grows. Measured
directly instead, by pushing ids into one document on a throwaway mongod until the write is
refused (`benchmarks/measure_posting_capacity.py`, `measurements/posting_capacity.json`):

| ids stored as | held before refusal | bytes per id |
|---|---|---|
| int32 (ids below `2**31`) | 1,350,000 | 12.18 |
| int64 (ids past `2**31`) | 1,050,000 | 15.94 |

The earlier "ten pushes of 100,000 succeeded, the eleventh was refused" check reproduces the int64
row exactly (refused at 17,588,946 bytes against 17,588,958 then), so it had used ids past
`2**31` without noticing. Put together, 1.35 million over 36,183 is 37x the corpus: **the wall is
near 270,000 samples, not 615,000.** Corrected on pr3 (`57079ee`) and pr4 (`d7283e5`) and on this
branch. `STORAGE_BAND_BUCKET_SIZE = 100,000` is unaffected - it sits under either capacity.

The lesson is the one from section 5c in a new place: a maximum was read from the first partition
instead of all of them, and a per-element cost was measured on a small instance of a structure
whose per-element cost grows with size. Both errors pointed the same way, which is why neither
was caught by the other.

### Function-id headroom is set by the counter, not by the count

The live corpus has 8,657,357 functions but its highest function id is **12,003,563**. Ids come
from a counter that is never reused, and earlier bulk deletions burned 3.3 million of them. At the
observed burn of about 1,660 ids per sample kept, `2**31 - 1` is reached at around **1.3 million
samples**; at the stored density of 1,195 functions per sample it would be 1.8 million. Either is
well short of a billion, which is what made claim 2 worth fixing now.

## 11. 64-bit posting arrays in the candidate accumulator

`_getCandidatesForMinHashesNumpy` - the default accumulation since `STORAGE_CANDIDATE_ACCUMULATION
= "numpy"` - turned every posting list into an int32 array. Past `2**31 - 1` the failure depends on
the numpy that `pyproject.toml` allows (`numpy>=1.26`), and both versions were run to see it:

- numpy 2.4.6: `OverflowError: Python integer 2147483648 out of bounds for int32`. Matching fails.
- numpy 1.26.4: a `DeprecationWarning` that Python hides by default, and then
  `[3, 2**31, 2**32 + 3]` becomes `[3, -2147483648, 3]`. The first wrapped id lands in the negative
  range query functions use; the second becomes function 3, so a candidate is attributed to the
  wrong function and can be counted twice against `BAND_MATCHES_REQUIRED`. Silent and wrong.

The fix is one dtype, on pr2 (`9c8e930`) because pr2 is the lowest stack branch still open and the
accumulator is the stage it restructures. Tests first (`tests/testCandidateAccumulation.py`): a
subclass of `MongoDbStorage` answers the band lookups from canned posting lists, so the test runs
in the unit suite and exercises only the accumulation. Both tests failed on the int32 code with
the OverflowError above and pass on int64. A first version patched `_getDb` on the instance and
failed `ty` with two `invalid-assignment` errors; CI enforces zero, so the subclass replaced it.

Always-int64 was chosen over choosing the width per corpus. The cost was measured on the live
corpus, read-only - the storage object is handed a plain `MongoClient` database so `_initDb`, which
ensures indexes, never runs - with the three standing queries, median of three, time and memory in
separate passes (`benchmarks/bench_accumulator_dtype.py`, `measurements/dtype_int32.json`,
`measurements/dtype_int64.json`):

| configuration | query | candidate pairs | time, int32 (3 runs) | time, int64 (3 runs) | peak, int32 | peak, int64 |
|---|---|---|---|---|---|---|
| one-stage | win.zloader | 183,621 | 0.46-0.54 s | 0.47-0.55 s | 19.0 MB | 26.4 MB |
| one-stage | win.blackpos | 865,854 | 1.02-1.06 s | 1.12-1.15 s | 38.7 MB | 60.5 MB |
| one-stage | win.acidbox | 129,307 | 0.21-0.24 s | 0.20-0.21 s | 7.3 MB | 11.5 MB |
| df cutoff 200 | win.zloader | 5,518 | 0.18-0.21 s | 0.20-0.25 s | 5.2 MB | 5.8 MB |
| df cutoff 200 | win.blackpos | 23,795 | 0.16-0.21 s | 0.17-0.18 s | 4.7 MB | 5.5 MB |
| df cutoff 200 | win.acidbox | 3,767 | 0.08-0.10 s | 0.08-0.10 s | 1.6 MB | 1.8 MB |

Only the widest query pays in time consistently: about 8%, some 90 ms, the one row where the
three runs of each variant do not overlap. Every other row's ranges overlap. The pushed commit
message says "time within noise"; that came from a first pass that timed under `tracemalloc`
while the test suite ran on the same four CPUs - the confound section 9 warns about - and it read
2.8 s and 6.8 s for the first two rows. The rerun above, on a quiet machine with time and memory
in separate passes (`dtype_int32*.json`, `dtype_int64*.json`, three files each), is the one to
trust, and it agrees except for that one query.

Candidates are identical, and every query finds all of its own functions in one-stage. The worst
memory cost is 22 MB on the widest one-stage query, against a measured whole-process peak of
766 MB for that configuration at this size; two-stage pays under 1 MB. An adaptive width would
save that and add a code path that is only exercised past two billion ids - the one place a
narrowing bug would stay hidden longest.

### Repository state on 2026-09-24, before this push

Upstream merged #194 (pr1) today as `ab56c34`, along with #163, #168 and #169. #195-#200 (pr2-pr7)
are open against `main`, with heads `e9f3c03`, `a1afe24`, `e50087c`, `a071e50`, `6356282` and
`1f4c3e1`, identical to fork PRs #44-#49. Nothing in familiary/mcrit, familiary/mcritweb or either
fork covers 32-bit function ids, client timeouts, SQLite WAL, the jQuery UI CVE or docker-mcrit
healthchecks. Batch sample lookup is covered by mcrit #213 and mcritweb #221, and the adaptive
cutoff and the LogBucket cache key by the two issues already filed (#201, #202 and #215).

### Operational notes from this round

- **The box reboots, and docker does not come back by itself.** Three reboots in one day. After
  each, `dockerd` refused to start because `/var/run/docker.pid` survived and named a PID that no
  longer existed ("process with PID 393 is still running" - it was not). Check that the PID is
  gone, delete the file, start `dockerd`, then `docker start mcrit-mongo3`. The corpus fingerprint
  compared unchanged after every one (`db_fingerprint.py compare`, 35 collections, 28,716,568
  objects).
- **The container `nofile` ceiling is now 20,000.** `--ulimit nofile=200000:200000`, which AGENTS.md
  suggests, is refused by the runtime here (`error setting rlimit type 7: operation not
  permitted`); 20,000 matches the host hard limit and is what `mcrit-mongo3` already runs with.
- **`pkill -f` matches the shell that runs it.** Stopping a background harness with
  `pkill -f cascade.sh` killed the invoking shell too, because the pattern is in its own command
  line. Kill by PID taken from a pattern that cannot match itself (`grep "[c]ascade"`).
- **Test runs go to a throwaway server.** Every test run in this round used a tmpfs mongod on
  27018 (`TEST_MONGODB=127.0.0.1:27018`), and the capacity measurement, which writes, a second one
  on 27019. The live server's database list was recorded before and compared after.
