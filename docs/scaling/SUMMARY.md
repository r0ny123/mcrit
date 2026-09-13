# Scaling MCRIT 1-vs-N matching: results

## The problem, stated as a measurement

Every stage of a 1-vs-N query grows with corpus size, and so does the answer. Measured on the
same query samples against the same corpus at three sizes:

| corpus | median 1-vs-N | candidate pairs (sample 148) | matched samples (sample 148) |
|---|---|---|---|
| 257 | 0.268 s | 20,744 | 35 |
| 993 | 0.520 s | 33,328 | 568 |
| 10,000 | 3.128 s | 361,325 | 5,930 |

From 993 to 10,000 samples: candidate pairs grew **10.8x**, matched samples **10.4x** for a
10x corpus. The growth is not an inefficiency to tune away - it is the result set getting
bigger. 5,930 matched samples is not an answer anybody reads.

## Baseline vs final

Fixed query set (samples 148, 157, 8), same query samples at both corpus sizes, warm cache,
repeated runs (2 for one-stage, 3 for two-stage) and averaged. Two-stage is
`MINHASH_MATCHING_SHORTLIST_SIZE=100`, `STORAGE_BAND_DF_CUTOFF=200`.

| | 257 samples | 12,500 samples | growth | fitted exponent k in latency ~ corpus^k |
|---|---|---|---|---|
| **one-stage median** | 0.429 s | 4.427 s | 10.32x | **+0.601** |
| **one-stage mean** | 0.521 s | 3.392 s | 6.50x | +0.482 |
| **one-stage max** | 0.954 s | 5.188 s | 5.44x | +0.436 |
| **two-stage median** | 0.645 s | 0.374 s | **0.58x** | **-0.140** |
| **two-stage mean** | 0.868 s | 0.835 s | **0.96x** | -0.010 |
| **two-stage max** | 1.695 s | 1.810 s | **1.07x** | +0.017 |

The corpus grew **48.6x**. One-stage latency grew with it. **Two-stage latency did not grow at
all** - mean moved -4%, max +7%, both inside run-to-run variation. The remaining cost is set by
the *query* (how many functions it has) and by the shortlist size, not by how much corpus there
is, which is exactly the property the goal asked for.

The median even falls slightly, and that is a measurement artefact worth naming rather than
claiming: the 257-sample corpus is real samples carrying `xcfg` disassembly, so loading the
query sample's own functions costs more there than in the leaner synthetic corpus. It is a
constant per-query cost on the query side, unrelated to corpus size; the honest reading of the
median row is "no growth", not "gets faster".

**Extrapolated to 1,000,000 samples** (80x beyond the measured 12,500), applying the fitted
exponents:

| | one-stage | two-stage |
|---|---|---|
| median | ~62 s | **~0.4 s** |
| mean | ~28 s | **~0.8 s** |
| max | ~35 s | **~2.0 s** |

For two-stage these are near-flat projections of a near-zero exponent, so they mostly restate
the measured 12,500-sample numbers - which is the claim: at a million samples the query should
still cost what it costs today.

### What the cutoff is worth

At 12,500 samples, holding the shortlist at 100 and varying only `STORAGE_BAND_DF_CUTOFF`:

| cutoff | median | top-10 recall | top-25 recall | identical scores |
|---|---|---|---|---|
| 0 (off) | 0.814 s* | 1.000 | 1.000 | - |
| 1000 | 1.172 s | 1.000 | 1.000 | 0.9945 |
| 200 | **0.374 s** | **1.000** | **1.000** | 0.9936 |
| 100 | 0.332 s | 1.000 | 1.000 | 0.9955 |

\* measured at 10,000 samples before the corpus was grown further.

200 is the recommended starting point: it is where the traversal stops scaling while top-K
recall is still perfect. Tightening to 100 buys little more.

## Matching quality

Measured against the *unrestricted* result on the same corpus (`benchmarks/compare_quality.py`):

| corpus | top-10 sample recall | top-25 sample recall | function matches with identical score |
|---|---|---|---|
| 257 | 1.000 | 1.000 | 1.000 |
| 10,000 | 1.000 | 1.000 | 0.9945 |
| 12,500 (cutoff 1000) | 1.000 | 1.000 | 0.9945 |
| 12,500 (cutoff 200) | 1.000 | 1.000 | 0.9936 |

The samples a user actually reads are all retained, and a retained function match keeps a
bit-identical score: restricting *which* samples are matched does not change *how* they are
matched. Overall sample recall is 0.67, which is the shortlist doing its job - sample 148's
5,930 matched samples become 99.

PicHash matching is deliberately left unbounded, so exact matches are still reported whether or
not their sample made the shortlist. **That is also the one stage still linear in corpus size,
and it is a known limit rather than an oversight**: a position-independent hash held by a large
share of the corpus returns one tuple per holder, so on a real million-sample corpus a query
containing a common library function would pull a very large exact-match set. It did not bind in
these measurements (0.02-0.07 s per query throughout, because synthetic pichashes derive from
signatures and so are more diverse than real library code), which means this design is *not*
validated for pichash behaviour at a million real samples. The same two remedies apply as for
bands - a document-frequency cutoff and a top-K bound - and neither is implemented.

## End-to-end validation on a real instance

The numbers above come from the benchmark harness driving the matcher in-process. The same
configuration was also run through an actual MCRIT deployment - `mcrit server` (waitress) plus
a `mcrit worker`, against the 12,500-sample corpus, with `MINHASH_MATCHING_SHORTLIST_SIZE=100`
and `STORAGE_BAND_DF_CUTOFF=200` - by POSTing a real 1-vs-N job and reading the stored result
back over the REST API:

```
GET /matches/sample/148          -> job 6aa6009529e14ab92c3a50fa
GET /results/<result_id>         -> 286,543 bytes, 100 matched samples, 754 query functions
```

- **2.18 s** job duration end to end, queue to stored result.
- The worker logged `Vectorized matching over 5753 pairs in 618 candidate groups` - the
  shortlist took the same query from **361,325 candidate pairs to 5,753**, a 63x reduction in
  scoring work.
- The result is correct, not merely fast: the query sample is `win.zloader`, and the four
  highest-scoring matches are all `win.zloader` (51.6%, 21.9%, 21.5%, 21.0%), with the first
  synthetic filler sample only appearing at 8.1%.

## The architecture, and why

Keep LSH banding - it is already the correct index for MinHash/Jaccard, and every dense-vector
ANN system (FAISS, ScaNN, HNSW, DiskANN, Milvus, Qdrant, Vespa) indexes a *different*
similarity, so adopting one would change what "similar" means rather than make MCRIT faster at
what it does. Add the two properties the scale literature says are load-bearing (CEBin,
ISSTA 2024; and classical IR):

1. **Bound the traversal.** A band hash held by much of the corpus is a stopword: expensive to
   read, uninformative about which samples match. `STORAGE_BAND_DF_CUTOFF` skips it.
2. **Bound the answer.** `MINHASH_MATCHING_SHORTLIST_SIZE` ranks candidate samples cheaply,
   keeps the best N, and the existing exact matching runs against only those.

Full reasoning and the rejected options are in `INDEXING-OPTIONS.md`; the flow diagrams and
per-piece justification are in `ARCHITECTURE.md`; the measurement history, including six places
where a measurement corrected a plausible assumption, is in `RESEARCH-LOG.md`.

Also landed, and **lossless** (exact, not approximate): scoring one representative per distinct
MinHash signature. Identical signatures score identically against any query, so comparing both
is the same comparison twice. Worth 2.46x at 257 samples and a projected ~24x at a million,
from the fitted Heaps' law V(n) = 1412.8 * n^0.7247.

## Rollout

Both knobs default to **0 (off)**: an upgraded instance is bit-identical until it opts in. Two
indexes need one build on an existing database, each gated on a completeness flag so the old
behaviour holds until they exist:

```python
storage.rebuildFunctionRangeIndex()   # required for shortlisting
storage.rebuildBandDfIndex()          # makes the df cutoff skip from the index
```

Measured build cost at 12,500 samples / ~10M functions: 145 s and 147 s.

## Confidence, and what the numbers do not say

- **Measured** up to 12,500 samples / ~10.2M functions. The 1M figures are **extrapolations**
  from the fitted exponents over a 48.6x measured range. For two-stage the fitted exponent is
  within noise of zero, so the extrapolation is close to a restatement of the measurement; for
  one-stage it is a genuine extrapolation of a clear trend.
- The corpus is **257 real Malpedia samples** plus synthetic growth drawn from a process fitted
  to that corpus (functions-per-sample from the real empirical distribution; signatures from a
  preferential-attachment urn calibrated to the *measured* Heaps exponent, validated to within
  1.6%). Synthetic samples reproduce the skew that drives cost; they are not real malware, and a
  real million-sample corpus could differ in ways this cannot capture. ~1.9k further real
  samples were being fetched from the Malpedia API as this was written.
- Single machine, single mongod. Numbers are warm-cache and single-query; concurrency was not
  measured.
- Two-stage shows no measurable growth at cutoff 200, but "no growth measured over 48.6x" is
  not "provably constant". Stage 1 still performs index lookups whose cost is logarithmic in
  corpus size, and a flat cutoff remains a blunt instrument - see next steps.

## What remains

1. **WAND / MaxScore instead of a flat cutoff.** A df cutoff discards a long posting list
   entirely; WAND would skip it only while it cannot change the top-K, which is strictly better
   for recall at the same cost. Needs a maintained score bound per posting list.
2. **Sharding.** A petabyte corpus is a partitioning problem. Band hashes partition cleanly, and
   the two-stage shape is already compatible: stage 1 fans out per shard, each returns a local
   top-N, and the merged shortlist feeds stage 2. Not implemented.
3. **Push dedup further down.** Scoring is deduplicated; the matching-cache *fetch* still pulls
   one signature per candidate function rather than per distinct signature.
4. **Adaptive shortlist size.** A fixed N is wrong in both directions - the right N depends on
   how sharply the vote distribution falls off. Stopping where the votes flatten would keep more
   of the tail on ambiguous queries and less on clear ones.
5. **Bound the PicHash stage.** It is the one stage still linear in corpus size, and the one
   whose behaviour the synthetic corpus is least able to predict, because synthetic pichashes
   are more diverse than real library code. It needs the same df cutoff and top-K treatment the
   band path got, measured on a real corpus.
6. **Validate on a real corpus beyond 10k.** The Malpedia fetch was still running; re-running
   `benchmarks/scaling_sweep.py` over a fully real corpus would replace the synthetic points at
   the sizes it can reach.
