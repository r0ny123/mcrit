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

Fixed query set (samples 148, 157, 8), same corpus grown in place, warm cache:

| corpus | one-stage (stock) | two-stage (shortlist 100, df cutoff 1000) | speedup |
|---|---|---|---|
| 257 | **0.410 s** | 0.681 s | 0.60x *(slower - nothing to save yet)* |
| 12,500 | **5.645 s** | **1.172 s** | **4.8x** |

Across that 48.6x growth in corpus size:

| | latency growth | fitted exponent (latency ~ corpus^k) |
|---|---|---|
| one-stage | 13.77x | **k = 0.675** |
| two-stage | 1.72x | **k = 0.140** |

Tail behaviour at 12,500 samples matters more than the median, and moves further:

| | median | mean | max |
|---|---|---|---|
| one-stage | 5.645 s | 11.152 s | 27.215 s |
| two-stage | 1.172 s | 1.209 s | 2.093 s |
| | 4.8x | **9.2x** | **13.0x** |

**Extrapolated to 1,000,000 samples** using the fitted exponents (80x beyond the measured
12,500): one-stage **~109 s**, two-stage **~2.2 s**. The extrapolation is a fit over two
decades of real measurement, not a model of the code - see *Confidence* below.

## Matching quality

Measured against the *unrestricted* result on the same corpus (`benchmarks/compare_quality.py`):

| corpus | top-10 sample recall | top-25 sample recall | function matches with identical score |
|---|---|---|---|
| 257 | 1.000 | 1.000 | 1.000 |
| 10,000 | 1.000 | 1.000 | 0.9945 |
| 12,500 | 1.000 | 1.000 | 0.9945 |

The samples a user actually reads are all retained, and a retained function match keeps a
bit-identical score: restricting *which* samples are matched does not change *how* they are
matched. Overall sample recall is 0.67, which is the shortlist doing its job - sample 148's
5,930 matched samples become 99.

PicHash matching is deliberately left unbounded, so exact matches are still reported whether or
not their sample made the shortlist.

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
  from the fitted exponents over a 48.6x measured range.
- The corpus is **257 real Malpedia samples** plus synthetic growth drawn from a process fitted
  to that corpus (functions-per-sample from the real empirical distribution; signatures from a
  preferential-attachment urn calibrated to the *measured* Heaps exponent, validated to within
  1.6%). Synthetic samples reproduce the skew that drives cost; they are not real malware, and a
  real million-sample corpus could differ in ways this cannot capture. ~1.9k further real
  samples were being fetched from the Malpedia API as this was written.
- Single machine, single mongod. Numbers are warm-cache and single-query; concurrency was not
  measured.
- The two-stage exponent is 0.14, not 0. Stage 1 still touches the index, and a flat cutoff is
  a blunt instrument - see next steps.

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
5. **Validate on a real corpus beyond 10k.** The Malpedia fetch was still running; re-running
   `benchmarks/scaling_sweep.py` over a fully real corpus would replace the synthetic points at
   the sizes it can reach.
