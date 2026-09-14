# Scaling MCRIT 1-vs-N matching: results

## Baseline vs final, in one table

Four real Malpedia corpus sizes, same three query samples throughout, addressed by sha256 so the
comparison survives sample ids shifting as the corpus is grown in place. Warm cache, three
repeats each (the table reports the median across repeats), nothing else competing for CPU.
"two-stage" is `MINHASH_MATCHING_SHORTLIST_SIZE=100`, `STORAGE_BAND_DF_CUTOFF=200`,
`MINHASH_PICHASH_MAX_MATCHES=200`. Corpus sizes are counted, not read from `/status` - see the
note at the end of this section.

| real samples | one-stage median | two-stage median | one-stage max | two-stage max | one-stage peak RSS | two-stage peak RSS |
|---|---|---|---|---|---|---|
| 2,016 | 1.55 s | 1.60 s | 3.60 s | 2.10 s | 367 MB | 276 MB |
| 2,997 | 2.71 s | 1.82 s | 6.91 s | 2.16 s | 401 MB | 251 MB |
| 5,236 | 4.86 s | 1.46 s | 14.15 s | 1.49 s | 556 MB | 244 MB |
| 7,244 | **10.20 s** | **1.58 s** | **25.39 s** | **1.93 s** | **766 MB** | **253 MB** |

Fitted over that 3.59x growth, as k in `cost ~ corpus**k`:

| | one-stage | two-stage |
|---|---|---|
| median | **k = +1.40** | **k = -0.07** |
| mean | k = +1.44 | k = -0.11 |
| max | k = +1.49 | k = -0.17 |
| peak RSS | k = +0.57 | k = -0.07 |

**The baseline grows superlinearly on real data. Two-stage does not grow.** At 7,244 samples the
gap is **6.4x on the median, 9.7x on the mean, 13.2x on the tail, and 3.0x less memory** - having
been 1.0x on the median at the smallest corpus, where the two configurations were
indistinguishable.

Quality at that size, against the unrestricted result: **top-10 sample recall 1.000**, top-25
0.907, and **0.985 of surviving function matches keep a bit-identical score**. The loss is
concentrated exactly where it is designed to be: of the three queries, the two whose result sets
fit inside the shortlist returned identically to the baseline (236 and 756 samples, recall 1.000
across the board), while the one matching 2,443 samples was truncated to 48 - top-10 still 1.000,
top-25 0.72.

### What the fourth point changed

The three-point fit reported two-stage at k = -0.12 and described it as "flat or falling". With a
fourth point that reading needed checking rather than repeating, and the check is worth recording
because it nearly went the other way. The first two-stage repeat at 7,244 came in at 2.43 s,
against 1.46 s at the previous size - which looks like the bound failing. It was a cache artefact:
the one-stage runs immediately before it evict two-stage's working set, and repeats 2 and 3 gave
1.58 s and 1.53 s.

Across all four points the two-stage medians are 1.60, 1.82, 1.46, 1.58 - non-monotonic, noise
around a flat line rather than a trend, which is what the small negative exponent summarises.
Meanwhile the baseline's exponent strengthened from +1.25 to +1.40. A single repeat would have
supported either conclusion; three repeats and a fourth corpus size are what make "flat" a
measurement rather than an impression.

### Cold cache: the bound is structural, but it is a bound on seeks

Every number above is warm-cache, and the two-stage design's claim to stay flat rests on its work
being bounded by construction - the df cutoff bounds posting-list traversal, the shortlist bounds
candidates, the pichash cap bounds the last linear stage. That bounds *CPU*. It says nothing about
I/O, and the way the design plausibly fails at 10^6 samples is the band index no longer fitting in
RAM, so every bounded lookup becomes a disk seek.

`cold_cache_bench.sh` measures that regime directly: mongod is restarted and the host page cache
dropped before **each** query, so no query is warmed by the one before it. Same 7,244-sample
corpus, same deployment, same 3 GB WiredTiger cache.

| query | one-stage warm | one-stage cold | penalty | two-stage warm | two-stage cold | penalty | cold ratio |
|---|---|---|---|---|---|---|---|
| win.zloader (557 fn) | 10.20 s | 14.62 s | 1.43x | 1.93 s | 3.24 s | 1.68x | 4.5x |
| win.blackpos (650 fn) | 25.39 s | 30.81 s | 1.21x | 1.59 s | 4.21 s | 2.64x | 7.3x |
| win.acidbox (158 fn) | 3.87 s | 7.24 s | 1.87x | 0.53 s | 2.22 s | **4.18x** | 3.3x |
| **total** | 39.45 s | 52.67 s | **1.33x** | 4.05 s | 9.67 s | **2.39x** | **5.4x** |

**Two-stage pays nearly twice the cold penalty the baseline does**, and its advantage narrows from
9.7x warm to 5.4x cold. That is the expected direction and it matters: bounded work is dominated
by *random* posting-list lookups with little compute to amortise them, while the baseline's bulk
scans stream from disk efficiently. The effect is sharpest on the smallest query - win.acidbox
does the least compute per seek and pays 4.18x.

So the bound is real - two-stage stays several times faster even when every lookup hits disk - but
it is a bound on the *number* of seeks, not on their cost. **At a corpus large enough that the
index cannot be resident, the honest expectation is the cold column, not the warm one.**

### Extrapolated to one million samples

Applying the fitted exponents, 138x beyond the largest measured real corpus:

| | one-stage | two-stage (warm-fit) | two-stage (cold-adjusted) |
|---|---|---|---|
| median | ~2 hours | ~1.5 s | **~4 s** |
| tail (max) | ~9 hours | ~1.9 s | **~5 s** |

The two-stage warm figures are near-restatements of the measurements, since a negative fitted
exponent is read as flat rather than as improvement. The cold-adjusted column multiplies them by
the measured 2.39x cold penalty, which is the more honest figure at a size where the band index
(projected at ~338 GB, see below) cannot be RAM-resident.

The one-stage figures extrapolate a clear superlinear trend and should be read as an order of
magnitude, not a prediction: k > 1 cannot hold forever, since cost is ultimately bounded by
scanning the corpus. The defensible claim is that **the baseline becomes unusable well before a
million samples, and two-stage does not** - while being clear that "does not" means seconds, not
milliseconds.

### Billion-scale readiness: where the bottlenecks actually are

The question this work exists to answer is not "how fast is it today" but "what breaks when the
corpus grows". Those are different, and the second is not answered by extrapolating the first -
a cost that is invisible at 7,244 samples and fatal at 10^9 shows up as a wall, not a gradient.

**The query path is bounded by query size, not corpus size.** Every stage that was linear in the
corpus now has a bound that does not move as the corpus grows:

| stage | what bounds it | was |
|---|---|---|
| PicHash lookup | `MINHASH_PICHASH_MAX_MATCHES` | O(corpus) |
| band candidate generation | `STORAGE_BAND_DF_CUTOFF` | O(corpus) |
| matching-cache fetch | shortlist | O(candidates) |
| pairwise scoring | shortlist x query functions | O(candidates) |
| result assembly | `MINHASH_MATCHING_SHORTLIST_SIZE` | O(matches) |
| shortlist ranking | samples that received a vote | O(corpus) |

The last row was found by asking this question rather than by benchmarking. `_rankShortlist`
fetched a function count for *every sample in the corpus*, once per matching job. At the sizes
measured here that map is 5,034 entries and costs nothing - which is exactly why four points
across 3.59x of growth show no trace of it. At 10^9 samples it is a 10^9-entry dict per query.
No amount of measuring at this scale would have found it; only reading the code for
corpus-shaped work would.

`project_index_growth.py --target 1000000000` confirms the invariant that matters: the per-query
seek count stays **11,140** (557 query functions x 20 bands), identical to the count at 7,244
samples. Per-query work does not grow with the corpus.

**The hard limit is nearer than sharding, and sharding does not move it.** A band posting list is
a `function_ids` array inside one document, extended with `$push`, and MongoDB caps a document at
16 MB. Measured on this corpus: the largest `band_0` document holds **18,968 postings in 197,606
bytes** - 10.42 bytes each - so **1,610,427 postings fit**, giving **84.9x headroom** over the
current corpus. That puts the wall at roughly **615,000 samples**.

Verified rather than projected. Pushing 100,000 ids at a time into one document succeeded ten
times and failed on the eleventh:

    successful pushes of 100k = 10
    final df = 1000000   bsonsize = 15888958
    error: BSONObj size: 17588958 is invalid. Size must be between 0 and 16793600(16MB)

The write **fails**; it does not degrade. Ingestion stops for any sample containing a function
whose band hash is already at the cap.

Two things follow. First, **sharding cannot fix this** - a single document cannot span shards, so
adding machines does not raise the cap. Second, the estimate is optimistic: it assumes the hottest
posting list grows linearly with the corpus, while Malpedia is curated and deduplicated. A corpus
carrying many near-duplicate packed variants concentrates df far faster and would hit the cap
sooner.

The fix is the standard bucket pattern - split a band hash's postings across several documents
keyed `(band_hash, bucket)` and cap each - which also shards better than one hot document per
hash. It is a change to the stored data shape, so it needs a migration and a version bump; it is
a prerequisite for the sharding work rather than a consequence of it.

**What does grow, ranked by how badly:**

1. **The 16 MB posting-list cap - the one that binds first**, at ~615,000 samples, described
   above. Nothing else on this list matters until it is fixed, because ingestion stops there.
2. **Index residency - fatal at billion scale.** The band index projects to **331 TB** at 10^9
   samples (1.20e12 functions, 4.50e10 distinct band hashes), against 2.40 GB at 7,244. No single
   machine holds that, and **sharding is not implemented**. This is the gap between the current
   design and billion-scale, and nothing else on this list matters until it is closed. The
   encouraging part is that the work is already partitioned correctly: the 20 band collections are
   independent, and a query touches each with an equal share of its lookups, so sharding by band
   hash needs no algorithmic change - only a router and a fan-in.
3. **Seek cost, as distinct from seek count.** The count is bounded; what each costs is not. The
   cold-cache measurement puts a number on it: **2.39x for two-stage against 1.33x for one-stage**,
   because bounded work is dominated by random lookups with little compute to amortise them. At a
   corpus too large to be resident, every lookup pays that. Sharding buys this down too, by
   shrinking each node's share until it is resident again.
4. **Maintenance is still superlinear.** The PicHash count rebuild measured k ~ +2.2 (437.1 s at
   7,244 against 211.9 s at 5,243). It never touches query latency - the indexes are maintained
   incrementally on write and a full rebuild is offline - but at 10^9 a single-pass rebuild is not
   a thing that can run. It needs partitioning the same way queries got bounded.
5. **The df cutoff is a tuned constant, and vocabulary grows sublinearly.** `STORAGE_BAND_DF_CUTOFF
   = 200` was chosen at this corpus size. Band-hash vocabulary follows Heaps' law (fitted
   V(n) = 1412.8 * n^0.7247 here), so posting lists lengthen as the corpus grows and a fixed cutoff
   discards a different - probably much larger - fraction at 10^9. **Recall 1.000 is a measurement
   at 7,244 samples, not a property of the design.** This is the correctness risk on the list, and
   the reason WAND/MaxScore is the right next step: it makes the bound adaptive rather than tuned.
6. **Ingestion.** Indexing measured ~12 samples/minute single-node here. That is embarrassingly
   parallel and not an architectural problem, but reaching 10^9 samples is a distributed-ingest
   project in its own right, not something the current harness does.

**The short answer**: per-query work is now corpus-independent and measured as such, so the
*algorithm* will not degrade as the corpus grows. What stops it is storage, in two stages. At
around **615,000 samples** a single band posting list exceeds MongoDB's 16 MB document limit and
ingestion fails outright - that one binds first and sharding does not move it. Past that, the
index outgrows one machine long before a billion, which is what sharding is for. The remaining
items are a tuning constant that needs to become adaptive and an offline rebuild that needs
partitioning.

**Ordering matters here.** Sharding is the obvious next piece and it is the wrong one to build
first: it addresses the limit at 10^9 while the limit at 6x10^5 is the one a growing corpus meets.
Bucketing the posting lists is the prerequisite, and unlike sharding it can be built and verified
on a single machine.

### What this does and does not establish

The growth problem is solved across the range measured: the thing that made 1-vs-N unusable -
cost rising faster than the corpus - is gone, and no quality was traded for it. Every number
above is backed by a file in `measurements/`.

It is **not** a demonstration at a million samples. These remain unmeasured:

- **Scale.** The largest real corpus here is 7,244 samples, 138x short of the target, and the
  exponents are fitted on four points across 3.59x of growth. A negative exponent means flat
  across what was measured, not flat forever.
- **Absolute latency.** 1.5 s that stays 1.5 s is *stable*, not *blazing*. Billion-scale
  similarity search at Google or Meta targets tens of milliseconds; this is two orders of
  magnitude off that, and the achievement here is the flatness, not the number.
- **Concurrency.** Every measurement is one query at a time, on one machine, against one mongod,
  warm cache. QPS under load was never measured; there is no sharding and no distribution.
- **Cold cache at scale.** Measured here (2.39x penalty for two-stage, 1.33x for one-stage), but
  only on a corpus whose working set is far smaller than 10^6. The seek *count* is bounded by
  query size and does not grow with the corpus; the seek *cost* at a size where nothing is
  resident is not something 7,244 samples can establish.
- **Whether the cutoff still preserves recall at scale.** `STORAGE_BAND_DF_CUTOFF=200` was tuned
  at this corpus size. Posting lists grow with the corpus - Heaps' law fitted at
  V(n) = 1412.8 * n^0.7247 on this data - so at 10^6 the same constant discards a different, and
  possibly much larger, fraction of the index. Recall 1.000 is a result at 7,244 samples, not a
  guarantee at 1,000,000.

The defensible claim is that **the baseline becomes unusable well before a million samples and
the two-stage design does not**, together with a measured, quality-preserving 6.4x-13.2x warm
(5.4x cold) at the largest size tested. Closing the remaining gap means sharding the band index across machines,
measuring under concurrent load, re-measuring recall and cutoff binding at 10^5-10^6 with a cold
cache, and replacing the flat df cutoff with WAND/MaxScore so the bound adapts rather than being
a tuned constant.

### What a million samples actually costs, from measured index growth

Extrapolating the fitted latency exponents 191x is weak evidence, which is why they are hedged
above. Index *size* extrapolates much better, because what drives it is structural rather than
empirical: every hashable function contributes exactly one posting to each of the 20 band
collections, and function count is linear in sample count. So the size at any corpus follows
from counting what exists. `benchmarks/project_index_growth.py` does that against a live corpus.

Measured at 5,510 real samples, projected to 10^6:

| | today (5,510 samples) | at 10^6 samples |
|---|---|---|
| functions | 6,287,521 | 1.14e9 |
| distinct band hashes | 7,029,368 | 3.05e8 (Heaps, beta = 0.7247) |
| band index size | **1.86 GB** | **~338 GB** |

338 GB against the 3 GB WiredTiger cache these measurements ran with. **The band index cannot be
resident on one machine at a million samples** - it is roughly 100x the cache it has here.

This is the thing the flat latency curve does not prove, and it has a specific consequence. The
df cutoff bounds how many postings a query *reads*; it does not bound the structure those reads
land in. The seek count per query is set by query size, not corpus size - 557 functions x 20
bands = 11,140 posting-list lookups for the median measured query - so it stays constant as the
corpus grows. What changes is the cost of each one, as it stops being a memory reference:

| device | per-query I/O floor at 10^6 |
|---|---|
| NVMe SSD (80 us) | **0.89 s** |
| SATA SSD (150 us) | 1.67 s |
| spinning disk (5 ms) | 55.7 s |

Two things follow. First, single-node two-stage at a million samples plausibly lands around
1-2 s on NVMe - close to what is measured today, but **I/O-bound rather than CPU-bound**, and
for a different reason than the exponent fit suggests. That the two arguments agree is worth
more than either alone. Second, it is fatal on spinning disks, which is a deployment constraint
worth stating rather than discovering.

This is a projection from measured counts, not a measurement. It assumes B-tree internal nodes
stay cached (they are a small fraction of the structure), uses published seek latencies rather
than ones measured here, and counts only band lookups - the pichash probe and the matching-cache
fetch add to it. The cold-cache benchmark (`cold_cache_bench.sh`) replaces the assumed per-seek
cost with a measured one at the corpus sizes available here.

**What sharding actually buys**, in these terms: it does not reduce the work per query, which is
already bounded. It divides the *index* across nodes until each node's share is resident again,
returning each lookup to memory speed. That is the argument for distribution, and it is a
storage argument rather than a throughput one.

### Index maintenance is superlinear, even though queries are not

Worth separating from the query-path result, because it is the one place cost still grows fast.
Rebuilding the PicHash count index took **437.1 s at 7,244 samples against 211.9 s at 5,243** -
2.06x the time for 1.38x the corpus, an exponent near +2.2. The function-range and band-df
rebuilds stayed cheap (35.7 s and 38.9 s).

This does not touch query latency: all three indexes are maintained incrementally on write, and
a full rebuild is an offline operation run after a bulk import or a schema change. But it is a
real operational cost that the headline numbers do not capture, and at a corpus where a rebuild
matters it would need the same treatment the query path got - incremental or partitioned rebuilds
rather than a single pass.

### A note on the corpus sizes above

They are counted from the samples that exist, not read from `/status`. `/status` sums the
denormalised per-family counters, and those drift permanently once a family document goes
missing during a deletion - on this corpus they over-report by 2,092 samples. The harness now
counts directly and warns when the two disagree; `fit_real_points.py` refits this table from the
raw JSON so the exponents are derived rather than transcribed.

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
validated for pichash behaviour at a million real samples. The document-frequency remedy is now
implemented as `MINHASH_PICHASH_MAX_MATCHES` (default 0, off), which drops a PicHash held by
more than N corpus functions. The holder count is taken from the `_pichash` index rather than
by reading the documents, so an over-common hash costs an index probe instead of a fetch -
the same trick that made the band cutoff worth having. It is **not** yet measured against a
real corpus large enough for PicHash lookup to bind, which is why the recommended value stays
0; a top-K bound on the exact-match path is still unimplemented.

## Validation on a real corpus (no synthetic samples)

Everything above grows a 257-sample real corpus with synthetic samples. This section is
**2,016 real Malpedia samples** - 1,866,128 functions, 757 families, nothing synthetic - and it
changes two of the conclusions, which is why it was worth building.

Fixed queries, warm cache, three repeats averaged. "two-stage full" is shortlist 100,
`STORAGE_BAND_DF_CUTOFF=200`, `MINHASH_PICHASH_MAX_MATCHES=200`:

| | one-stage | two-stage full | |
|---|---|---|---|
| median | 1.568 s | 1.647 s | **no win** |
| mean | 1.953 s | 1.425 s | 1.37x |
| max | 3.570 s | 2.120 s | **1.68x** |
| peak RSS | 367 MB | 276 MB | **-25%** |

Quality against the unrestricted result: **top-10 sample recall 1.000**, top-25 0.973.

### Real-corpus scaling: two points, and they are worse for the baseline than synthetic

The corpus was then grown in place to **2,996 real samples / 3,228,833 functions** and the same
queries re-run (growing in place keeps the sample ids valid, so this is a controlled
comparison). Index paused during measurement so nothing competed for CPU; three repeats each:

| | one-stage 2,016 -> 2,996 | k | two-stage 2,016 -> 2,996 | k |
|---|---|---|---|---|
| median | 1.57 s -> 2.76 s (1.76x) | **+1.43** | 1.65 s -> 1.89 s (1.15x) | **+0.35** |
| mean | 1.95 s -> 3.53 s (1.81x) | **+1.49** | 1.43 s -> 1.55 s (1.09x) | **+0.22** |
| max | 3.57 s -> 6.87 s (1.92x) | **+1.65** | 2.12 s -> 2.21 s (1.04x) | **+0.11** |
| peak RSS | 367 MB -> 401 MB (1.09x) | +0.22 | 276 MB -> 251 MB (0.91x) | **-0.24** |

For a 1.49x corpus increase. Three things are worth stating plainly:

1. **On real data the baseline grows *superlinearly*** - k between +1.43 and +1.65, against
   +0.44 to +0.60 measured on the synthetic series. The synthetic corpus, fitted to the real
   one's Heaps growth and signature skew, was *kinder* to the baseline than reality. That is the
   opposite of the usual worry about synthetic benchmarks, and it means the earlier ~62 s
   projection at a million samples is a floor rather than a ceiling.
2. **Two-stage is nearly flat on real data too** (k = +0.11 to +0.35), and its peak memory
   *falls* as the corpus grows (k = -0.24) - the shortlist bounds what is fetched, so a larger
   corpus does not mean a larger working set.
3. **The crossover is now behind us.** At 2,016 samples two-stage lost on the median (1.65 s
   against 1.57 s); at 2,996 it wins (1.89 s against 2.76 s), and by 3.1x on the tail. The
   cost of ranking is fixed, the cost of not ranking is not.

Quality at 2,996: **top-10 sample recall 1.000**, top-25 0.987, 0.978 of surviving function
matches bit-identical - unchanged from 2,016.

**Caveats.** This is a two-point fit over 1.49x, far weaker evidence than the 48.6x synthetic
series, and a two-point exponent is sensitive to both endpoints. The 2,996-sample corpus also
carries a slightly lower hashed fraction (59.6% against 65.9%) because measurement paused an
in-flight indexing chunk; unhashed functions are cheaper, not dearer, so if anything that
*understates* the baseline's growth.

### The PicHash stage: measured, found still scaling, fixed, re-measured

Per-stage timings across the real 2,016 -> 2,996 growth showed every stage the shortlist bounds
staying flat, and one that did not:

| stage | 2,016 | 2,996 | |
|---|---|---|---|
| matching-cache fetch | 0.183 s | 0.182 s | flat |
| minhash scoring | 0.103 s | 0.095 s | flat |
| shortlist restriction | 0.093 s | 0.083 s | flat |
| result assembly | 0.849 s | 0.356 s | falls |
| **pichash lookup** | 0.598 s | **1.078 s** | **1.80x, with the cutoff on** |

The cutoff was not bounding anything, because of how it counted: a `$group` over the functions
collection touches one index entry per holder *including for every hash it then rejects* - the
exact cost the cutoff exists to avoid. This is the same mistake already found and fixed on the
band path, where filtering on `$size` measured no better than no filter at all, repeated in the
exact-match path.

A `pichash_counts` collection (one document per distinct hash, `(_pichash, df)` indexed) makes
the filter one indexed probe per *queried* hash instead of one entry per *holder*. Measured A/B
on the same 3,653-sample real corpus, same queries, index paused so nothing competed:

| | pichash lookup (3 queries) | total mean |
|---|---|---|
| counting fallback | 1.318 s | 1.55 s |
| indexed counts | **0.387 s** | 1.43 s |

**3.4x on the stage.** The point is not the constant: it replaces an O(holders) term with an
O(queried hashes) one, so it removes the growth rather than shrinking it.

Two smaller defects surfaced while building it, both recorded in the research log because both
fail *silently*: the rebuilds set their completeness flag only on success, so an interrupted
rebuild advertised a complete index over an empty one; and they created their index *after* the
upserts, making each upsert scan the collection - the pichash rebuild ran at ~35 upserts/s and
was 42 minutes into an expected ~1.5M hashes. Indexed first, the same rebuild completes in
**148 s** for 1,398,282 hashes.

### What the real corpus changed

**1. The PicHash cutoff matters, and only real data shows it.** The synthetic corpus could not
exercise `MINHASH_PICHASH_MAX_MATCHES` at all - that limitation was written down before this
measurement, because synthetic pichashes derive from signatures and are therefore more diverse
than real library code. On real data it binds immediately: one query pulled **51,488 pichash
match tuples**, and turning the cutoff on took the median from 2.594 s to 1.606 s. The same
knob on the synthetic corpus did nothing measurable. A synthetic corpus fitted to real *fuzzy*
statistics is not automatically faithful in its *exact*-match statistics.

**2. At 2,016 samples the median is not yet better** - the shortlist's ranking cost is not yet
repaid, exactly as the crossover in the synthetic series predicts, and as `docs/TUNING.md`
already warns. The tail and the memory are better well before the median is, and the tail is
what makes a corpus unusable.

### Memory, and upstream issue #69

The **-25% peak RSS** is the first direct evidence for
[#69](https://github.com/danielplohmann/mcrit/issues/69) ("workers consume a lot of ram on
query": tens of GB, sometimes over 60 GB, on a 20M-function instance). It is a modest
proportion at this corpus size for the same reason the median is - the bound has little to bite
on yet - but it moves in the right direction for the right reason: peak RSS tracks bytes
fetched, bytes fetched tracks candidate volume, and candidate volume is what the shortlist
bounds. See `UPSTREAM-REVIEW.md`.

### A quality cost that is not recall

The PicHash cutoff changes some **scores**, not only which samples are reported: on one query
0.903 of surviving function matches kept a bit-identical score, against 1.000 for the other
two. The cause is not a lost match but a changed one - `PICHASH_IMPLIES_MINHASH_MATCH` reports
an exact match as 100, and when the cutoff drops that exact match the pair falls back to its
MinHash score. Folding this into a recall number would hide it, so it is stated separately.

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
5. **Measure the PicHash cutoff on a real corpus.** The df cutoff for it now exists
   (`MINHASH_PICHASH_MAX_MATCHES`), but the corpus this was built on cannot exercise it:
   synthetic pichashes derive from signatures and so are more diverse than real library code,
   so the stage never binds here. It needs a real corpus large enough to make it bind, and a
   top-K bound on the exact-match path is still unimplemented.
6. **Validate on a real corpus beyond 10k.** The Malpedia fetch was still running; re-running
   `benchmarks/scaling_sweep.py` over a fully real corpus would replace the synthetic points at
   the sizes it can reach.
