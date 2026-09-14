# Raw measurement data

Every number quoted in `../SUMMARY.md`, `../RESEARCH-LOG.md` and the commit messages comes from
one of these files, so a claim can be checked rather than taken on trust. They are the verbatim
JSON written by the harness, kept on this branch so the implementation branch stays clean.

| File | Produced by | What it holds |
|---|---|---|
| `analysis_250.json` | `analyze_corpus.py` | band / pichash posting-list and signature-multiplicity distributions over 257 real Malpedia samples |
| `growth_250.json` | `measure_growth.py` | Heaps' law fit V(n) = 1412.8 * n^0.7247 and the functions-per-sample distribution |
| `baseline_50.json`, `baseline_250.json`, `scale_1k.json` | `bench_matching.py` | per-stage baseline timings at 48 / 257 / 993 samples |
| `scale_10k_onestage.json`, `scale_10k_twostage.json` | `bench_matching.py` | per-stage timings at 10,000 samples, both configurations |
| `small_onestage.json`, `small_twostage.json` | `bench_matching.py` | the 257-sample end of the scaling fit |
| `big_onestage.json`, `big_twostage.json` | `bench_matching.py` | the 12,500-sample end of the scaling fit |
| `quality_250_cut100.json`, `quality_250_cut500.json`, `quality_250_sl25.json` | `compare_quality.py` | recall and score agreement at 257 samples for each knob |
| `quality_10k.json`, `quality_12500.json` | `compare_quality.py` | recall and score agreement at 10,000 and 12,500 samples |
| `rr_one_*.json`, `rr_full_*.json` | `bench_matching.py` | the 2,016-sample real-corpus point, three repeats per configuration |
| `r3k_one_*.json`, `r3k_full_*.json` | `bench_matching.py` | the 2,996-sample real-corpus point, three repeats per configuration |
| `r5k_one_*.json`, `r5k_full_*.json` | `bench_matching.py` | the 5,243-sample real-corpus point, three repeats per configuration |
| `r3k_quality.json`, `r5k_quality.json` | `compare_quality.py` | recall and score agreement on the real corpus at 2,996 and 5,243 samples |
| `pcA_*.json`, `pcB_*.json` | `bench_matching.py` | A/B of the PicHash count index: `$group` counting vs the indexed probe, same corpus |
| `r7k_one_*.json`, `r7k_full_*.json` | `bench_matching.py` | the 7,244-sample real-corpus point, three repeats per configuration |
| `r7k_quality.json` | `compare_quality.py` | recall and score agreement on the real corpus at 7,244 samples |
| `cold_one_*.json`, `cold_full_*.json` | `cold_cache_bench.sh` | one query per file, each after a mongod restart and a page-cache drop, so no query is warmed by the one before it |
| `projection_1m.json` | `project_index_growth.py` | index size and per-query seek count projected from live collection counts |
| `qps_onestage.json` | `bench_concurrency.py` | throughput, latency percentiles, memory and CPU/ticket saturation at concurrency 1-16 for the one-stage baseline |
| `qps_twostage.json` | `bench_concurrency.py` | the same for the two-stage configuration (`MINHASH_MATCHING_SHORTLIST_SIZE=100`, `STORAGE_BAND_DF_CUTOFF=200`, `MINHASH_PICHASH_MAX_MATCHES=200`) |

## Reading the concurrency files

- `levels[]` holds one entry per concurrency level, each with `repeats[]` (one entry per repeat,
  every individual request timed in `repeats[].requests[]`) and the pooled percentiles across
  repeats. `requests_per_second_min` / `_max` / `_stdev` over the repeats are the variance.
- `read_only_check` holds the before and after snapshots of the corpus database and the verdict.
  `read_only_check.result.clean` being `true` is the assertion that the run only read; the
  harness exits non-zero if it is not.
- `foreign_cpu_fraction` per repeat is machine-wide busy CPU that was neither a worker nor
  mongod. It polices the measurement: a level with a large share was measured next to something
  else and is not a measurement of this software.
- `read_tickets_total` is mongod's WiredTiger concurrent-read limit, and
  `read_queued_seconds` how long readers spent waiting for one. That pair is the saturation
  evidence.

## Caveats that apply to the concurrency files

- One machine, 4 cores, ~15.7 GB RAM, one mongod with a 3 GB WiredTiger cache, warm cache, one
  corpus of 7,244 real Malpedia samples. The ceiling reported is the machine's, not the design's.
- Concurrency is realised as independent OS processes, mirroring how `SpawningWorker` executes
  jobs. The REST hop, the queue round trip and the per-job interpreter start-up are outside the
  measured window; `spawn_cost` in `qps_twostage.json` measures that last constant separately.
- The three query samples are the ones every earlier scaling point used, addressed by sha256.
  Three distinct queries cycled round-robin is a narrow workload: it says nothing about a mix of
  query sizes wider than 158-650 functions, and the corpus-side working set it touches is the
  same one every repeat.

## Caveats that apply to the serial measurements

- Single machine, single mongod (3 GB WiredTiger cache), warm cache, one query at a time.
  Throughput under concurrent load is measured separately, in the `qps_*.json` files above.
- `quality_250_sl25.json` was produced *before* the sample-score reader was fixed; its
  `top10_sample_recall` of 0.90 is an artefact of comparing two arbitrary orderings, not a real
  recall loss. It is kept because the mistake is part of the record - see the research log.
- The `rr_`, `r3k_` and `r5k_` files are the exception to the synthetic caveat below: those
  corpora are real Malpedia samples throughout, grown in place, and are the three points the
  headline result is fitted on. `_one_` is the one-stage baseline, `_full_` the two-stage
  configuration; the same three query samples are used at every size, addressed by sha256 so
  the comparison survives sample ids shifting.
- Corpora above 257 samples are real samples plus synthetic growth fitted to them. The synthetic
  process is described in `synth_corpus.py`; it is not replicated samples.
