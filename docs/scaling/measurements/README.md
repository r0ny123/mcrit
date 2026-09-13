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

## Caveats that apply to all of them

- Single machine, single mongod (3 GB WiredTiger cache), warm cache, one query at a time.
  Concurrency was never measured.
- `quality_250_sl25.json` was produced *before* the sample-score reader was fixed; its
  `top10_sample_recall` of 0.90 is an artefact of comparing two arbitrary orderings, not a real
  recall loss. It is kept because the mistake is part of the record - see the research log.
- Corpora above 257 samples are real samples plus synthetic growth fitted to them. The synthetic
  process is described in `synth_corpus.py`; it is not replicated samples.
