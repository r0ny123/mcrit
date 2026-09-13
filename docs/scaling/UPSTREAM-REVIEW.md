# What is in flight upstream and in this fork, and how it relates to scaling

Reviewed at the start of this work and re-checked at the end. Upstream is
[danielplohmann/mcrit](https://github.com/danielplohmann/mcrit); the fork is
[r0ny123/mcrit](https://github.com/r0ny123/mcrit), whose open PRs are the same changes
proposed upstream.

## The one open issue that is this problem

**[#69 "Workers consume a lot of ram on query"](https://github.com/danielplohmann/mcrit/issues/69)** — open, unlabelled, unassigned, no linked PR.

> "It seems like there's no limit at all and the workers are greedy with memory usage, if some
> file will require 200GB of ram the worker will try to get it and will probably crash due to
> lack of memory."

Reported against a **20 million function** instance, with workers reaching *tens of GB* and
sometimes **over 60 GB**, one worker starving the others and crashing multi-worker deployments.
Fifteen specific file hashes reproduce it.

This is the same defect as the latency problem, seen from the memory side. A 1-vs-N query's cost
is driven by candidate volume, and the repository's own `docs/TUNING.md` says so from an earlier
measurement campaign: *"peak RSS correlates 0.98 with bytes fetched from MongoDB and only 0.62
with the sample's function count"*. Candidate volume grows with the corpus, so peak memory grows
with the corpus, and a 20M-function instance is where that becomes fatal rather than annoying.

What already exists for it is **mitigation, not a fix**: `MINHASH_MATCHING_MAX_PAIRS` caps how
many candidate pairs are held at once (its own comment calls the default "a guard against
runaway jobs (#69-class: hundreds of millions of pairs)"), and the pair budget plus the
incremental matching cache bound the peak *within* a job. None of them reduce how many
candidates a query produces; they spread the same work over more batches.

**The shortlist attacks the cause.** Bounding the corpus samples the exact stage may look at
bounds the candidates, and therefore the bytes fetched, and therefore the peak. That makes this
work a candidate answer to #69 and not only to the latency question — which is why
`benchmarks/bench_matching.py` now records peak RSS alongside the stage timings.

## Everything else open upstream (17 PRs, 15 issues) is orthogonal

Every open upstream PR is authored by the fork owner, and they pair with the fork's own open
PRs. None of them touch the matching path's scaling behaviour:

| Theme | Upstream PRs | What it is |
|---|---|---|
| Client and API surface | #185, #183, #169, #170 | typed errors instead of `None`, generated API docs, `SearchResult` objects, function-name search |
| Jobs and lifecycle | #168, #161, #160, #176 | job ownership, paging, preferring the newest finished job, cleanup of orphaned query data |
| Storage correctness | #181, #175, #179, #178 | zero-padded pichashes, oversized-document handling, rebuildable SMDA reports, keeping submitted binaries |
| Metadata | #177, #163 | family actors, function renaming |
| Release | #193, #184 | trusted publishing, export/import round-trip test |

Two are adjacent to performance but not to *scaling*: **#162** serves sorted searches from an
index (search listing, not matching) and **#181** pads pichashes so hex order is numeric order
(ordering, not lookup cost).

Of the open issues, **#80 "Refactor use of gridfs"** and **#93 "Support other architectures"**
could interact with a future sharded deployment, and **#94** (rebuildable SMDA reports) matters
if `STORAGE_DROP_DISASSEMBLY` becomes the default for large corpora - which the disk arithmetic
in this work suggests it should. None conflict with the changes made here.

## Conflict check

The two-stage work touches `MongoDbStorage` (candidate generation, two new indexes),
`MatcherInterface` (the shortlist), `MatchingCache` (signature dedup) and the config classes.
The open PRs above touch the client, the job queue, search, and storage *schema* concerns. The
one file with real overlap is `MongoDbStorage`, where #181 changes how pichashes are *stored*
and this work changes how they are *counted* (`MINHASH_PICHASH_MAX_MATCHES` groups on
`_pichash`) - compatible, since the cutoff counts holders of whatever encoding is stored.
