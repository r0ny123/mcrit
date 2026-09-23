# Repository audit — mcrit + mcritweb

A running log of an end-to-end triage of every open pull request across
`r0ny123/mcrit` and `r0ny123/mcritweb` (forks of `danielplohmann/mcrit` and
`fkie-cad/mcritweb`), including what was found, what was decided and why, and what
is deliberately left.

Audit date: 2026-09-12, last updated 2026-09-23 (section 10: upstream 1.5.0, the open
PRs brought onto it, and a correction to section 9). Baselines are measured, not
estimated; every number below came from a run in this environment.

## Environment the numbers were taken in

| | |
|---|---|
| Python | 3.11.15 |
| mcrit (as a dependency of mcritweb) | 1.9.0 from PyPI |
| MongoDB | `mongo:7.0` in docker, four instances on 27017-27020 for parallel runs |
| mcrit tooling | ruff 0.16.7, ty 0.0.79, pytest 9.1.1 |
| mcritweb tooling | ruff 0.16.0, pytest 9.1.1 |

Baselines on the default branches before any change:

| | ruff | ty | tests |
|---|---|---|---|
| `mcrit@main` (a112539) | clean | clean (0 diagnostics) | 187 unit / **282 with mongo** |
| `mcritweb@master` (df53db9) | clean | n/a | **239** |

Note on `ty`: it reports 120 diagnostics when run against the system interpreter and
zero against the project venv. Always `ty check --python /path/to/venv`; a bare
`ty check` is measuring the wrong environment, not finding real problems.

## 1. Repository state as found

### mcrit — 17 open PRs, every one of them unmergeable

This was the finding that mattered. `main` had moved **50 commits** ahead of the point
every open PR branched from, and nine of those commits were merges of this fork's own
earlier PRs landing upstream (`#165`-`#182`). Measured at the start:

- all 17 PRs: **50 commits behind** `main`
- **11 of 17: conflicting** with `main`
- CI: green on all 17 — and misleading, because those runs were against the old base

A PR that is fifty commits behind and textually conflicting cannot be merged, and a
green check on its own head says nothing about that. The whole queue was blocked.

### mcritweb — 63 open PRs, in far better shape

- 62 of 63 `mergeable_state: clean`, 0 commits behind `master`
- 0 failing check runs anywhere
- the exception, PR #1, is covered below

### The trap underneath both

`mcrit` 1.9.0 is now on PyPI, and it moved `pytest` into its `dev` extra.
`mcritweb`'s `requirements.txt` asks for plain `mcrit>=1.5.3`, so the extra is never
requested and **pytest no longer arrives transitively**. Verified in a clean venv:

```
$ pip install -r requirements.txt && python -c "import pytest"
ModuleNotFoundError: No module named 'pytest'
```

`master`'s CI workflow still runs `python -m pytest` without installing it, and PR #9 is
the fix that should land first.

**Correction, made on 2026-09-13 after checking rather than assuming.** This audit first
said the next CI run on any of the 62 open PRs would be red for a reason unrelated to its
own change. That was wrong. All **62/62** open PR heads already carry the four-line
workflow fix in their own `.github/workflows/test.yml`, so each installs pytest itself and
is immune. Only `master` lacks it.

The exposure is therefore not "every open PR" but "every branch cut from `master` from now
on", which is exactly how it was found: `feat/schedule-maintenance-jobs`, opened as #67 on
2026-09-13, was cut from `master` and its first CI run failed on all four Python versions
with `No module named pytest`, against a diff that has nothing to do with pytest. Proved
from the job logs rather than inferred - the passing job's install step runs five commands
including `python -m pip install pytest`, the failing one runs three without it, and
neither restored a pip cache.

## 2. Cross-repo dependency graph

The two repositories are backend (`mcrit`: SMDA -> MinHash/PicHash -> matching ->
MongoDB -> REST) and front end (`mcritweb`: Flask, consuming that REST API through
`McritClient`). The coupling is real and it is versioned only by PyPI, so the
front end can break without anyone touching it.

```
mcrit 1.9.0 (already upstream)
  |
  +-- moved pytest to the `dev` extra
  |     `-- BREAKS mcritweb CI on master and on every branch without
  |         mcritweb#9  ......................................  blocks all 62
  |
  +-- added 3 @Remote Worker methods
  |     rebuildPicBlockHashIndex / recomputeFamilyStats / repairMinHashes
  |     |-- BROKE mcritweb#19 (jobnames ratchet)      ... fixed here
  |     |-- BROKE mcritweb#16 (empty-state map)       ... fixed here
  |     `-- not offered by any MCRITweb page          ... open, see section 6
  |
  +-- added 3 REST routes for the above
        `-- mcrit#40 regenerates docs/api_reference.md to cover them

paired work, front end blocked on backend:
  mcrit#42  typed client errors      <->  mcritweb#27  error pages not stack traces
  mcrit#21  rename a function        <->  mcritweb#64  rename from the function page
  mcrit#18  record a job's owner     <->  mcritweb#63  show who requested a job
  mcrit#20  sorted search indexes    <->  mcritweb#54  records the index ask
  mcrit#17  job cache prefers done   <->  mcritweb#53  records why it is mcrit's
  mcrit#26  typed search results     <->  mcritweb#65  consume them through an adapter
  mcrit#41  export/import round trip <->  mcritweb#32  import progress

stacked branches (a merge into the base must be followed down):
  mcrit#18      -> mcrit#19
  mcritweb#66   -> mcritweb#64, #48, #42, #36
  mcritweb#22   -> mcritweb#21
```

The four `mcritweb` PRs whose entire content is a written record of *why* something is
blocked upstream (#51, #53, #54, #55) are worth reading as a group: they are the
front end's half of the pairs above, and each one is now answered by a real backend
change in this queue.

## 3. What was done — mcrit

`main` was merged into all 17 branches (merge commits, no history rewritten, so
nobody's checkout breaks and no review anchor moves). Each conflict was resolved by
first working out *why* main had changed, not by picking a side. Every branch then had
to pass `ruff format --check`, `ruff check`, `ty check` and the **full mongo suite**
before it was pushed; nothing was pushed on a partial run.

| PR | branch | conflicts | full suite (base 282) |
|---|---|---|---|
| #42 | feat/43-client-errors | none | 293 |
| #41 | test/67-export-import-round-trip | none | 287 |
| #40 | docs/54-api-reference | McritClient | 285 |
| #38 | feat/145-padded-pichash | MongoDbStorage | 292 |
| #36 | feat/94-rebuild-smda-report | testStorage | 288 |
| #35 | feat/95-keep-submitted-binaries | 5 files, 9 hunks | 289 |
| #34 | feat/57-family-actors | testMinHashIndex | 287 |
| #33 | fix/68-cleanup-orphans | 4 files | 287 |
| #32 | fix/42-oversized-documents | testStorage | 285 |
| #27 | fix/76-fast-no-result-function-search | MongoDbStorage | 294 |
| #26 | feat/64-typed-search-results | none | 288 |
| #22 | fix/155-match-flags-round-trip | MatchedFunctionEntry | 283 |
| #21 | feat/72-modify-function | none | 287 |
| #20 | fix/59-sorted-search-indexes | MongoDbStorage, testMinHashIndex | 285 |
| #19 | fix/57-select-jobs-before-paging | mongoqueue (stacked on #18) | 294 |
| #18 | fix/37-record-job-owner | none | 290 |
| #17 | fix/47-cached-job-prefers-finished | mongoqueue | 286 |

**Result: 17/17 now 0 commits behind `main` and conflict-free.**

### The resolutions worth reading

**#22 was superseded and is now a test-only PR.** main's `#44` rewrite of
`MatchedFunctionEntry` already fixes issue #155, and fixes it better: the flags are
kept as the integer the wire format carries and the `match_is_*` booleans are derived
on access, so `getMatchTuple` hands back exactly what came in. This branch stored three
booleans and multiplied them back out, which is the construction the issue was about —
main's own docstring cites #155. Took main's implementation verbatim and kept only the
branch's regression test, which walks all eight flag combinations and passes unchanged
against main's code. The PR went from a 60-line duplicate fix to a 14-line test that
stops the bug coming back. That is the honest outcome, not a smaller one.

**#40 needed a regenerated artifact, and its own test said so.** main added three REST
routes; this branch adds a generated `docs/api_reference.md` plus the generator and a
sync test. After the merge `test_the_committed_reference_is_current` failed, correctly.
The three new client methods were also brought into the shape the branch exists to
establish (`-> Optional[str]`, one-line docstring, `self._passthrough`), then
`python -m mcrit.server.api_reference` regenerated the doc — 57 endpoints, with each new
route resolving to its client method.

**#17 and main were solving different halves of the same function.** main's `$or`
narrows which jobs are *eligible* to be reused (never one whose dead worker still holds
the lock, #150); this branch's sort decides *which* eligible job wins (finished first,
newest first, fkie-cad/mcritweb#47). The merge kept both and the docstring now states
both halves.

**#20's conflict hid a deletion.** main had *removed* the `_picblockhashes.offset`
index (no query could use it) in the same hunk where this branch added compound
(sort field, id) indexes. Keeping "both sides" naively would have resurrected the
dead index. The removal is honoured and the additions kept.

**#19 merged wrong without conflicting.** The `from typing` line came through as
`Any, Dict, List`, silently dropping the `Optional` that main's heartbeat annotations
need — two `F821`s that ruff caught and a conflict marker never would have. This is the
argument for running lint on a merge result rather than trusting a clean merge.

### Verification habit adopted mid-way

For a merge where main rewrote the same code, "no conflict markers" is not evidence.
The check used from `#33` onward:

```
git diff origin/main HEAD   ==   git diff <merge-base> origin/<branch>
```

If those two diffs agree line for line, the merge kept exactly the branch's feature and
exactly main's other work. It held for every branch except `#35`, where it differed by
precisely the lines main added to `deleteSample` — the expected signature of a
deliberate graft, and worth the check to be sure it was that and not a revert.

## 4. What was done — mcritweb

Every one of the 62 live branches was checked out and run against **mcrit 1.9.0**,
which is newer than the mcrit any of their CI runs saw. Three real problems came out of
that, all of them invisible to a green check.

### 4.1 Two contract tests were already failing against 1.9.0

mcrit 1.9.0 added three `@Remote` Worker methods — `rebuildPicBlockHashIndex`,
`recomputeFamilyStats`, `repairMinHashes`. Two mcritweb branches carry ratchets that
enumerate mcrit's own surface and demand the front end keep up. Both did their job:

- **#19** `tests/testJobNames.py` — `rebuildPicBlockHashIndex` had no display name, so
  it would have rendered as a raw RPC name. Named it next to `rebuildIndex`.
  (262 pass.)
- **#16** `tests/testEmptyTableMessages.py` — all three were missing from the
  empty-state map, so each tab fell back to the generic "Click here to create your
  first job" that the branch exists to remove. All three are backend-only —
  MCRITweb's server page starts `rebuildIndex` and `recalculateMinHashes` and nothing
  else — so they take `doDbCleanup`'s wording and no link, rather than pointing at a
  page that cannot start them. (298 pass.)

These are exactly the API/front-end mismatch class, and they were caught by tests the
author had already written against the right source of truth. Worth saying plainly:
those two ratchets earned their keep here.

### 4.2 Eight branches carried a half-fixed Makefile

The `make init` correction was ported to 23 branches on 2026-08-30. Eight PR heads
were cut from `master` *after* that and inherited the stale recipe — and seven of them
had the worst possible shape of it: the comment above `init` had been updated to say
pytest no longer arrives with mcrit, while the recipe below it still did not install
it. That is the exact defect the review thread on #26 opened about, sitting unfixed in
eight open PRs.

Ported to **#66, #65, #63, #61** directly, and to the four stacked on #66 (**#64, #48,
#42, #36**) by merging their updated base — which also brought them current, #64 having
been 3 commits behind. All 62 open PR heads now pin `pytest==9.1.1`, `pytest-cov==7.1.0`
and `ruff==0.16.0` in `make init`.

This is papering over the root cause, which is that `master` itself has both the stale
`Makefile` and a CI workflow that never installs pytest. **PR #9 is the real fix and
should merge first.**

### 4.3 PR #1 closed as superseded

`cursor/scan-for-typos-and-logic-errors-befc`, open since 2025-07-31, shares no merge
base with `master` (`refusing to merge unrelated histories`), has never had a check
run, and sits on a `base.sha` 51 commits stale. Its four review threads had been marked
resolved **with no reply**, which left it unclear whether the underlying bugs were ever
dealt with. Checked all four against current `master` — every one is fixed:

| finding | where it is fixed on master |
|---|---|
| `migrate()` never commits, so tokens roll back while the `ALTER TABLE` sticks | `db.py:592`, inside a `try/finally` |
| registration continues after server persistence fails | `authentication.py:101`, the save is behind `if error is None:` |
| `UPDATE ... LIMIT` needs a non-default SQLite build | `db.py:114`, `SELECT rowid ... LIMIT 1` then a singleton update |
| redundant `if` in the pagination loop | `list(range(start_page, end_page + 1))` |

Two of those were P1 correctness bugs and both are genuinely gone. Closed with that
table in the comment, so the reasoning survives the close.

## 5. Review threads — decisions

Eight unresolved threads, all from `chatgpt-codex-connector`. Three had been left open
by the author explicitly awaiting a maintainer's call. All eight are now answered and
resolved.

**#43 — "cache creation does not belong in a GET route" → keep `READ_ONLY`.**
`tests/routePolicy.py` defines `writes` in its own docstring as "the local SQLite
database or the MCRIT backend". A PNG under `instance/cache/` is neither, and the module
already excludes `get_user_column_setup()`'s row creation on the grounds that it is
"idempotent and not caller-controlled" — the diagram write is both. The route is also
behind `@visitor_required`, which removes the unauthenticated-prefetcher case the P1
rested on, and against `master` the work is *moved off* the page request rather than
added. If image-cache materialisation is ever worth tracking it wants a third value in
that table, not an overload of `WRITES_ON_GET`.

**#47 — "start the total at the earliest dependency" → keep the parent's `created_at`.**
The reviewer is right that the parent is enqueued last: `MongoQueue.put()` inserts the
parent after the children it awaits. But the remedy is worse than the defect, for a
reason neither side had raised. `QueueRemoteCalls.remote_call_function` short-circuits
on the job cache before enqueueing, and `MinHashIndex.py:401` passes exactly those
return values in as `await_jobs` — so a cross compare whose per-sample matches were
computed last week awaits five *finished* jobs from last week. Starting the total at the
earliest dependency would report that job as taking days when it queued and finished in
seconds. The current under-report is bounded by the enqueue interval (measured: 10 ms
for five children); the proposed over-report is bounded by nothing. A tight honest lower
bound beats an upper bound that can be off by days.

**#42 and #66 — "do not patch the vendored asset" → `main_duo.js` is ours.**
Measured on the current head: 3,549 lines against `main.js`'s 3,533, a 510-line diff,
and it already carried `// mcritweb: issue #83` CSRF headers plus resize and sort fixes
before either branch existed. The AGENTS.md rule protects *stock* third-party assets;
applying it here forbids touching a file that is already a fork we maintain. The
mitigation that actually survives an upstream refresh is the one the author shipped:
the fork recorded at `AGENTS.md:147`, and `test_main_duo_keeps_the_hook_function_compare_needs`
plus `testCsrf.py`'s parametrisation failing if the hooks go.

**#26 — Makefile → fixed, and found to be unfixed in eight more places.** See 4.2.

**#10 / #15 / #16 — committed session cookie → accepted, with a correction.** The
signing key belonged to a throwaway instance in a container that no longer exists and
the cookie is scoped to `127.0.0.1`, so the proposed rotation has no target. But "the
file is out of the working tree on every branch" was not quite true: it is still in the
tree of **eight branches**, none of which is merged to
`master`. Rewriting the history of branches carrying open PRs, for an artifact with no
live exposure, is the wrong trade and not an unattended decision — and deleting the
branches, floated as the cheap alternative, would have been worse: each is the head of
an open upstream PR. **Settled in section 9**: upstream removed the file with an
ordinary commit, which is the move neither option here had considered.

## 6. Findings carried out of the merges - now resolved

Six were recorded on 2026-09-12 as unowned. One was withdrawn after measurement
(see section 7). The other five were worked on 2026-09-13 and are fixed, each on the
branch that owns the code.

**1 and 2 - `mcrit` PR #33, `fix/68-cleanup-orphans` (pushed, CI green 7/7).**
`deleteOrphanedQueryData` took its boundary from the newest query function and returned
early when there was none, so with `query_functions` empty the orphaned `query_xcfg`
documents were never collected - permanently. Reachable rather than theoretical:
`addSmdaReport` writes the disassembly (`_insertXcfgDocuments`) before the functions
(`_dbInsertMany`), so an insert interrupted between the two leaves exactly that residue,
and deleting the queries around it empties the collection the boundary came from.
Reproduced against mongo before fixing: two blobs, cleanup answers `query_xcfg: 0`, and
answers 0 again forever after.

With no function id to bound by, an existing query *sample* is what proves an insert may
be in flight - the sample is written first of the three - so the collection is only
emptied when `query_samples` is empty too. The second fix removed the two `distinct()`
calls the docstring's "no single command carries the whole collection" was already
contradicted by: they answer with one document and fail past MongoDB's 16 MiB cap at
roughly 1.3M distinct ids. Now one `$group` read through a cursor, batched, with the
sample lookup done per batch. Three tests; the first two fail on the previous
implementation. 290 pass against mongo, up from 287.

**3 and 4 - `mcrit` PR #35, `feat/95-keep-submitted-binaries` (pushed, CI green 7/7).**
Two memory problems and a missing changelog entry.

`Worker.addBinarySample` decided whether a resubmitted sample already had its binary with
`getSampleBinary(...) is None` - streaming the entire file out of GridFS to answer a
yes/no question, on the ingestion path. And the binary route buffered the whole sample
into `resp.data`. `hasSampleBinary()` and `openSampleBinary()` fix both; measured with
`tracemalloc`:

| | before | after |
|---|---|---|
| resubmission check, 64 MiB sample | 128.1 MiB peak | **0.0 MiB** |
| serving a 32 MiB sample | 64.1 MiB peak | **33.9 MiB** |
| serving a 128 MiB sample | 256.2 MiB peak | **33.9 MiB** |
| serving a 256 MiB sample | 512.4 MiB peak | **33.9 MiB** |

Buffered costs twice the file, because `GridOut.read()` joins the chunks it has
collected. Streamed is flat - bounded by the driver's cursor batch, not the sample - so
this is the difference between constant and linear, which is why it matters on large
corpora rather than in a test. The return type is a small `BinaryStream` Protocol, not
`typing.IO`: `ty` rejects a `GridOut` as one, and it named the exact fix (`size` had to
be positional-only to match `BytesIO.read`). The changelog entry the branch was missing
now carries these numbers and the caveat that the corpus grows by the size of its
submissions. 293 pass, up from 289.

**5 - `mcritweb` PR #67, new branch `feat/schedule-maintenance-jobs`.**
`/status` reports three things a corpus can have wrong and mcrit 1.9.0 added the repair
for each; MCRITweb could report all three and start none of them. Three places had to
agree, and two of them were traps: `data.result()` dispatches to
`result_maintenance.html` from a hand-written list of job parameters, so without adding
the new types the result of a job MCRITweb had itself just scheduled would have been
reported as an invalid job id; and the template would have said "Unhandled maintenance
job type".

Two further bugs fell out of writing the tests rather than being looked for. A backend
answering no job id took `url_for` into a `BuildError` - a 500 where a message belongs -
and **the three pre-existing scheduling routes had the same hole**, saved only by the
backend answering; all six go through one guard now. And `tests/conftest`'s permissive
fake mints a job id only for names starting with one of its queueing prefixes, which did
not include `repair` or `recompute` - exactly the gap its own docstring describes, and
why two of the three new routes failed the policy test while the third quietly did not.
16 tests; reverting the dispatch list fails 4, removing the guard fails 6. 258 pass, up
from 239.

## 7. Dead ends and mistakes, recorded

Kept because the next person doing this will hit the same things.

- **A proposed index for `get_cached_job_id` was measured and dropped.** The queue's
  compound index is `(locked_by, finished_at, priority, created_at)`, shaped for
  `next()`, and the cache lookup filters on `payload.descriptor` and sorts on
  `(finished_at desc, created_at desc)` — so it looked unserved. Benchmarked on 200,000
  job documents in `mongo:7.0`, 60 lookups per configuration:

  | configuration | plan | median | p95 |
  |---|---|---|---|
  | no index at all (**wrong baseline**) | `SORT <- COLLSCAN` | 83.62 ms | 88.43 ms |
  | **as shipped today** | `SORT <- FETCH <- IXSCAN` | **0.82 ms** | 3.08 ms |
  | with `(descriptor, finished_at, created_at)` | `FETCH <- IXSCAN` | 0.63 ms | 3.60 ms |

  The first run omitted the single-field `payload.descriptor` index that
  `_ensure_indices` already creates, and reported a 97.9x win that does not exist.
  Against the real baseline it is **1.3x at the median and slightly worse at p95** —
  the descriptor is selective enough (~20 jobs each) that the in-memory sort is
  trivial. Not worth a third index on a hot write path. Recorded because the reasoning
  that led to the idea was sound and someone will have it again.

- **A sweep reported 17 failures on `feat/34-74-function-pages` that did not exist.** I
  had checked a branch out in a worktree while that worktree's own test run was in
  flight. Re-running it in an untouched worktree: 261 pass. Lesson: a worktree with a
  job running in it is off limits, and a surprising failure is worth reproducing in
  isolation before it is believed.
- **Every "PUSHED" in the first validation pass was a lie.** The script said
  `if git push ... | tail -2; then echo PUSHED; fi` — a pipeline's exit status is its
  *last* command, so `tail` succeeding reported success for fourteen pushes that had all
  been rejected. The real error only surfaced on a bare `git push`:
  `GH007: Your push would publish a private email address`. Commits were being authored
  with the account's private address; rewritten to
  `49360849+r0ny123@users.noreply.github.com` and re-pushed, and every push is now
  checked by its own exit code and confirmed against `git ls-remote`.
- **A Jinja `{# #}` comment cannot go inside a `{% set %}` expression.** Putting one in
  the middle of the empty-state dict literal broke 29 tests. The note belongs in the
  comment block above the map.
- **`ty check` against the system interpreter reports 120 diagnostics on a clean tree.**
  Pass `--python <venv>`.
- **`pip install -e ".[dev]"` fails on this image's Debian-patched setuptools**
  (`AttributeError: install_layout`) while building `picblocks`. A clean venv fixes it.
- **`docker run --ulimit nofile=...` is refused in this sandbox** (`error setting
  rlimit type 7`). Dropping the flag works; the container inherits nofile 20000, which
  was enough for the full suite repeatedly.

## 7a. State at the end of the audit — verified, not assumed

Every line below was re-measured after the last push.

| | before | after |
|---|---|---|
| mcrit PRs 0 commits behind base, conflict-free | 0 / 17 | **17 / 17** |
| mcrit PRs with a green CI run on their current head | 17 / 17 (stale base) | **17 / 17 (current base)** |
| mcritweb PRs 0 behind, conflict-free | 62 / 63 | **62 / 62** (#1 closed) |
| mcritweb PRs passing locally against mcrit 1.9.0 | 59 / 62 | **62 / 62** |
| mcritweb PRs with `make init` that installs pytest | 54 / 62 | **62 / 62** |
| unresolved review threads | 8 | **0** |

- mcrit: all 17 CI runs on the new heads are `success` (runs 222-238).
- mcritweb: the 10 PRs pushed to are green — 100 check runs across `Ruff` and
  `Unit tests` on 3.11/3.12/3.13/3.14, every one `success`.
- The local sweep ran all 62 mcritweb branches against mcrit 1.9.0: 62 green, test
  counts from 239 to 369, zero failures and zero ruff findings.

Push mechanics worth knowing for next time: the account rejects commits authored with
its private address (`GH007`). Everything here is authored as
`49360849+r0ny123@users.noreply.github.com`.

## 8. What remains

- ~~**`mcritweb#9` should merge first.**~~ **Merged 2026-09-13** (`75c09b0`), at the owner's
  instruction, which closes this. `master` now installs `pytest==9.1.1` and
  `pytest-cov==7.1.0` in CI, so a branch cut from it no longer inherits a workflow that
  runs `python -m pytest` without ever installing it.

  Checked before merging rather than after: a simulated merge of #9 into `master`, then of
  that `master` into all 63 open PR heads, produced **0 conflicts**. Worth simulating
  because #9's version of the fix is *not* the one most branches carry - #9 installs
  `"pytest==9.1.1" "pytest-cov==7.1.0"` after the editable install, while the older variant
  installs an unpinned `pytest` before it, and both edit the same region of the same file.
  Git merges them anyway. 56 of the 63 already carry #9's exact change, so for them the
  merge is a no-op; the other 7 (#36, #42, #48, #63, #64, #65, #66) ended up with **both**
  install lines - harmless, since the pinned install runs last and wins, but duplicated
  cruft carrying two contradictory comments about why the line is there.

  **Tidied the same day.** master was merged into the three standalone branches of the
  seven (#66, #65, #63) and the unpinned lines removed; the four stacked on #66 (#64, #48,
  #42, #36) took both through their base, which is why their merge needed no edit of its
  own. The result is asserted rather than eyeballed - each branch's `Install dependencies`
  block is compared byte-for-byte against master's before the push, and the file is checked
  to contain exactly one pinned install and no unpinned one. All **62/62** open PR heads
  now match master's block exactly, and all seven are 0 commits behind master.
- ~~**The eight stale branches holding the cookie blob** are the last tree references to
  it.~~ **Corrected, then settled upstream 2026-09-13** — see section 9. "Stale" was wrong:
  every one of the eight is the head of an *open* upstream PR (`fkie-cad/mcritweb#163`
  through `#170`), matched by SHA on `refs/pull/N/head`, so deleting them would have
  closed eight PRs. Upstream dropped the file itself instead.
- **Nothing here was merged.** Every PR is left reviewed, current and green, for its author
  to merge - that was the scope.

### Smaller things noticed and deliberately left

- `getSampleBinary()` still buffers, by design: it is the bytes API and its callers want
  bytes. Only the two paths that did not need them were moved off it.
- MCRITweb's user manual (`docs/manual/README.md`) documents no maintenance action at all,
  so the three new buttons are not described there either. Worth a pass over the admin
  page as a whole rather than a paragraph bolted on for these three.

## 9. Upstream integration — `fkie-cad/mcritweb#177`, reviewed 2026-09-13

Opened by the maintainer as a **draft, explicitly not for merge**: `integrate-independent`,
183 commits, consolidating 39 of the 76 open upstream PRs onto `master`. It changes the
shape of everything in section 8, so it is recorded here rather than folded into it.

**Whose PRs these are.** Of the 90 upstream PR head refs, **75 are branches in this fork**
— matched by SHA on `refs/pull/N/head`. The upstream backlog and this audit's output are
largely the same set of changes, which is why an integration branch is the thing that now
gates the rest.

### Verified independently, not taken on the PR's word

| Claim | How it was checked | Result |
|---|---|---|
| 39 PRs integrated | `git log --first-parent`, counting `Merge PR #N` subjects | **37** such merges; two of the 39 folded without one |
| nothing lost in conflict resolution | for each, `git merge-tree --write-tree pr177 <PR head>` and compare to `pr177^{tree}` | ~~37/37 identical~~ — **withdrawn: this check cannot fail here** (§10.1) |
| 808 tests pass | full suite in a clean worktree on the head | **803 passed, 5 skipped** (the Playwright browser tests), 244s |
| ruff passes | `ruff check .` | clean |

~~The absorption check is the one worth keeping: re-merging an already-merged PR is a no-op
**only if** the resolution kept all of it, so a hand-resolved merge that quietly dropped a
hunk shows up as a differing tree. None did.~~

**Correction, 2026-09-23.** The check proves nothing here. Every one of those PR heads is an
*ancestor* of the integration, so for each of them the merge base is the PR head itself and
`merge-tree` returns the integration's tree by construction, dropped hunk or not. §10.1
demonstrates it on a fake integration that drops a hunk and still "passes". What stands is
the `--remerge-diff` reading below.

### The resolutions, read with `--remerge-diff`

`git show --remerge-diff` shows exactly what a human changed while resolving, which is
where an integration hides its bugs. Four were worth reading:

- **#164 / #167 / #170** — all three "conflicts" were import blocks. Each resolution keeps
  both sides' imports. Nothing else was touched.
- **#113** — an assertion was retargeted (`"failed!"` → `"the backend did not answer"`)
  because that PR changed the wording. The negative assertion it exists to protect
  (`"Nothing matched" not in page`) is untouched. Reconciled, not weakened.
- **#146 vs #168** — the one that mattered. #146 moved family names to a JSON endpoint,
  which reopened the `innerHTML` injection #168 had closed. Resolved by centralising the
  escaping in a new `mcritweb/autocomplete.py`, shared by the `autocomplete_items`
  template filter and by `explore.family_names`. Both entries into the widget were
  confirmed to go through it, and the test was **strengthened** rather than adjusted: it
  now asserts the raw name does not survive the round trip at all.

**Verdict: no blocking findings.** The gate is the maintainer's own — live review on a
test instance — not anything found here.

### What #177 settles

`3adac71` drops `work/harness/cookies.txt` and gitignores `work/harness/`, with the same
reasoning recorded in section 5 ("a credential artifact — even a dev one against localhost
— should not enter the repository's history"). That closes the open question there, by a
third route: an ordinary commit, no history rewrite and no branch deletion.

Seven of the eight branches carrying the blob are integrated, so merging #177 removes it.
The eighth, `fix/query-uploads-collide-across-users` (upstream #169), is **not** integrated
and would have put the file back. Fixed on the branch:

- `5ef48d8` — drops the file and adds a `.gitignore` block byte-identical to #177's, so the
  two sides of the merge resolve to the same content instead of colliding.
- `7f4d77c` — this branch predates the tooling canonicalisation of section 8, so it carried
  an older wording of the same `AGENTS.md` / `Makefile` change that #177 has since settled
  its own way. Replaced with #177's exact text, for the same reason.

Conflicts against the integration went from **five files to three**: `AGENTS.md` (the
Uploads bullet, genuine PR content), `README.md` (both sides add an `unreleased` entry) and
`mcritweb/views/analyze.py`. 274 tests pass, ruff clean, pushed.

### What is left, and what gates it

**37 PRs are not integrated** (excluding #103, whose content #177 carries at its base, and
#177 itself).

- **4 are gated on the backend**, and the PR names them: upstream `#173 → mcrit#163`,
  `#172 → mcrit#161`, `#174 → mcrit#169`, `#130 → mcrit#185`. Those four are open PRs on
  **`danielplohmann/mcrit`**, headed by this fork's branches (`r0ny123/mcrit#21, #18, #26,
  #42`) — all **0 commits behind upstream `main`**, conflict-free against it, and **7/7
  green**.

  The merge that unblocks them is upstream's, and only upstream's. Merging them into this
  fork's `main` would do nothing — `mcritweb/requirements.txt` asks for `mcrit>=1.5.3`,
  resolved from PyPI, so nothing ever installs what sits in the fork — and it would push
  the fork's `main` ahead of upstream, where it is currently exactly level. Every branch
  cut from it afterwards would carry backend commits upstream does not have, which is the
  trap section 1 records for mcritweb's `master`. Nothing is owed on this side.
- **1 is a sequencing question** — `#176`, which moves the version into `pyproject.toml`.
- **The other 32 need conflict resolution**, and `mcritweb/views/data.py` is the reason: 20
  of them change it, each adding its own helpers to the same regions. This is not the
  mechanical collision that #103 was — there is no single edit that dissolves it.

Measured against `pr177` directly, only **#33, #125, #138 and #172** merge with no conflict
at all, and **#151** conflicts on `AGENTS.md` alone.

A pairwise conflict matrix over the 37 was also computed and is **misleading**, recorded
here so it is not recomputed: it reports `.github/workflows/test.yml`, `AGENTS.md` and
`Makefile` colliding across 36 of 37 pairs. That is an artifact of pairwise comparison —
each pair's merge base is upstream `master`, which lacks the CI fix, so both sides adding
it reads as add/add. Against `pr177`, which already has it, those three files are identical
on most branches and do not conflict.

**The resolution work is gated on #177 landing on `master`.** Merging an unmerged draft
integration branch into 32 PR branches would balloon every one of their diffs with 183
foreign commits. Once it is on `master`, the same branches take it as an ordinary base
merge and each diff collapses back to its own change.

**#177 landed on 2026-09-21**, with two more integrations and the 1.5.0 release; by then 24
upstream PRs were still open, and all of them are current with it. See §10.3.

### Dead end recorded

Checked whether the integration calls an `McritClient` method newer than the declared
`mcrit>=1.5.3` floor — `search_samples`, `search_families` and `search_functions` appear in
no tagged `McritClient.py` when grepping for `def`. They are `functools.partialmethod`
bindings and have been present since v1.5.3. **No finding; the floor is correct.**

### Version, for the maintainer's third question

`1.5.0`, not a patch on `1.4.8`. The integration adds `python_requires=">=3.11"` to
`setup.py` (from #166) — deployment-affecting, since a 3.8–3.10 host stops resolving — on
top of four security fixes and 39 PRs. Suggested order: **#177 first, then #176, then tag**.
Both touch the version, and resolving one PR against a merged integration is a smaller job
than re-resolving a 183-commit integration against one PR.

## 10. Upstream 1.5.0 — verified, and the open PRs brought onto it (2026-09-23)

#177 merged on 2026-09-21, followed the same day by two further integrations and the
release:

| merge on `master` | what it brought |
|---|---|
| `dc2412d` #177 | `integrate-independent`, as reviewed in §9 |
| `210275b` #178 | `integrate-batch-2`: #108, #111, #134 |
| `41b0a17` #179 | `integrate-batch-3`: #116, #139, #144, #150, #165, #175 |
| `3bebcb1` #180 | the manual's lists render as lists on `/help` |
| `98cfdc0` #181 | release 1.5.0 |

53 upstream PR heads are now reachable from `master`.

### 10.1 Master verified, and §9 corrected

- **Tests:** 962 passed, 6 skipped, ruff clean - the figure the release commit states,
  measured here rather than taken from it. The six skips hide more than six tests:
  `testFunctionVsBrowser.py` skips as a whole module, which counts once, and holds 18. With
  `playwright==1.56.0` against the Chromium build preinstalled in this environment the suite
  collects **985, and all 985 pass**. The release notes' "968 in total" and "six of them
  drive a real browser" count that module as one test.
- **§9's absorption check is withdrawn.** A fake integration that merges #170 and then
  reverts its `mcritweb/views/data.py` change, put through the same `merge-tree` comparison,
  comes out "identical". All 39 heads #177 integrated are ancestors of it, which makes the
  check a tautology for every one of them. It can only say something about a PR whose head
  is *not* in the integration's history.
- **Reading the resolutions is the real check, with one blind spot.**
  `git show --remerge-diff` over the 61 merges now on `master`: 20 carry hand edits (12 in
  #177, 8 in the later integrations), and all 20 were read. Three things are worth recording,
  two of them resolutions that did nothing but delete the conflict markers - which reads as
  the safest resolution there is, and was wrong both times:
  - `a5f7aa4` (#175 against #116 in `style.css`, part of batch-3) dropped a closing `}`.
    53 `{` met 52 `}`, and CSS error recovery swallowed the seven rules after it, the
    function comparison's whole layout (#74), without an error anywhere. Already fixed on
    `master` by `a2d020a`. **This read missed it.** The remerge-diff shows nothing but the
    three conflict markers being deleted - both sides kept verbatim, which reads as the
    safest resolution there is. But the two sides had shared one closing `}` below the
    conflict as context, and each needed its own. A brace count catches that where reading
    does not, so every stylesheet merged since has been checked with one.
  - `d350c5d` (#169, `AGENTS.md`) kept the Uploads bullet #169 had rewritten next to its
    rewrite, so the file says both that uploads are "named by SHA-256" and that a query
    upload is named by its job id. Missed here as well; it turned up while checking the
    `data.submit` finding in §10.7, and is fixed on a branch (§10.8).
  - `d350c5d` also removes #104's sha256 check and its tests in favour of #169, which stops
    the request naming the upload's file at all. Legitimate: the replacement tests cover
    every case #104 listed, and more.

### 10.2 Upstream PR state after the release

Read from git (a `refs/pull/N/merge` ref exists only while a PR is open), since the GitHub
API still refuses `fkie-cad` repositories from this environment.

- **24 open:** #107 #114 #115 #117 #119 #122 #126 #130 #132 #133 #136 #141 #142 #145 #147
  #148 #149 #152 #159 #160 #172 #173 #174 #176.
- **Closed without a merge, content superseded:** #33 (unrelated history, older than the
  fork's base), #138, #151, and #169, whose change reached `master` through the integration.

### 10.3 The open PRs brought onto 1.5.0

Each branch took `master` as an ordinary merge — no rebase, no force-push — so every PR's
diff shrinks back to its own change. #172 merges clean and was left alone; the other 23 were
resolved by reading both sides, checked with ruff (which selects `F`, so shadowed and
undefined names fail), a duplicated-block check and a CSS brace count, and pushed only after
a green full suite. Test counts differ because each branch carries its own tests on top of
master's 985 (every test, the browser ones included - see §10.1).

| PR | branch | commits | passed | what the resolution had to decide |
|---|---|---|---|---|
| #107 | `fix/73-empty-result-vs-unknown-job` | `4a32b88` | 991 | its test's name shadowed a new master test — renamed |
| #114 | `fix/89-cache-the-backend-probe` | `9a218fa` `2add9da` | 1017 | unions; and the ADR link text still said 0003 after the ADR became 0012 |
| #115 | `fix/51-job-search` | `56aa4de` | 1071 | the job search rework on master's category check; the group-job tab joins `JOB_CATEGORIES`; a narrowed queue read that one unreadable job fails falls back to the full queue |
| #117 | `fix/41-wrap-long-job-names` | `5e89824` | 995 | one template cell each |
| #119 | `fix/65-empty-table-messages` | `e23feff` | 1044 | `empty_message` beside master's `row_decorations` |
| #122 | `fix/39-one-name-per-job-method` | `aeab268` | 1007 | a test followed the fake's new per-method queue filter |
| #126 | `fix/63-page-specific-libraries` | `151b893` | 1026 | **security:** master's escaped type-ahead (#168) kept over this branch's older copy; icon subset regenerated |
| #130 | `fix/43-backend-transport-errors` | `af8ee07` | 1045 | `require_result` through master's functiondiff refactor; a marker test retired because #77 landed |
| #132 | `fix/36-job-tab-in-the-url` | `2347217` | 991 | master's category check adopted; seven master tests follow the new redirect, one had been passing hollow |
| #133 | `fix/55-rerun-job` | `e4d66f2` | 1040 | one band-range table, read in both directions; an alert git had merged in twice |
| #136 | `fix/45-mark-the-search-term` | `7f38729` | 1055 | `highlight_terms` beside `row_decorations` |
| #141 | `fix/44-dedumped-is-not-a-dump` | `8b5110c` | 1061 | guarded SMDA parse kept; its sha256-named upload write dropped, #169 owns uploads now |
| #142 | `fix/38-filter-the-matching-statistics` | `9ece824` | 1011 | unions |
| #145 | `fix/68-result-page-performance` | `7bc62a6` `54bc9e6` | 1117 | caching rework on master's `utc_now` and logging; then `$`→`\Z` and whole-id matching in the cache lookups |
| #147 | `fix/80-block-isolation-table` | `9e150be` | 999 | annotation applied to master's parametric YARA rule; a button calling a function this branch removed |
| #148 | `fix/7-round-the-score-columns` | `c75221a` | 1009 | a master test encoded truncation; it compares with `round()` now |
| #149 | `fix/46-cross-job-duration` | `3c1371d` | 1016 | a local `utc_now()` shadowed master's timezone-aware one |
| #152 | `fix/50-deduplicate-result-tables` | `7db5fe5` | 996 | master's count wins on the sample-filtered page |
| #159 | `fix/42-cross-compare-ordering` | `05b1621` | 1022 | test helpers git had interleaved, rebuilt |
| #160 | `fix/70-tokenise-the-palette` | `16d8f81` | 1101 | the palette carried onto master's newer templates; row state as classes; the CFG legend drawn from the graph's own colour constants |
| #173 | `feat/72-edit-function-name` | `341c673` | 999 | a stale copy of a fake master had rewritten, dropped |
| #174 | `feat/64-typed-search-results` | `0290e76` | 1003 | master's search views run on `SearchPage`; its new picker converted; an `is None` guard where master tests truthiness |
| #176 | `release/modernize-release-workflow` | `699d889` | 998 | 1.5.0 carried into `pyproject.toml` and `CHANGELOG.md`; the floor stays at master's `>=3.11` |

### 10.4 What git merged without a conflict, and got wrong

The conflict markers were the easy part. None of these was inside one:

| branch | what | caught by |
|---|---|---|
| #107 | a test name defined on both sides; Python keeps the later, so master's stopped running | ruff F811 |
| #176 | `import re` removed from `utility.py`, which master's new code needs; the module no longer imported | ruff F821 |
| #133 | the missing-sub-jobs alert rendered twice | master's own test for that alert |
| #160 | a second, identical 74-line `SCHEMA_V1_4_8` in `testMigrations.py` | the duplicated-block check |
| #160 | master's job-badge test found the badge by `color:green`, which #160 tokenises, so every badge read as absent | the full suite |
| #174 | master's new `unique_blocks` picker still on the dict API, handing a dict to a helper that now takes a `SearchPage`: a 500 | its rendering test, extended to that page first |
| #174 | master's `if not results`, harmless on a dict, drops the exact-match badge from a `SearchPage` that has no text hits | a new test, which fails with the truthiness guard |
| #149 | a module-level `utc_now()` shadowing master's timezone-aware import | reading the auto-merged file |
| #147 | master's button calling a JS function this branch had removed | reading the auto-merged template |
| #132 | a master test passing hollow on the new redirect stub | asking why seven tests changed |

### 10.5 The backend side

Upstream mcrit merged #161 and #185 on 2026-09-16 (with #184). #163 and #169 are still open,
and there is no release after v1.9.0. For the four mcritweb PRs the integration held back:

- #172 (mcrit#161) and #130 (mcrit#185): the backend change is on mcrit's `main`, not yet on
  PyPI.
- #173 (mcrit#163) and #174 (mcrit#169): still gated. #174's adapter takes the typed search
  where the client has one and the dict otherwise, so it also runs against today's release.

This fork's `main` is untouched: 0 ahead of upstream `main`, 13 behind, for §9's reasons.

### 10.6 Mistakes, recorded

- §9's absorption check, above.
- Pushing #115's merge to its twin, `fix/51-malformed-job-payload`, re-created that branch
  on the remote after it had been deleted there: the push went through a stale local
  tracking ref. No PR points at it, and it is identical to `fix/51-job-search`. **It is
  left for the owner to delete.** Since then every push is preceded by `git fetch --prune`
  and `git ls-remote` for the branch. #160's twin, `fix/70-selected-rows-follow-the-theme`,
  does not exist on the remote and was not pushed.
- The script that runs the suite was edited while background runs were using it, which
  corrupted those runs. They were repeated.
- A copy command failed (there is no `rsync` here) and the commands after it ran in the
  live #174 worktree during a suite run. That run was stopped and repeated rather than
  trusted.

### 10.7 Found along the way

Fixed on branches of their own, cut from 1.5.0 (§10.8):

- `data.submit` wrote every submitted binary to `temp/uploads/<sha256>` before handing it to
  mcrit, and nothing read it again: the only reader of that directory is the query upload
  path, which names files by job id (#169). That is an unbounded second copy of every
  submitted sample, usually malware, on the web host - and the 1.5.0 notes tell operators
  the sha256-named files there are orphans they can delete, while this route kept making
  new ones. The name itself was safe: on that branch it is always a digest of the upload.
- ADR references that renumbering left behind: `AGENTS.md` linked 0014 (table reloads) and
  0010 (search results as dicts) under the text "ADR-0003", and `explore.fetchDotGraph` and
  `testCfgGraphs` (twice) cited `docs/adr/0003` - which is about function labels - for the
  CFG export round trip that 0011 records, from the commit that added 0011. Plus the
  duplicated Uploads bullet of §10.1.
- Thirteen check/cross icons across eight templates put the tag's closing `>` inside the
  `{% else %}` branch, so when the condition is true the markup is
  `<i … class="fa-solid fa-square-check" </i>`: the `</i>` is read as attributes and the
  `<i>` element is never closed.

Noted, not changed:

- `index()` asks for finished `getMatchesForSample` jobs only, which never carry a
  `family_id`, so its `getFamily` branch cannot run.
- The jobs page's "Minhashing (N)" counts only mcrit's own minhashing job types, so the
  admin maintenance jobs filed under that tab are listed but not counted in its number.
- The 1.5.0 notes undercount the suite (§10.1); a published release note is not the place
  to fix it, the next one is.

### 10.8 After the branch updates

**The fork's own open PR.** Of the fork's 23 open PRs, 21 head a branch updated in §10.3 and
one (`fix/37-show-job-owner`, #172 upstream) merges clean - and its merge with 1.5.0, built as
a throwaway commit and test-run like the mcrit ones in §11.4, passes too (989, ruff clean).
The last, r0ny123/mcritweb#67
(`feat/schedule-maintenance-jobs`, the admin buttons for mcrit 1.9.0's three repairs), exists
only in the fork and was 247 commits behind 1.5.0. It took `master` without a conflict, and
review turned up two gaps in the PR itself:

- it raised `requirements.txt` to `mcrit>=1.9.0` and left `setup.py` at `>=1.5.3`, so
  `pip install -e .` could resolve an mcrit without the client methods the new buttons call.
  Both files say 1.9.0 now, and `tests/testMcritFloor.py` fails when they disagree;
- the jobs page, which files every job the server page starts under its own type, had no
  entry for the three new types, and `?active=repairMinHashes` said it was not a job type.
  Filed with the others now; the Minhashing tab also marks itself for all eight entries it
  opens onto, where it named three.

`affdc5b`, 1022 passed; the PR description was brought up to date rather than commented on.

**Four fork branches head no PR anywhere** - `fix/56-listing-pages-drop-id-matches-paged`,
`fix/65-empty-state-map-drift`, `fix/69-duo-page-hover-and-edge-throws`, `fix/triage-batch` -
and were left untouched, per the owner's rule about branches unrelated to a PR or issue.

**New fix branches, cut from 1.5.0** (§10.7 has the findings). The owner asked for PRs;
upstream is out of this session's reach - it accepts only repositories of the owner it was
started with - so they are open in the fork, ready to be proposed upstream as they stand:

| PR | branch | commits | passed | what |
|---|---|---|---|---|
| r0ny123/mcritweb#68 | `fix/close-the-check-icon-tags` | `4e5563c` | 989 | thirteen icons closed; a lint over the template tree for any conditional that closes a tag in one branch only, and a render of the sample row both ways |
| r0ny123/mcritweb#69 | `fix/docs-left-stale-by-the-integration` | `ec5cd42` `12c8dca` | 989 | the ADR references, with `tests/testAdrReferences.py` holding them to existing files and matching numbers; the duplicated Uploads bullet |
| r0ny123/mcritweb#70 | `fix/submit-keeps-no-upload-copy` | `5e47c2d` | 987 | `data.submit` keeps no copy; a test submits an unmapped and a dumped binary and finds `temp/uploads` empty |

The last two both edit the AGENTS.md Uploads bullets on neighbouring lines, so whichever
lands second has a one-line conflict; the commit message says how to resolve it.

## 11. mcrit after upstream's 2026-09-16 merges

Upstream mcrit merged #161 (who asked for a job), #184 (the export/import round trip) and
#185 (typed client errors) on 2026-09-16. No release followed; v1.9.0 is still the latest.
**22 upstream mcrit PRs are open**, every one headed by a branch of this fork, and five of
them no longer merged.

### 11.1 The five that conflicted

Each took upstream `main` as an ordinary merge, was resolved by reading both sides, and
passed ruff, `ruff format --check` and every test not marked `mongo` before it was pushed.
MongoDB was not started here, so the `mongo` tests ran in CI: all five fork PRs report all
seven checks green, "Integration tests" (the MongoDB service job) included.

| upstream | branch | commits | what the resolution had to decide |
|---|---|---|---|
| #160 | `fix/47-cached-job-prefers-finished` | `e069654` | two new tests at the same spot in `testMongoQueue`; both kept |
| #163 | `feat/72-modify-function` | `398a5ef` `9a6d09b` | `modifyFunction` beside `main`'s `getMatchesCross(username=)`; then the route's docstring said 202 where it answers 200 |
| #169 | `feat/64-typed-search-results` | `1712f3c` | the `_search_request` / `_search_base` split, parsing in `main`'s mode |
| #177 | `feat/57-family-actors` | `22b2730` | the actors and `main`'s requester, both on the family modification |
| #183 | `docs/54-api-reference` | `5af77d4` | 51 client hunks: the typed client rebuilt with `main`'s six changes applied, then checked method by method against `main` |

### 11.2 What git merged without a conflict, and got wrong

#185 moved every `McritClient` method from `handle_response` to `self._handle`, so a client
built with `raise_client_errors` / `raise_server_errors` raises typed errors instead of
answering `None`. A method written before that - on a branch, or on `main` while #185 was
open - still parses with `handle_response` directly and ignores the mode, and nothing fails
until someone relies on it. Found:

- **on `main`**: `rebuildPicBlockHashIndex`, `repairMinHashes`, `recomputeFamilyStats`,
  which arrived while #185 was open. Fixed on `fix/client-errors-reach-every-method`
  (r0ny123/mcrit#52), with a test for the three and a ratchet that fails on any client method
  parsing outside the client's mode;
- **#163's `modifyFunction`, #169's typed searches, #177's `modifyFamily`**: fixed in their
  merges, each with a test that fails on the bare call;
- **the scaling stack (#194-#200)**: its second PR adds `rebuildFunctionRangeIndex` and
  `rebuildBandDfIndex` the same way. Fixed on 2026-09-23: `main` (e94d339) was cascaded up
  the seven stacked branches with ordinary merges, in stack order (f907296, 5b6efe6, a1afe24,
  e50087c, a071e50, 6356282, 1f4c3e1), and the second branch carries the fix in e9f3c03, with
  a test that failed first (`2 failed, 1 passed` before, `1 passed, 2 subtests passed` after).
  ruff, ruff format and the full suite including the mongo-marked tests pass on every branch
  (218-230 non-mongo, 96-123 mongo), and fork PRs #43-#49 are green on all seven checks,
  Integration tests included. The ratchet above no longer trips on the stack.

Also recorded: #169 asserts the dict search answers `None` in raw mode, and #183 makes every
method honour raw mode. Whichever of the two lands second has to reconcile that test.

### 11.3 The fork's `main`

**Corrected the same day.** This section first said the fork's `main` was still 13 commits
behind upstream, so the five fork PRs above would show upstream's commits in their diffs until
it was synced. That was read off a local ref: the fork's `main` had already been fast-forwarded
to upstream's `e94d339` - by the owner, not here - so it is level, and every fork PR shows only
its own change.

### 11.4 The sixteen that merge clean

A clean textual merge has hidden a broken one often enough today (§10.4, §11.2) that the
other sixteen were not taken on git's word either. For each, the merge with upstream `main`
was built as a throwaway commit object - no branch or ref touched - and put through ruff,
`ruff format --check` and every test not marked `mongo` in a detached worktree.

**All sixteen pass** - ruff and `ruff format --check` clean, every non-`mongo` test green:

| upstream | head | passed | | upstream | head | passed |
|---|---|---|---|---|---|---|
| #162 | `0362447` | 212 | | #193 | `30f590a` | 222 |
| #168 | `2defd5f` | 211 | | #194 | `9ebdfd6` | 218 |
| #170 | `74afed6` | 217 | | #195 | `6d579dc` | 222 |
| #175 | `22596e5` | 210 | | #196 | `5b48854` | 222 |
| #176 | `a1ff15b` | 213 | | #197 | `10748bc` | 222 |
| #178 | `499be21` | 219 | | #198 | `8b796ce` | 222 |
| #179 | `b7dd292` | 215 | | #199 | `db02be2` | 227 |
| #181 | `6bb9388` | 211 | | #200 | `472e3a7` | 229 |

The 22nd, #204 (`ida-bulk-submit`, `65dd5e2`), already contains `main`; its head passes
the same checks (235). So all 22 open upstream mcrit PRs are mergeable into today's `main`
and pass there, bar the `mongo` tests, which CI ran on the five that were changed (§11.1).
None of the sixteen was
touched: a clean, passing merge needs nothing from the branch. The one thing a merge of theirs
would still carry is §11.2's pair of methods in the scaling stack.

### 11.5 Issues

The fork's two open issues, r0ny123/mcrit#50 and #51, each ask the maintainer for a design
decision (an adaptive band-df cutoff; the LogBucket cache keyed on its parameters). They were
left alone at the owner's instruction.

## 12. familiary/mcritweb (2026-09-23)

`fkie-cad/mcritweb` now lives at **`familiary/mcritweb`**: identical history, PR numbers
continuing, `master` at `e4bfa55` (1.5.0 plus CODEOWNERS). The owner asked for its open issues
to be worked end to end, every change tested against a live mcrit and mcritweb, and every PR
left review-ready for Daniel, with nothing merged.

### 12.1 Access, and how the work is split

This session's GitHub access covers the r0ny123 repositories only. Attaching `familiary/mcritweb`
was refused ("cross-tier adds are not supported"), so a second session was started with it as its
repository: `session_01PLUvsNgrmyijTZ3X5QJEU1`. It reads the issues, PRs and checks through the
API. **Writes to familiary - push, comment, PR - answer 403 until the Claude GitHub App is
installed on the familiary organisation**; the owner has been told. Messages reach that session
through a routine that fires into it (`trig_01V1Dy7ENSSbsmxmow8AVNFH`); it answers on a private
status page, "familiary mcritweb triage". The PRs headed by fork branches (#107 to #176, #208 to
#212) are changed from here, since only this session can push to the fork.

### 12.2 State found

- **48 open issues.** 26 were filed on 2026-09-23 (#182 to #207), almost all performance
  findings read from the code and marked as not measured. Of the 22 older ones, 21 are covered by
  an open PR and #76 is backend-side (mcrit's search).
- **29 open PRs**, all green on Python 3.11 to 3.14, none reviewed, all "blocked" only by the new
  CODEOWNERS review. #208 to #212 were opened on 2026-09-23 from fork branches `codex/*` by
  another tool: #209 to #212 port the fork's #67 to #70 (#212 tree-identical, the other three with
  their tests cut down), and #208 fixes #201.
- **Fork work never opened upstream: none that should be.** The four fork branches with no PR are
  already in master (`fix/56-…` through 0eb93f1, 8573a13 and 239a17a; `fix/69-…` through 09847a6),
  an ancestor of #119's branch (`fix/65-empty-state-map-drift`), or notes (`fix/triage-batch`,
  which touches `work/` only).

### 12.3 The live stack

MongoDB 8.0.32 from the upstream tarball; mcrit 1.9.0 from PyPI, served with `--gunicorn`, since
the waitress fallback binds `*:8000` and dies without IPv6 in this container; one mcritweb per PR
under test. The corpus is 64 real samples: setuptools, distlib and installer launchers, pnpm's
fastlist, clipboardy, windows-kill, mcrit's own SMDA test reports, 40 overlay variants, and
ripgrep for Windows (8,479 functions). There are finished jobs of every kind: 1vN, 1v1, a
40-sample cross compare, a binary query, unique blocks, and the three 1.9.0 repairs.

A crawler requests 247 pages as an admin on master and on every PR, diffing status codes. Those
pages are every listing, detail, result, download, link-hunt, CFG and admin page for that data.

- **Master has five 500s.**
  - The three repair jobs' result pages, because `data.result()`'s dispatch falls off its end.
  - GET `/admin/change_password` and `/admin/change_username`. These are debug-mode renderings of
    a documented 400.
- **No PR adds one.**
  - #107 and #212 remove the three result-page 500s.
  - #132's 302 on `/data/jobs` is its design.
  - #172's head is 244 commits behind master, so it was crawled on GitHub's merge ref, and that
    matches master.

### 12.4 The five ported PRs

| PR | pushed | what, and the evidence |
|---|---|---|
| #208 | `747b377` `aab8976` | `unreleased:` lowercase and the house test header. `/api/functions` also read the ID list from `request.data`, which Flask empties for a form body, and a form body is what `curl --data 1,2` sends. Live: master 500, `1c973cd` 400, `aab8976` 200 with the functions. 990 passed. |
| #209 | `cfa945c` | the house header; the lint names the template line instead of raising IndexError on an endif written differently. 988 passed; a reverted template still fails it. |
| #210 | `48ed166` | the house header; a test that each ADR pattern still finds references, so the checks cannot pass on nothing. 989 passed. |
| #211 | - | nothing needed. Live: master leaves `temp/uploads/<sha256>` behind a submit, #211 leaves nothing. 987 passed. |
| #212 | `2f30f4d` | the comment and docstring said an unlisted maintenance job "is reported as an invalid job id". It is a 500 on master, and would be the incompatible-result page under #107. Now worded so it holds either way. Live: all three repairs schedule and render against mcrit 1.9.0. 1022 passed. |

Every head passed the full suite and ruff before its push. One README area is shared: #160,
#176, #208, #211 and #212 each add an `unreleased:` line at the same spot, so whichever lands
later has a one-line conflict. That is the repository's convention, not a defect.

### 12.5 The issues, divided

This session takes the result-page and job-page issues, where its own #145, #152 and #159
already sit: #182, #183, #184, #186, #187, #188, #194 and #195. The other session takes #189
to #193, #196 to #200, #202, and #204 to #207. #201 is done by #208. #203 is not a bug: the
renderer draws only unfiltered data, and live PNGs under six filters were md5-identical to the
unfiltered ones.
