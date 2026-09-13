# Repository audit — mcrit + mcritweb

A running log of an end-to-end triage of every open pull request across
`r0ny123/mcrit` and `r0ny123/mcritweb` (forks of `danielplohmann/mcrit` and
`fkie-cad/mcritweb`), including what was found, what was decided and why, and what
is deliberately left.

Audit date: 2026-09-12. Baselines are measured, not estimated; every number below
came from a run in this environment.

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

`master`'s CI workflow still runs `python -m pytest` without installing it. The green
runs on every mcritweb PR date from 2026-09-06, before 1.9.0 shipped; the next run on
any branch without the fix is red for a reason unrelated to its own change. PR #9 is
the fix and it should land first.

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
tree of **eight branches**, none of which has an open PR and none of which is merged to
`master`. All 62 open PR heads are clean. Rewriting the history of branches carrying
open PRs, for an artifact with no live exposure, is the wrong trade and not an
unattended decision; deleting those eight stale branches is the cheap complete cleanup
and is flagged for the owner rather than done.

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

- **`mcritweb#9` should merge first.** `master`'s workflow runs `python -m pytest` without
  ever installing it, which worked only while mcrit brought pytest along. mcrit 1.9.0 moved
  it into the `dev` extra, and this is no longer theoretical: the CI run on `mcritweb#67`
  failed on all four Python versions with `No module named pytest`, against a diff that has
  nothing to do with it. Verified in a clean venv - installing `requirements.txt` resolves
  mcrit 1.9.0 and `import pytest` fails. #9's four lines are ported into #67 so it can be
  green while #9 waits, and they no-op the moment #9 lands. Every branch cut from `master`
  after that inherits the problem again until it does.
- **The eight stale branches holding the cookie blob** are the last tree references to it.
  None has an open PR; deleting them is the complete cleanup and needs the owner's
  go-ahead (section 5).
- **Nothing here was merged.** Every PR is left reviewed, current and green, for its author
  to merge - that was the scope.

### Smaller things noticed and deliberately left

- `getSampleBinary()` still buffers, by design: it is the bytes API and its callers want
  bytes. Only the two paths that did not need them were moved off it.
- MCRITweb's user manual (`docs/manual/README.md`) documents no maintenance action at all,
  so the three new buttons are not described there either. Worth a pass over the admin
  page as a whole rather than a paragraph bolted on for these three.
