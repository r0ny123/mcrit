# MCRIT / mcritweb PR & Issue Survey — 2026-09-24

Sources: `git ls-remote https://github.com/familiary/{mcrit,mcritweb} 'refs/pull/*'` (anonymous,
authoritative for head SHAs and open/closed-via-merge-ref-presence), the github.com HTML pages
(pulls/issues listings and individual PR pages — read-only, no auth; GitHub's free-text `q=` search
on these pages is unreliable/imprecise, noted where used), and the GitHub REST API against
`r0ny123/mcrit` and `r0ny123/mcritweb` (both reachable directly).

No writes, no branch changes, nothing pushed/commented — survey only.

---

## 1. familiary/mcrit

### 1a. The "scaling stack" — PR #194–#200

All confirmed via `git ls-remote refs/pull/N/head` + `refs/pull/N/merge` presence (merge ref = open)
and individual PR page reads. Head SHAs match the fork branch heads **exactly**.

| PR # | Branch (head) | Head SHA | Matches given SHA | State | Base |
|---|---|---|---|---|---|
| 194 | pr1/indexing-crash-fixes | `f907296` (f9072960216a31a77e90cd42029fc119786aa473) | ✅ f907296 | **Merged** (Sep 24, 2026; merge commit `ab56c34`, squash/merge into `familiary:main`) | main |
| 195 | pr2/two-stage-matching | `e9f3c03` (e9f3c03b10fab98d3c26fa5d1724216536bfbeba) | ✅ e9f3c03 | **Open** | main |
| 196 | pr3/band-bucketing | `a1afe24` (a1afe24581164c4819e9ab54dda1f9034a7c0b0a) | ✅ a1afe24 | **Open** | main |
| 197 | pr4/scaling-research | `e50087c` (e50087cde56105be47d6c3a5383a2d88efcae9c7) | ✅ e50087c | **Open** | main |
| 198 | pr5/concurrency-benchmark | `a071e50` (a071e50fb9e2060f6e513b9f93e4cc95cb92bbec) | ✅ a071e50 | **Open** | main |
| 199 | pr6/rebuild-partitioning | `6356282` (635628260701ea6dd4ae7b805bd137a095e78f1b) | ✅ 6356282 | **Open** | main |
| 200 | pr7/cache-fetch-dedup | `1f4c3e1` (1f4c3e1343cd46c5f920f75c5850a71e803379d0) | ✅ 1f4c3e1 | **Open** | main |

All authored by r0ny123. #194 is confirmed merged today (Sep 24, 2026) — "Fix two crashes that abort
indexing on large corpora" (LogBucket.getLogBucketRange KeyError clamp; Worker.updateMinHashes
UnboundLocalError on empty backlog). #195–200 each declare a growing stack of prior commits in their
descriptions (e.g. #197: "stacks on #196"; #200 shows 15 commits including the earlier fixes) — base
branch shown by GitHub is `main` for all of them (stacking is via shared commit history, not a
non-main base).

Corresponding **r0ny123/mcrit fork-local PRs** (stacked against each other, not against familiary):
#43=pr1 (base main), #44=pr2 (base pr1/indexing-crash-fixes), #45=pr3 (base pr2/two-stage-matching),
#46=pr4 (base pr3/band-bucketing), #47=pr5 (base pr4/scaling-research), #48=pr6 (base
pr5/concurrency-benchmark), #49=pr7 (base pr6/rebuild-partitioning). Head SHAs match table above
exactly (cross-verified through the REST API).

### 1b. familiary/mcrit — all other open PRs (24 open total)

Full open-PR list (author is r0ny123 unless noted):

| # | Title | Author |
|---|---|---|
| 214 | Let /jobs select jobs by sample id and by job id | r0ny123 |
| 213 | Add batch lookup endpoints for samples and families | r0ny123 |
| 212 | Accept the empty and one-character values the edit messages allow | r0ny123 |
| 211 | Leave a family alone when it is renamed to its own name | r0ny123 |
| 206 | Let the client's error modes reach the three maintenance jobs | r0ny123 |
| 205 | Bump ty from 0.0.79 to 0.0.82 | dependabot[bot] |
| 204 | Submit samples through headless IDA Pro from the CLI | r0ny123 |
| 200, 199, 198, 197, 196, 195 | (scaling stack, see 1a) | r0ny123 |
| 193 | Release on a tag through trusted publishing, with the checks that were memory before | r0ny123 |
| 183 | Document the REST API and type the McritClient (#54) | r0ny123 |
| 181 | Store pichashes zero-padded so that hex order is numeric order (#145) | r0ny123 |
| 179 | Keep enough of the SMDA report to rebuild it from storage (#94) | r0ny123 |
| 178 | Optionally keep the binary a sample was submitted as (#95) | r0ny123 |
| 177 | Let a family carry the actors it is attributed to (#57) | r0ny123 |
| 176 | Clean up the query data nothing refers to, and survive jobs without a result (#68) | r0ny123 |
| 175 | Say which documents are over MongoDB's size limit, and keep the sample (#42) | r0ny123 |
| 170 | Answer function name searches from the distinct names | r0ny123 |
| 162 | Serve sorted searches from an index, and page past an id of 0 | r0ny123 |
| 160 | Serve repeated requests from the newest finished job, never a failed one | r0ny123 |

(r0ny123 has 57 PRs total against familiary/mcrit historically per the author-filtered listing;
above + 1a covers all 24 currently open.)

### 1c. familiary/mcrit — merged in the last ~3 days (Sep 21–24, 2026)

Top of "updated desc, is:merged" listing (dates shown by GitHub, all r0ny123 except noted):

- **#194** "Fix two crashes that abort indexing on large corpora" — merged Sep 24, 2026
- **#168** "Select jobs before paging them, and count what a listing would show" — merged Sep 24, 2026
- **#169** "Answer searches as SearchResult objects from McritClient" — merged Sep 23, 2026
- **#163** "Let a function be renamed, and record who named it" — merged Sep 23, 2026
- **#185** "Let McritClient raise typed errors instead of answering None for every failure" — merged Sep 16, 2026
- **#184** "Test that an export -> import changes nothing but the ids" — merged Sep 16, 2026
- **#161** "Record who asked for a job" — merged Sep 16, 2026
- **#191** "Say that an upgraded corpus reports every sample as stale, and what to do instead" — danielplohmann, merged Sep 8, 2026

(Repo shows 104 merged PRs total; only #194/#168/#169/#163 fall inside the ~3-day window, the rest
listed for context/recency ordering.)

### 1d. familiary/mcrit — open issues (12)

| # | Title |
|---|---|
| 215 | LogBucket serves a cached table built for another max_value or bucket_width |
| 210 | Let /jobs select jobs by sample id and by job id |
| 209 | Sample and family edits refuse the empty and one-character values their messages allow |
| 208 | Renaming a family to its own name deletes it, and MemoryStorage can't rename a family |
| 207 | Expose a batch sample lookup (POST /samples by ids / McritClient.getSamplesByIds) |
| 203 | Memory/fake-queue mode: LocalQueue mints uuid4 job ids that JobResource rejects as invalid (400) |
| 202 | LogBucket's cache file name carries none of its parameters, so changed bucket settings silently reuse a stale table |
| 201 | Should the band-hash df cutoff become adaptive (WAND/MaxScore) rather than a fixed constant? |
| 192 | Backfill GitHub releases from the changelog: latest release object is v1.3.0 against a current 1.9.0 |
| 145 | Store pichash zero-padded so that hex order is numeric order |
| 126 | ICF: one body can carry several equally-true names, which (pic_hash, function_name) cannot express |
| 95 | Option to store submitted binaries in MCRIT |

Note #202 and #215 look like duplicates/near-duplicates of the same LogBucket cache-key bug.

---

## 2. familiary/mcritweb

### 2a. Open PRs — 55 total, all authored by r0ny123

Highest-numbered (most recent) shown first; full set collected across 3 listing pages:

240, 239, 238, 237, 236, 234, 232, 231, 230, 229, 228, 227, 226, 225, 224, 223, 222, 221, 220, 219,
218, 217, 216, 215, 214, 213, 212, 211, 210, 209, 208, 176, 174, 173, 172, 160, 159, 152, 149, 148,
147, 145, 142, 141, 136, 133, 132, 130, 126, 122, 119, 117, 115, 114, 107 (55 numbers).

Titles for the ones most relevant to the topic search below (see §4); full title list available on
request but omitted here to stay compact — every one was read from the live "Open" filter (`is:pr
is:open`) and cross-checked against `git ls-remote` (each has a `refs/pull/N/merge` ref, consistent
with "open").

### 2b. Recently merged (last ~3 days)

The repo shows **66 merged PRs total**, and the "sort:updated-desc, is:merged" listing's whole first
page (15 shown) is dated **Sep 22, 2026** — i.e. everything visible near the top merged in a single
batch 2 days ago, comfortably inside the ~3-day window. Examples: #170 "Security: submit metadata is
concatenated into the backend's query string unescaped", #168 "Security: a family name is rendered
as HTML by the type-ahead", #165, #166, #164, #104, #163, #106, #162, #123, #121, #167, #137, #103,
#129 — all r0ny123, all "Sep 22, 2026". Could not get GitHub to show anything newer than Sep 22 for
this repo (i.e. no mcritweb PR merged Sep 23–24 was found, unlike mcrit's #194/#168/#169/#163).

### 2c. Open issues (12)

| # | Title |
|---|---|
| 235 | A cross compare's job row leaves out the samples of the unnamed family |
| 233 | Link hunt answers 500 when a filter is submitted with the family count left empty |
| 207 | Id existence checks are followed by a fetch of the same entity |
| 206 | Admin username/password handlers run all checks unconditionally and re-read the user |
| 205 | Family autocomplete re-normalizes lookup and labels once per candidate per keystroke |
| 204 | CFG endpoints rebuild graphs and strings inside per-block loops |
| 203 | Match diagram cache key ignores the active filters |
| 202 | Result cache writes are non-atomic, pretty-printed, and unbounded |
| 201 | Two request branches reference names that are unbound on their fallback paths |
| 200 | API passthrough parses and re-encodes every response end to end |
| 199 | User admin page iterates the full user list five times |
| 198 | Cross-compare embeds a full tooltip payload per cell; job rows group samples quadratically |

---

## 3. Forks (r0ny123/mcrit, r0ny123/mcritweb) — via the REST API

### 3a. r0ny123/mcrit — open PRs (21)

All local/stacked PRs used to build up the branches later opened against familiary. Notable:
#52 "Let the client's error modes reach the three maintenance jobs" (head
`fix/client-errors-reach-every-method` @ 9c93a50e7998eff36c5da2523a5f65091357047f) — SHA matches
familiary #206's head exactly, confirming #206 = this PR opened upstream.
#43–#49 = the scaling stack (pr1..pr7), see §1a.
Others (#40, #38, #36, #35, #34, #33, #32, #27, #26, #22, #21, #20, #19, #17) are the local branches
behind familiary #183, #181, #179, #178, #177, #176, #175, #170, (already-merged predecessors),
#162, #160, etc. — same content, base branches vary (some stack on `main`, some on a sibling
`fix/NN-...` branch such as #19's base `fix/37-record-job-owner`).

### 3b. r0ny123/mcritweb — open PRs (27)

E.g. #70 "Stop data.submit keeping an unread copy of every submitted binary", #69 "Point every ADR
reference...", #68 "Close the check/cross icons...", #67 "Let an admin start the three repairs mcrit
1.9.0 added", #65 "Consume searches as entry objects through one adapter", #63 "Show who requested a
job", down through #59, #57, #50, #47, #46, #45, #43, #40, #39, #33, #30, #29, #27, #23, #19, #16,
#14, #12, #11, #3 — all base `master`. These are the fork-local originals of many of the familiary
open PRs in §2a (numbering differs between fork and upstream).

### 3c. Fork open issues

- r0ny123/mcrit: **2 open** — #51 "LogBucket's cache file name carries none of its parameters..."
  (= familiary #202/#215 topic), #50 "Should the band-hash df cutoff become adaptive (WAND/MaxScore)
  rather than a fixed constant?" (= familiary #201).
- r0ny123/mcritweb: **0 open issues**.

---

## 4. Topic search across all four repos

GitHub's `issues?q=...` free-text search on these repos, read as HTML, proved **unreliable** —
multi-term/OR queries repeatedly returned what look like generic recent-activity listings rather than
true filtered matches (self-inconsistent results across repeated queries with different search
terms). Findings below rely on the most specific single/quoted-term queries plus direct verification
by reading the candidate issue/PR pages; anything not confirmed by reading the actual item is marked
UNVERIFIED.

**(a) 32-bit / int32 vs int64 function ids, 2^31 / 2,147,483,647 overflow, band posting-list dtype**
- familiary/mcrit **#37** "MongoDB may throw an overflow error" (closed, dated 2023) — READ: reporter
  hit `OverflowError: MongoDB can only handle up to 8-byte ints` during sample insertion; about an ID
  field exceeding BSON's **8-byte (int64)** limit, not the 32-bit/2^31 case asked about. **Not a
  match** for the int32/2³¹ overflow or band-posting-list-dtype topic — no issue or PR found that
  covers that specific concern. UNVERIFIED / NOT FOUND for the exact topic.
- PR #196 "Let a band posting list outgrow a single MongoDB document" (open) discusses the 16 MB
  document ceiling (~615k samples) but its description, as summarized, does not mention int32/int64
  function-id width or 2^31 — plausible but **UNVERIFIED** whether it touches posting-list dtype.

**(b) McritClient timeouts, requests.Session, retries**
- No issue or PR title/body match found in familiary/mcrit or r0ny123/mcrit (targeted searches for
  "requests.Session", "read timeout", "connect timeout" returned zero results). PR #206 "Let the
  client's error modes reach the three maintenance jobs" and merged #185 "Let McritClient raise typed
  errors instead of answering None for every failure" are adjacent (client error handling) but do not
  appear, from their titles/summaries, to be about timeouts/Session/retries specifically —
  **UNVERIFIED**, likely NOT COVERED.

**(c) Batch lookup of samples/families (POST /samples/ids), N+1 getSampleById in mcritweb**
- familiary/mcrit **issue #207** "Expose a batch sample lookup (POST /samples by ids /
  McritClient.getSamplesByIds)" — **open**, direct match.
- familiary/mcrit **PR #213** "Add batch lookup endpoints for samples and families" — **open**,
  direct match, presumably implements #207 (and a family equivalent).
- familiary/mcritweb **PR #221** "Look up each sample and family entry at most once per request" —
  **open**, direct match for the N+1 getSampleById topic.
- familiary/mcritweb **issue #207** "Id existence checks are followed by a fetch of the same entity"
  — open, related but narrower (redundant existence-check + fetch, not general N+1 over a list).
- Adjacent open mcritweb PRs also on N+1/duplicate-fetch patterns: #223 "Ask getJobsForSample once
  per row instead of four times", #220 "Stop re-reading rows a request has already loaded", #232
  "Drop id checks that repeat the fetch right after them".

**(d) SQLite WAL / busy_timeout**
- No match. Targeted searches ("SQLite", "WAL", "busy_timeout") on familiary/mcritweb returned no
  issue/PR with SQLite in title; r0ny123/mcritweb search also empty. **NOT FOUND** — mcritweb's user
  store was not confirmed to be SQLite-backed at all in this survey (out of scope to verify further
  without reading source).

**(e) secret_key O_EXCL race**
- familiary/mcritweb **issue #71** "Generate SECRET_KEY dynamically on first start" — **closed**.
  READ in full: body describes `SECRET_KEY` hardcoded as `"dev"` and asks for it to be generated
  dynamically on first deployment; migrated from a private predecessor repo issue (opened 2022-10-04).
  This is the issue that covers the general secret_key-generation topic, but its text (as read) says
  nothing about an **O_EXCL race** specifically — whichever PR closed it may or may not have used an
  atomic/race-safe file-creation pattern. Could not identify the closing PR with confidence (a
  `SECRET_KEY`-filtered PR search returned mostly unrelated open/closed PRs). **UNVERIFIED** whether
  the O_EXCL race itself was ever raised or fixed as a distinct concern.

**(f) jquery-ui upgrade / CVE-2022-31160**
- No match. Quoted "jquery-ui" search on familiary/mcritweb returned nothing with that term in the
  title. Adjacent open issue **#63** "optimize browser performance" (danielplohmann, frontend/
  enhancement) and open PR **#126** "Trim the page weight: page-specific libraries, minified CSS,
  deferred Bootstrap, lazy Dropzone, gzip" touch frontend assets generally but do not name jquery-ui
  or the CVE. **NOT FOUND**.

**(g) docker-mcrit healthchecks or worker scaling**
- No dedicated issue/PR in any of the four repos. Closest hits: familiary/mcrit open issue **#69**
  "Workers consume a lot of ram on query" (yankovs, 2024) — resource/scaling-adjacent but not about
  healthchecks or docker-mcrit specifically; merged **#101** "Modernise packaging and CI, adopt ty,
  and fix the bugs it surfaced" (r0ny123) came up under a "healthcheck" search but its summary gives
  no indication of actually covering healthchecks — likely a false positive from unreliable search.
  docker-mcrit itself is a separate repo not in scope for this survey. **NOT FOUND** / UNVERIFIED.

**(h) band bucketing / 16 MB document limit**
- familiary/mcrit **PR #196** "Let a band posting list outgrow a single MongoDB document" (open,
  part of the scaling stack, see §1a) — direct match. Introduces `STORAGE_BAND_BUCKET_SIZE`,
  bucketing `(band_hash, bucket)` documents, default 0 (off), plus a required
  `rebuild_band_df_index` migration step.
- familiary/mcrit **issue #201** "Should the band-hash df cutoff become adaptive (WAND/MaxScore)
  rather than a fixed constant?" — open, adjacent/related design question, not the same as the 16 MB
  bucketing fix itself.
- familiary/mcrit issues **#202** and **#215** (LogBucket cache-key staleness) are a different
  LogBucket concept (log-scale bucketing table cache) — same word "bucket", unrelated mechanism to
  the band-posting-list document-size fix.

---

## Caveats / things marked UNVERIFIED

- GitHub's HTML search (`?q=...`) read as HTML was demonstrably unreliable for multi-term/boolean
  queries — several calls returned near-identical generic listings regardless of the query string.
  All topic-search conclusions above rely on the most specific quoted single-term queries plus direct
  page reads of the strongest candidates; absence of a hit is reported as NOT FOUND/UNVERIFIED, not
  as proof nothing exists.
- Could not confirm mcritweb's #71-closing PR or whether it used `O_EXCL`.
- Could not confirm PR #196's diff actually changes function-id/posting-list **dtype** to int64 (only
  read the PR description, not the diff) — flagged UNVERIFIED under (a)/(h).
- docker-mcrit and mcrit-plugins/mcrit-data are out of scope (not one of the four repos) and were not
  queried beyond keyword mentions inside familiary/mcrit itself.
