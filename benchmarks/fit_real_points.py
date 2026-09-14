#!/usr/bin/env python3
"""Recompute the real-corpus scaling fit from the raw measurement JSON.

Reads the per-repeat harness output for each corpus size and fits cost ~ corpus**k by
least squares on log(corpus) vs log(cost), so the exponent quoted in SUMMARY.md is derived
from the files in the repository rather than typed in by hand.
"""
import json
import math
import os
import sys

D = os.environ.get("MEASURE_DIR", "/home/user/data")
POINTS = ["rr", "r3k", "r5k", "r7k"]

# Corpus size on the x-axis is the number of samples that actually exist. Runs before the
# harness was fixed recorded `num_corpus_samples` from /status instead, which sums the
# denormalised per-family counters; those over-report by a fixed 2,092 on this corpus because
# _updateFamilyStats skips its decrement for a missing family document, so the bulk deletion of
# 2,540 samples never came off them. The offset is verifiable today - /status claims 7,414
# against 5,322 actual - and it reproduces the corpus sizes quoted for the two points that can
# be corroborated independently: r5k's range rebuild covered 4,760 samples (7,328 - 2,092 =
# 5,236 samples, 4,760 of them with functions) and the current corpus counts out exactly.
#
# rr predates the deletion, so the +2,540 component did not exist yet; what remains there is a
# separate -448 under-report from samples added under family documents that were missing. Its
# corrected size is therefore quoted from the count taken at the time rather than derived here.
CORRECTED_SIZE = {"rr": 2016, "r3k": 2997, "r5k": 5236}


def load(prefix, kind):
    """Median across repeats of each summary statistic the harness reports."""
    runs = []
    for i in (1, 2, 3):
        path = os.path.join(D, "%s_%s_%d.json" % (prefix, kind, i))
        if os.path.exists(path):
            runs.append(json.load(open(path)))
    if not runs:
        return None
    pick = lambda key: sorted(r[key] for r in runs)[len(runs) // 2]
    # a run from the fixed harness records the true count; an older one needs the correction
    reported = runs[0]["num_corpus_samples"]
    n = reported if "num_corpus_samples_reported_by_status" in runs[0] else CORRECTED_SIZE.get(prefix, reported)
    return {
        "n": n,
        "median": pick("median_total_seconds"),
        "mean": pick("mean_total_seconds"),
        "max": pick("max_total_seconds"),
        "rss": pick("peak_rss_mb"),
    }


def fit(xs, ys):
    lx = [math.log(x) for x in xs]
    ly = [math.log(y) for y in ys]
    n = len(xs)
    mx = sum(lx) / n
    my = sum(ly) / n
    num = sum((a - mx) * (b - my) for a, b in zip(lx, ly))
    den = sum((a - mx) ** 2 for a in lx)
    return num / den


rows = {"one": [], "full": []}
for prefix in POINTS:
    for kind in ("one", "full"):
        got = load(prefix, kind)
        if got:
            rows[kind].append(got)

if not rows["one"]:
    sys.exit("no measurements found in %s" % D)

print("%-8s %10s %10s %10s %10s %10s" % ("corpus", "one med", "two med", "one max", "two max", "one/two"))
for a, b in zip(rows["one"], rows["full"]):
    assert a["n"] == b["n"], "corpus size mismatch between configurations"
    print("%-8d %10.3f %10.3f %10.3f %10.3f %9.1fx" % (a["n"], a["median"], b["median"], a["max"], b["max"], a["median"] / b["median"]))

print()
print("fitted cost ~ corpus**k over %d points (%d -> %d samples, %.2fx)"
      % (len(rows["one"]), rows["one"][0]["n"], rows["one"][-1]["n"], rows["one"][-1]["n"] / rows["one"][0]["n"]))
for stat in ("median", "mean", "max", "rss"):
    ko = fit([r["n"] for r in rows["one"]], [r[stat] for r in rows["one"]])
    kt = fit([r["n"] for r in rows["full"]], [r[stat] for r in rows["full"]])
    print("  %-7s one-stage k=%+.2f   two-stage k=%+.2f" % (stat, ko, kt))
