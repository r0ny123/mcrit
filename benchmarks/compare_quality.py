#!/usr/bin/env python3
"""Compare 1-vs-N match results between two configurations, so a speedup can be priced.

Any change that bounds work by discarding candidates buys latency with recall, and the only
honest way to spend that currency is to measure it. This runs the same query samples twice -
once as a reference (normally stock configuration) and once under the candidate
configuration - and reports what changed, at both levels a user reads results at:

  * sample level: which samples were reported as matching, and their scores. Recall here is
    what matters for "did we still find the related samples".
  * function level: per (query function -> matched sample) pair, whether the same match was
    found and with the same score. This catches a change that keeps the sample but degrades
    the evidence for it.

Reports recall, precision and score agreement, plus the top-K sample recall that a two-stage
design is actually allowed to be judged on (a user reads the top of the list, not all of it).

Usage:
    python benchmarks/compare_quality.py --db scale --queries 5 \
        --candidate-overrides '{"STORAGE_BAND_DF_CUTOFF": 1000}' --json out.json
"""

import argparse
import json
import os
import random
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bench_matching import make_config  # noqa: E402


def run_query(db, mongo_host, mongo_port, sample_id, overrides):
    from mcrit.index.MinHashIndex import MinHashIndex
    from mcrit.matchers.MatcherSample import MatcherSample

    config = make_config(db, mongo_host, mongo_port, overrides)
    index = MinHashIndex(config=config)
    matcher = MatcherSample(index.queue._worker)
    started = time.perf_counter()
    try:
        report = matcher.getMatchesForSample(sample_id)
    finally:
        duration = time.perf_counter() - started

    # entries are either dicts or the slotted MatchedSampleEntry / MatchedFunctionEntry, whose
    # toDict() uses the compact wire names ("fid", "matches"); read the attributes instead, so
    # this does not silently depend on which of the two a given code path handed back
    def field(entry, name, default=None):
        if isinstance(entry, dict):
            return entry.get(name, default)
        return getattr(entry, name, default)

    samples = {}
    for entry in report["matches"]["samples"]:
        samples[field(entry, "sample_id")] = entry
    # the report holds one entry per *query function*, each carrying a list of match tuples
    # [family_id, sample_id, function_id, score, flags]; expand them so recall is measured per
    # (query function -> matched sample), which is the granularity a user reads
    functions = {}
    for entry in report["matches"]["functions"]:
        function_id = field(entry, "fid", field(entry, "function_id"))
        for match_tuple in field(entry, "matches", []) or []:
            if isinstance(match_tuple, dict):
                matched_sample_id, score = match_tuple.get("sample_id"), match_tuple.get("score")
            else:
                matched_sample_id, score = match_tuple[1], match_tuple[3]
            functions[(function_id, matched_sample_id)] = score
    # release this run's connection pool; a comparison opens two per query sample, and mongod
    # aborts rather than degrades when it runs out of file descriptors
    try:
        index._storage._getDb().client.close()
    except Exception:  # nothing here is worth failing a measurement over
        pass
    return {"duration": duration, "samples": samples, "functions": functions}


def sample_score(entry):
    """The score a user ranks the sample list by.

    MatchedSampleEntry nests this as matched.percent.score_weighted - the share of the matched
    sample that the query accounts for, weighted by match score. Reading a flat key here
    silently returned 0.0 for every sample once, which turned "top-K recall" into a comparison
    of two arbitrary orderings and made a working shortlist look like it was dropping the best
    matches. Assert the shape rather than defaulting quietly.
    """
    matched = entry.get("matched") if isinstance(entry, dict) else getattr(entry, "matched", None)
    if isinstance(matched, dict):
        percent = matched.get("percent") or {}
        for key in ("score_weighted", "unweighted", "frequency_weighted"):
            if key in percent:
                return percent[key]
    raise KeyError("no matched.percent score on sample entry: %r" % (sorted(entry) if isinstance(entry, dict) else entry,))


def compare(reference, candidate, top_k_values=(10, 25, 100)):
    reference_samples = set(reference["samples"])
    candidate_samples = set(candidate["samples"])
    found = reference_samples & candidate_samples
    result = {
        "reference_num_samples": len(reference_samples),
        "candidate_num_samples": len(candidate_samples),
        "sample_recall": len(found) / len(reference_samples) if reference_samples else 1.0,
        "sample_precision": len(found) / len(candidate_samples) if candidate_samples else 1.0,
        "missed_samples": len(reference_samples - candidate_samples),
        "extra_samples": len(candidate_samples - reference_samples),
    }
    # top-K recall: of the K samples the reference ranks highest, how many survive
    ranked_reference = sorted(reference_samples, key=lambda sample_id: -sample_score(reference["samples"][sample_id]))
    for top_k in top_k_values:
        head = ranked_reference[:top_k]
        if head:
            result["top%d_sample_recall" % top_k] = sum(1 for sample_id in head if sample_id in candidate_samples) / len(head)
    # do the surviving samples keep their score?
    score_deltas = [abs(sample_score(reference["samples"][sample_id]) - sample_score(candidate["samples"][sample_id])) for sample_id in found]
    result["sample_score_max_delta"] = max(score_deltas) if score_deltas else 0.0
    result["sample_score_mean_delta"] = statistics.fmean(score_deltas) if score_deltas else 0.0

    reference_functions = set(reference["functions"])
    candidate_functions = set(candidate["functions"])
    shared = reference_functions & candidate_functions
    result["reference_num_function_matches"] = len(reference_functions)
    result["candidate_num_function_matches"] = len(candidate_functions)
    result["function_recall"] = len(shared) / len(reference_functions) if reference_functions else 1.0
    identical_scores = sum(1 for key in shared if reference["functions"][key] == candidate["functions"][key])
    result["function_score_identical_fraction"] = identical_scores / len(shared) if shared else 1.0
    result["speedup"] = reference["duration"] / candidate["duration"] if candidate["duration"] else float("inf")
    result["reference_seconds"] = reference["duration"]
    result["candidate_seconds"] = candidate["duration"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", required=True)
    parser.add_argument("--mongo-host", default=os.environ.get("TEST_MONGODB", "127.0.0.1"))
    parser.add_argument("--mongo-port", default="27017")
    parser.add_argument("--queries", type=int, default=5)
    parser.add_argument("--query-sample-ids", default="")
    parser.add_argument("--seed", type=int, default=23)
    parser.add_argument("--reference-overrides", default="{}")
    parser.add_argument("--candidate-overrides", required=True)
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    reference_overrides = json.loads(args.reference_overrides)
    candidate_overrides = json.loads(args.candidate_overrides)

    from mcrit.index.MinHashIndex import MinHashIndex

    index = MinHashIndex(config=make_config(args.db, args.mongo_host, args.mongo_port))
    if args.query_sample_ids:
        queries = [int(value) for value in args.query_sample_ids.split(",")]
    else:
        all_ids = sorted(sample.sample_id for sample in index._storage.getSamples(start_index=0, limit=0))
        queries = random.Random(args.seed).sample(all_ids, min(args.queries, len(all_ids)))

    print("reference: %s" % (reference_overrides or "stock configuration"), flush=True)
    print("candidate: %s" % candidate_overrides, flush=True)
    comparisons = []
    for sample_id in queries:
        reference = run_query(args.db, args.mongo_host, args.mongo_port, sample_id, reference_overrides)
        candidate = run_query(args.db, args.mongo_host, args.mongo_port, sample_id, candidate_overrides)
        result = compare(reference, candidate)
        result["sample_id"] = sample_id
        comparisons.append(result)
        print(
            "sample %-6d %6.3f s -> %6.3f s (%.2fx)   samples %d -> %d (recall %.3f, top10 %.3f)   function matches %d -> %d (recall %.3f, identical scores %.3f)"
            % (
                sample_id,
                result["reference_seconds"],
                result["candidate_seconds"],
                result["speedup"],
                result["reference_num_samples"],
                result["candidate_num_samples"],
                result["sample_recall"],
                result.get("top10_sample_recall", 1.0),
                result["reference_num_function_matches"],
                result["candidate_num_function_matches"],
                result["function_recall"],
                result["function_score_identical_fraction"],
            ),
            flush=True,
        )

    def mean_of(key, default=1.0):
        values = [comparison.get(key, default) for comparison in comparisons]
        return statistics.fmean(values) if values else default

    summary = {
        "db": args.db,
        "reference_overrides": reference_overrides,
        "candidate_overrides": candidate_overrides,
        "comparisons": comparisons,
        "mean_speedup": mean_of("speedup"),
        "mean_sample_recall": mean_of("sample_recall"),
        "mean_top10_sample_recall": mean_of("top10_sample_recall"),
        "mean_top25_sample_recall": mean_of("top25_sample_recall"),
        "mean_function_recall": mean_of("function_recall"),
        "mean_function_score_identical": mean_of("function_score_identical_fraction"),
    }
    print(
        "\nMEAN  speedup %.2fx | sample recall %.4f | top10 %.4f | top25 %.4f | function recall %.4f | identical scores %.4f"
        % (
            summary["mean_speedup"],
            summary["mean_sample_recall"],
            summary["mean_top10_sample_recall"],
            summary["mean_top25_sample_recall"],
            summary["mean_function_recall"],
            summary["mean_function_score_identical"],
        ),
        flush=True,
    )
    if args.json:
        with open(args.json, "w") as outfile:
            json.dump(summary, outfile, indent=2)
        print("wrote %s" % args.json, flush=True)


if __name__ == "__main__":
    main()
