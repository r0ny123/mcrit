#!/usr/bin/env python3
"""Measure how 1-vs-N latency scales, one-stage versus two-stage, over a growing corpus.

This is the experiment the whole exercise turns on. A single corpus size cannot answer
"does latency grow with the corpus"; what is needed is the *same* query samples run against
the same corpus at several sizes, so the only thing that varies is how much corpus there is.

At each checkpoint the corpus is grown to the target size, the function-range index is
rebuilt, and the fixed query set is run under each configuration under test. Results are
emitted as a table of per-stage timings plus the growth factor between checkpoints, which is
the number that says whether a configuration scales or merely runs fast today.

Usage:
    python benchmarks/scaling_sweep.py --db scale --source-db bench_250 \
        --checkpoints 1000 3000 10000 --queries 148,157,8 \
        --configs '{"one-stage": {}, "two-stage": {"MINHASH_MATCHING_SHORTLIST_SIZE": 100, "STORAGE_BAND_DF_CUTOFF": 10000}}' \
        --json data/sweep.json
"""

import argparse
import json
import math
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bench_matching import make_config  # noqa: E402

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))


def corpus_size(db, mongo_host, mongo_port):
    from pymongo import MongoClient

    client = MongoClient(mongo_host, int(mongo_port), maxPoolSize=4)
    try:
        database = client[db]
        return database.samples.count_documents({}), database.functions.count_documents({})
    finally:
        client.close()


def grow_to(db, source_db, target_samples, mongo_host, mongo_port):
    command = [
        sys.executable,
        os.path.join(BENCH_DIR, "synth_corpus.py"),
        "--source-db",
        source_db,
        "--target-db",
        db,
        "--target-samples",
        str(target_samples),
        "--mongo-host",
        mongo_host,
        "--mongo-port",
        str(mongo_port),
    ]
    print("growing %s to %d samples ..." % (db, target_samples), flush=True)
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)


def rebuild_range_index(db, mongo_host, mongo_port):
    from mcrit.storage.MongoDbStorage import MongoDbStorage

    storage = MongoDbStorage(make_config(db, mongo_host, mongo_port))
    num_samples = storage.rebuildFunctionRangeIndex()
    complete = storage.isFunctionRangeIndexComplete()
    storage._getDb().client.close()
    print("function range index: %d samples, complete=%s" % (num_samples, complete), flush=True)
    return complete


def run_benchmark(db, queries, overrides, mongo_host, mongo_port, out_path):
    command = [
        sys.executable,
        os.path.join(BENCH_DIR, "bench_matching.py"),
        "--mongo-host",
        mongo_host,
        "--mongo-port",
        str(mongo_port),
        "match",
        "--db",
        db,
        "--query-sample-ids",
        queries,
        "--json",
        out_path,
    ]
    if overrides:
        command += ["--config-overrides", json.dumps(overrides)]
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(out_path) as infile:
        return json.load(infile)


def stage_totals(summary):
    """Seconds per stage, summed over the query set - where the time actually went."""
    totals = {}
    for query in summary["queries"]:
        for label, entry in query["stages"].items():
            totals[label] = totals.get(label, 0.0) + entry["seconds"]
    return totals


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", required=True, help="corpus to grow and measure")
    parser.add_argument("--source-db", required=True, help="real corpus the synthetic growth is fitted to")
    parser.add_argument("--checkpoints", type=int, nargs="+", required=True)
    parser.add_argument("--queries", required=True, help="comma-separated query sample ids, fixed across checkpoints")
    parser.add_argument("--configs", required=True, help='JSON: {"name": {config overrides}}')
    parser.add_argument("--mongo-host", default=os.environ.get("TEST_MONGODB", "127.0.0.1"))
    parser.add_argument("--mongo-port", default="27017")
    parser.add_argument("--work-dir", default="/tmp")
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    configs = json.loads(args.configs)
    results = []
    for target in sorted(args.checkpoints):
        num_samples, _ = corpus_size(args.db, args.mongo_host, args.mongo_port)
        if num_samples < target:
            grow_to(args.db, args.source_db, target, args.mongo_host, args.mongo_port)
        rebuild_range_index(args.db, args.mongo_host, args.mongo_port)
        num_samples, num_functions = corpus_size(args.db, args.mongo_host, args.mongo_port)
        print("\n=== corpus: %d samples, %d functions ===" % (num_samples, num_functions), flush=True)
        checkpoint = {"num_samples": num_samples, "num_functions": num_functions, "configs": {}}
        for name, overrides in configs.items():
            out_path = os.path.join(args.work_dir, "sweep_%s_%d.json" % (name.replace(" ", "_"), num_samples))
            started = time.time()
            summary = run_benchmark(args.db, args.queries, overrides, args.mongo_host, args.mongo_port, out_path)
            checkpoint["configs"][name] = {
                "median_seconds": summary["median_total_seconds"],
                "mean_seconds": summary["mean_total_seconds"],
                "max_seconds": summary["max_total_seconds"],
                "stage_totals": stage_totals(summary),
                "matched_samples": [query["num_matched_samples"] for query in summary["queries"]],
                "candidate_pairs": sum(query["stages"].get("band_candidate_lookup", {}).get("observed", {}).get("candidate_pairs", 0) for query in summary["queries"]),
                "wall_seconds": time.time() - started,
            }
            print(
                "  %-12s median %7.3f s  mean %7.3f s  max %7.3f s  candidate pairs %d"
                % (name, summary["median_total_seconds"], summary["mean_total_seconds"], summary["max_total_seconds"], checkpoint["configs"][name]["candidate_pairs"]),
                flush=True,
            )
            for label, seconds in sorted(checkpoint["configs"][name]["stage_totals"].items(), key=lambda item: -item[1]):
                print("      %-24s %7.3f s" % (label, seconds), flush=True)
        results.append(checkpoint)

    print("\n\n=== SCALING SUMMARY (median seconds over the fixed query set) ===", flush=True)
    names = list(configs)
    header = "%-12s" % "samples" + "".join("%16s" % name for name in names)
    print(header, flush=True)
    print("-" * len(header), flush=True)
    for checkpoint in results:
        row = "%-12d" % checkpoint["num_samples"]
        row += "".join("%16.3f" % checkpoint["configs"][name]["median_seconds"] for name in names)
        print(row, flush=True)
    if len(results) > 1:
        first, last = results[0], results[-1]
        corpus_growth = last["num_samples"] / max(1, first["num_samples"])
        print("\ncorpus grew %.1fx (%d -> %d samples); latency grew:" % (corpus_growth, first["num_samples"], last["num_samples"]), flush=True)
        for name in names:
            before = first["configs"][name]["median_seconds"]
            after = last["configs"][name]["median_seconds"]
            growth = after / before if before else float("inf")
            # exponent k in latency ~ corpus**k: 1.0 is linear (unusable at scale), 0.0 is flat
            exponent = math.log(growth) / math.log(corpus_growth) if growth > 0 and corpus_growth > 1 else float("nan")
            print("  %-12s %.2fx  (%.3f s -> %.3f s)   latency ~ corpus^%.2f" % (name, growth, before, after, exponent), flush=True)

    if args.json:
        with open(args.json, "w") as outfile:
            json.dump({"checkpoints": results, "configs": configs, "queries": args.queries}, outfile, indent=2)
        print("wrote %s" % args.json, flush=True)


if __name__ == "__main__":
    main()
