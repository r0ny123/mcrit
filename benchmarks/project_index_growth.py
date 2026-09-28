#!/usr/bin/env python3
"""Project index size and the per-query I/O floor from the live corpus.

Latency extrapolates badly - the fitted exponents in SUMMARY.md are only honest over the range
they were measured on. Storage extrapolates far better, because the quantity that drives it is
structural rather than empirical: every hashable function contributes exactly one posting to
each of the STORAGE_NUM_BANDS band collections, and function count is linear in sample count.
So the band index size at any corpus size follows from counting what exists today.

That matters for one specific question the latency measurements cannot answer. The two-stage
design bounds the *number* of postings a query reads (STORAGE_BAND_DF_CUTOFF), which is why its
latency is flat. It does not bound the *size of the structure* those reads land in. Once the
band index stops fitting in RAM, each bounded lookup stops being a memory reference and becomes
a disk seek, and the per-query floor is set by seek count times seek cost.

Usage:
    python benchmarks/project_index_growth.py --db real --target 1000000
"""

import argparse
import json
import os
import sys

# A query reads one posting list per band per distinct function signature, so the seek count is
# driven by query size, not corpus size. These are the measured query sizes from the real-corpus
# runs; the median is used unless --query-functions is given.
MEASURED_QUERY_FUNCTIONS = (158, 557, 650)

# Random-read latencies for a B-tree leaf that is not cached. Internal nodes stay resident even
# at 10^6 - they are a tiny fraction of the structure - so one lookup costs about one leaf read.
DEVICE_SEEK_US = {"NVMe SSD": 80.0, "SATA SSD": 150.0, "spinning disk": 5000.0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--mongo-host", default=os.environ.get("TEST_MONGODB", "127.0.0.1"))
    parser.add_argument("--mongo-port", default="27017")
    parser.add_argument("--target", type=int, default=1000000, help="corpus size to project to")
    parser.add_argument("--query-functions", type=int, default=0, help="override the measured median query size")
    parser.add_argument("--heaps-beta", type=float, default=0.7247, help="Heaps' law exponent for distinct band hashes, fitted in measure_growth.py")
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    from pymongo import MongoClient

    client = MongoClient(args.mongo_host, int(args.mongo_port))
    db = client[args.db]

    num_samples = db.samples.count_documents({})
    if not num_samples:
        sys.exit("corpus '%s' is empty" % args.db)
    num_functions = db.functions.estimated_document_count()

    band_names = sorted(name for name in db.list_collection_names() if name.startswith("band_") and name[5:].isdigit())
    bands = {"count": len(band_names), "docs": 0, "storage_bytes": 0, "index_bytes": 0}
    for name in band_names:
        stats = db.command("collStats", name)
        bands["docs"] += stats["count"]
        bands["storage_bytes"] += stats["storageSize"]
        bands["index_bytes"] += stats["totalIndexSize"]
    band_bytes = bands["storage_bytes"] + bands["index_bytes"]

    growth = args.target / num_samples
    query_functions = args.query_functions or sorted(MEASURED_QUERY_FUNCTIONS)[len(MEASURED_QUERY_FUNCTIONS) // 2]
    # one posting list per band per query function
    seeks = query_functions * max(1, bands["count"])

    projected_band_bytes = band_bytes * growth  # postings are linear in functions, functions in samples
    projected_distinct = bands["docs"] * (growth**args.heaps_beta)  # vocabulary grows sublinearly

    print("corpus today")
    print("  samples                 %12d" % num_samples)
    print("  functions               %12d" % num_functions)
    print("  band collections        %12d" % bands["count"])
    print("  distinct band hashes    %12d" % bands["docs"])
    print("  band index size         %12.2f GB  (storage %.2f + indexes %.2f)" % (band_bytes / 1e9, bands["storage_bytes"] / 1e9, bands["index_bytes"] / 1e9))
    print()
    print("projected to %d samples (%.0fx)" % (args.target, growth))
    print("  functions               %12.3e" % (num_functions * growth))
    print("  distinct band hashes    %12.3e   (Heaps, beta=%.4f)" % (projected_distinct, args.heaps_beta))
    print("  band index size         %12.1f GB" % (projected_band_bytes / 1e9))
    print()
    print("per-query I/O floor at that size, for a %d-function query" % query_functions)
    print("  band lookups (seeks)    %12d   (%d functions x %d bands)" % (seeks, query_functions, bands["count"]))
    for device, micros in sorted(DEVICE_SEEK_US.items(), key=lambda item: item[1]):
        print("  %-18s      %12.2f s" % (device, seeks * micros / 1e6))
    print()
    print("The df cutoff bounds how many postings each lookup reads, so the seek count above is")
    print("independent of corpus size - but the structure they land in is not, and at this size it")
    print("cannot be resident on one machine. That floor is what sharding buys down, by cutting the")
    print("index each node holds rather than the work each query does.")

    if args.json:
        with open(args.json, "w") as handle:
            json.dump(
                {
                    "num_samples": num_samples,
                    "num_functions": num_functions,
                    "num_bands": bands["count"],
                    "distinct_band_hashes": bands["docs"],
                    "band_index_bytes": band_bytes,
                    "target_samples": args.target,
                    "growth": growth,
                    "projected_band_index_bytes": projected_band_bytes,
                    "projected_distinct_band_hashes": projected_distinct,
                    "query_functions": query_functions,
                    "band_lookups_per_query": seeks,
                    "io_floor_seconds": {device: seeks * micros / 1e6 for device, micros in DEVICE_SEEK_US.items()},
                    "heaps_beta": args.heaps_beta,
                },
                handle,
                indent=2,
            )
        print("\nwrote %s" % args.json)


if __name__ == "__main__":
    main()
