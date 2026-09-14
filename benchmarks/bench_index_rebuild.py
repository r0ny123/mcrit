#!/usr/bin/env python3
"""Measure how the pichash count rebuild scales, grouped against partitioned.

The rebuild is the one operation whose cost still follows corpus size: queries were bounded by
query size, offline maintenance was not. The question this answers is not "is the new code
faster" but "does its cost still bend upwards", so every size is run with both implementations
back to back and the result is an exponent, not a stopwatch reading.

**What it reads and what it writes.** The rebuild consumes exactly one field of the functions
collection, `_pichash`, and produces one small document per distinct hash. So a faithful scratch
corpus is a projection: `$out` the `_pichash` of every function belonging to the first N samples
of a source corpus into `wt_rebuild_<n>.functions`, index it, and both implementations then do
the same work they would do on the real thing. The source database is only ever read - `$out`
writes into the target database - which is what makes it safe to derive sizes from a shared
corpus that must not be modified. The script asserts the source's collection counts are
unchanged when it finishes.

Both implementations already read the index rather than the documents (verified with explain:
PROJECTION_COVERED over IXSCAN `_pichash_1`), so projecting away the other fields does not
favour either one. It does make absolute times lower than on a full corpus, where the same
index scan competes with far more data for the WiredTiger cache. Read the exponents, not the
seconds.

Usage:
    python benchmarks/bench_index_rebuild.py --source-db real --sizes 1000,2000,4000,7244 \
        --repeats 3 --json docs/scaling/measurements/rebuild_pichash.json

    # keep the scratch databases for inspection instead of dropping them
    python benchmarks/bench_index_rebuild.py --source-db real --sizes 500 --keep
"""

import argparse
import json
import math
import os
import resource
import statistics
import time

from pymongo import MongoClient

from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.QueueConfig import QueueConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.storage.MongoDbStorage import MongoDbStorage
from mcrit.storage.StorageFactory import StorageFactory

SCRATCH_PREFIX = "wt_rebuild_"


def freeDiskBytes(path="/"):
    """Bytes free where mongod keeps its data.

    Each scratch corpus is built, measured and dropped, so the peak is one corpus rather than
    all of them - but a scratch corpus for a large size is not small, and a benchmark that
    fills the disk takes the database down with it.
    """
    statistics_ = os.statvfs(path)
    return statistics_.f_bavail * statistics_.f_frsize


def buildStorage(host, port, db_name, partition_size):
    config = McritConfig()
    config.STORAGE_CONFIG = StorageConfig(
        STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB,
        STORAGE_SERVER=host,
        STORAGE_PORT=str(port),
        STORAGE_MONGODB_DBNAME=db_name,
        STORAGE_REBUILD_PARTITION_SIZE=partition_size,
    )
    config.MINHASH_CONFIG = MinHashConfig()
    config.SHINGLER_CONFIG = ShinglerConfig()
    config.QUEUE_CONFIG = QueueConfig()
    return MongoDbStorage(config=config)


def sourceFingerprint(database):
    """Document counts per collection, so 'read-only' is asserted rather than asserted to."""
    return {name: database[name].estimated_document_count() for name in sorted(database.list_collection_names())}


def sampleThreshold(database, num_samples):
    """The sample_id that admits exactly the first `num_samples` samples of the corpus."""
    sample_ids = sorted(document["sample_id"] for document in database.samples.find({}, {"sample_id": 1, "_id": 0}))
    if num_samples >= len(sample_ids):
        return sample_ids[-1], len(sample_ids)
    return sample_ids[num_samples - 1], num_samples


def buildScratchCorpus(client, source_db, target_name, num_samples):
    """Project the pichashes of the first N samples into a scratch database; returns its stats."""
    threshold, resolved_samples = sampleThreshold(client[source_db], num_samples)
    client.drop_database(target_name)
    started = time.time()
    client[source_db].functions.aggregate(
        [
            {"$match": {"sample_id": {"$lte": threshold}}},
            {"$project": {"_id": 0, "_pichash": 1}},
            {"$out": {"db": target_name, "coll": "functions"}},
        ],
        allowDiskUse=True,
    )
    target = client[target_name]
    target.functions.create_index("_pichash")
    stats = target.command("collstats", "functions")
    return {
        "samples": resolved_samples,
        "sample_id_threshold": threshold,
        "functions": target.functions.estimated_document_count(),
        "pichashes": target.functions.count_documents({"_pichash": {"$ne": None}}),
        "storage_bytes": stats["storageSize"],
        "pichash_index_bytes": stats["indexSizes"].get("_pichash_1", 0),
        "build_seconds": time.time() - started,
    }


def groupSpillStats(database):
    """What the grouped rebuild's `$group` costs the server: memory used and spills to disk.

    This is the diagnosis in numeric form. `explain` with executionStats runs the pipeline, so
    it is measured once per size rather than per repeat.
    """
    pipeline = [{"$match": {"_pichash": {"$ne": None}}}, {"$group": {"_id": "$_pichash", "df": {"$sum": 1}}}]
    explained = database.command("explain", {"aggregate": "functions", "pipeline": pipeline, "cursor": {}, "allowDiskUse": True}, verbosity="executionStats")
    for stage in explained.get("stages", []):
        if "$group" in stage:
            return {
                "spills": stage.get("spills"),
                "spilled_bytes": stage.get("spilledDataStorageSize") or stage.get("spilledBytes"),
                "max_used_mem_bytes": stage.get("maxUsedMemBytes"),
                "used_disk": stage.get("usedDisk"),
            }
    return {}


def timeReadPhases(storage, partition_size):
    """Seconds each implementation spends *producing* the counts, before writing any of them.

    A rebuild is a read side and a write side, and "which one got faster" is not answerable from
    the total. Both halves are re-created here rather than instrumented in the storage class,
    because a timer inside the library would be dead weight in production and a flag to enable
    it would be a second code path to keep honest.
    """
    database = storage._getDb()
    pipeline = [{"$match": {"_pichash": {"$ne": None}}}, {"$group": {"_id": "$_pichash", "df": {"$sum": 1}}}]
    started = time.time()
    grouped_hashes = sum(1 for _ in database.functions.aggregate(pipeline, allowDiskUse=True))
    grouped_seconds = time.time() - started
    started = time.time()
    partitioned_hashes = sum(1 for _ in storage._iteratePicHashRuns(partition_size))
    partitioned_seconds = time.time() - started
    return {
        "grouped_read_seconds": grouped_seconds,
        "partitioned_read_seconds": partitioned_seconds,
        "grouped_read_hashes": grouped_hashes,
        "partitioned_read_hashes": partitioned_hashes,
    }


def timeReadPhasesReadOnly(database, partition_size):
    """The same two read phases, over a raw client that provably writes nothing.

    Needed to compare against a full-fidelity corpus. Constructing a MongoDbStorage cannot be
    used for that: `_getDb` ensures indexes on first use, which creates any index the database
    is missing, and a corpus that must not be modified must not be handed to code that writes
    on construction. So the run iterator is reimplemented here in the twenty lines it takes -
    the duplication is the point, since only a client that never writes can be pointed at a
    shared corpus.

    The two loops must stay equivalent to the ones in MongoDbStorage; the harness checks that by
    comparing the hash counts they report, which would diverge if one of them drifted.
    """
    pipeline = [{"$match": {"_pichash": {"$ne": None}}}, {"$group": {"_id": "$_pichash", "df": {"$sum": 1}}}]
    started = time.time()
    grouped_hashes = sum(1 for _ in database.functions.aggregate(pipeline, allowDiskUse=True))
    grouped_seconds = time.time() - started

    started = time.time()
    partitioned_hashes = 0
    holders = 0
    condition = {"$ne": None}
    while True:
        run_key = None
        run_length = 0
        num_keys = 0
        num_runs = 0
        for document in database.functions.find({"_pichash": condition}, {"_id": 0, "_pichash": 1}).sort("_pichash", 1).limit(partition_size):
            key = document["_pichash"]
            num_keys += 1
            if key != run_key:
                if run_key is not None:
                    partitioned_hashes += 1
                    holders += run_length
                run_key, run_length, num_runs = key, 0, num_runs + 1
            run_length += 1
        if run_key is None:
            break
        if num_keys < partition_size:
            partitioned_hashes += 1
            holders += run_length
            break
        if num_runs == 1:
            partitioned_hashes += 1
            holders += database.functions.count_documents({"_pichash": run_key})
            condition = {"$gt": run_key}
        else:
            condition = {"$gte": run_key}
    partitioned_seconds = time.time() - started
    return {
        "grouped_read_seconds": grouped_seconds,
        "partitioned_read_seconds": partitioned_seconds,
        "grouped_read_hashes": grouped_hashes,
        "partitioned_read_hashes": partitioned_hashes,
        "partitioned_read_holders": holders,
    }


def timeRebuild(storage, repeats):
    """Seconds per repeat plus the resulting index, so the two implementations can be compared."""
    durations = []
    num_hashes = 0
    for _ in range(repeats):
        rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        started = time.time()
        num_hashes = storage.rebuildPicHashCountIndex()
        durations.append(time.time() - started)
        peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    counts = {document["_pichash"]: document["df"] for document in storage._getDb()[storage._PICHASH_COUNT_COLLECTION].find({}, {"_pichash": 1, "df": 1, "_id": 0})}
    return {
        "durations": durations,
        "median": statistics.median(durations),
        "min": min(durations),
        "num_hashes": num_hashes,
        "peak_rss_kb": peak_rss,
        "rss_delta_kb": peak_rss - rss_before,
    }, counts


def fitExponent(points):
    """k in cost ~ corpus**k, over the first and last point."""
    (first_size, first_cost), (last_size, last_cost) = points[0], points[-1]
    if first_size <= 0 or first_cost <= 0 or last_size == first_size:
        return None
    return math.log(last_cost / first_cost) / math.log(last_size / first_size)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source-db", default="real", help="corpus to derive scratch sizes from; read only")
    parser.add_argument("--mongo-host", default=os.environ.get("TEST_MONGODB", "127.0.0.1"))
    parser.add_argument("--mongo-port", type=int, default=27017)
    parser.add_argument("--sizes", default="1000,2000,4000", help="corpus sizes in samples")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--partition-size", type=int, default=500000)
    parser.add_argument("--min-free-gb", type=float, default=1.5, help="stop before a size that would leave less than this free")
    parser.add_argument("--keep", action="store_true", help="leave the scratch databases in place")
    parser.add_argument(
        "--read-phase-only",
        action="store_true",
        help="time both read phases against --source-db itself and stop, writing nothing anywhere",
    )
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    client = MongoClient(args.mongo_host, args.mongo_port)
    before = sourceFingerprint(client[args.source_db])

    if args.read_phase_only:
        phases = timeReadPhasesReadOnly(client[args.source_db], args.partition_size)
        print(
            "%s read phase: grouped %.2f s, partitioned %.2f s over %d / %d hashes"
            % (args.source_db, phases["grouped_read_seconds"], phases["partitioned_read_seconds"], phases["grouped_read_hashes"], phases["partitioned_read_hashes"]),
            flush=True,
        )
        after = sourceFingerprint(client[args.source_db])
        print("source database %s unchanged: %s" % (args.source_db, before == after), flush=True)
        if args.json:
            with open(args.json, "w") as outfile:
                json.dump({"source_db": args.source_db, "partition_size": args.partition_size, "read_phases": phases, "unchanged": before == after}, outfile, indent=2)
            print("wrote %s" % args.json, flush=True)
        return

    sizes = [int(size) for size in args.sizes.split(",")]
    results = []
    # kept alongside `results` rather than read back out of it, so the fit works on numbers
    # whose type is obvious at the point of use
    curves = {"grouped": [], "partitioned": []}
    try:
        for num_samples in sizes:
            free_bytes = freeDiskBytes()
            print("free disk before %d samples: %.2f GB" % (num_samples, free_bytes / 2**30), flush=True)
            if free_bytes < args.min_free_gb * 2**30:
                print("stopping: less than %.2f GB free" % args.min_free_gb, flush=True)
                break
            target_name = "%s%d" % (SCRATCH_PREFIX, num_samples)
            corpus = buildScratchCorpus(client, args.source_db, target_name, num_samples)
            print("== %d samples: %d functions, %d with a pichash" % (corpus["samples"], corpus["functions"], corpus["pichashes"]), flush=True)
            spills = groupSpillStats(client[target_name])
            print("   $group: %s" % json.dumps(spills), flush=True)

            phases = timeReadPhases(buildStorage(args.mongo_host, args.mongo_port, target_name, args.partition_size), args.partition_size)
            print(
                "   read phase: grouped %.2f s, partitioned %.2f s" % (phases["grouped_read_seconds"], phases["partitioned_read_seconds"]),
                flush=True,
            )

            grouped, grouped_counts = timeRebuild(buildStorage(args.mongo_host, args.mongo_port, target_name, 0), args.repeats)
            print("   grouped     median %.2f s over %s" % (grouped["median"], ["%.2f" % value for value in grouped["durations"]]), flush=True)
            partitioned, partitioned_counts = timeRebuild(buildStorage(args.mongo_host, args.mongo_port, target_name, args.partition_size), args.repeats)
            print("   partitioned median %.2f s over %s" % (partitioned["median"], ["%.2f" % value for value in partitioned["durations"]]), flush=True)

            identical = grouped_counts == partitioned_counts
            print("   identical index: %s (%d hashes)" % (identical, len(grouped_counts)), flush=True)
            if not identical:
                differing = {key for key in set(grouped_counts) | set(partitioned_counts) if grouped_counts.get(key) != partitioned_counts.get(key)}
                print("   !! %d hashes differ, e.g. %s" % (len(differing), list(differing)[:5]), flush=True)
            results.append(
                {
                    "corpus": corpus,
                    "group_stats": spills,
                    "read_phases": phases,
                    "grouped": grouped,
                    "partitioned": partitioned,
                    "identical_index": identical,
                    "speedup": grouped["median"] / partitioned["median"] if partitioned["median"] else None,
                }
            )
            curves["grouped"].append((float(corpus["samples"]), float(grouped["median"])))
            curves["partitioned"].append((float(corpus["samples"]), float(partitioned["median"])))
            if not args.keep:
                client.drop_database(target_name)
    finally:
        after = sourceFingerprint(client[args.source_db])
        if before != after:
            print(
                "!! SOURCE DATABASE CHANGED: %s" % {name: (before.get(name), after.get(name)) for name in set(before) | set(after) if before.get(name) != after.get(name)},
                flush=True,
            )
        else:
            print("source database %s unchanged across %d collections" % (args.source_db, len(before)), flush=True)

    summary = {}
    if len(results) > 1:
        for name, points in curves.items():
            summary[name] = fitExponent(points)
        print("fitted exponents (cost ~ samples**k): %s" % json.dumps(summary), flush=True)

    if args.json:
        with open(args.json, "w") as outfile:
            json.dump(
                {
                    "source_db": args.source_db,
                    "partition_size": args.partition_size,
                    "repeats": args.repeats,
                    "source_fingerprint_before": before,
                    "source_fingerprint_after": after,
                    "points": results,
                    "exponents": summary,
                },
                outfile,
                indent=2,
            )
        print("wrote %s" % args.json, flush=True)


if __name__ == "__main__":
    main()
