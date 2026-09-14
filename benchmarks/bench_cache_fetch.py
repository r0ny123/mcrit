#!/usr/bin/env python3
"""Isolate the matching-cache fetch and measure what deduplicating it is worth.

`bench_matching.py match` times the fetch as one stage of a whole query, where it competes
with mongod latency, the band lookup and the scorer. This drives the fetch alone, over the
exact candidate id set a real query produces, so the dedup factor (distinct signatures /
candidate functions) and the time and memory attributable to the fetch are visible
separately from everything else.

Three strategies are compared over the identical id set:

    per_function - decode one signature per candidate function (the pre-change behaviour)
    deduplicated - decode one signature per distinct signature (what the storage now does)
    aggregated   - ask mongod to $group by signature, so a repeated signature also crosses
                   the wire once; an alternative that was measured and not adopted

Read-only: it issues finds and an aggregation against the corpus and writes nothing.

Usage:
    python benchmarks/bench_cache_fetch.py --db real --query-sha256 <sha256> --repeats 3 --json out.json
"""

import argparse
import json
import os
import statistics
import sys
import time
import tracemalloc

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from bench_matching import make_config  # noqa: E402


def collectCandidateFunctionIds(index, query_sample_id, keep_batches):
    """The function id sets one 1-vs-N query asks the matching cache for, in order."""
    from mcrit.matchers.MatcherSample import MatcherSample

    storage = index._storage
    batches = []
    original = storage.createMatchingCache

    def recording(function_ids, *args, **kwargs):
        batches.append(list(function_ids))
        return original(function_ids, *args, **kwargs)

    storage.createMatchingCache = recording
    try:
        MatcherSample(index.queue._worker).getMatchesForSample(query_sample_id)
    finally:
        storage.createMatchingCache = original
    return batches[:keep_batches] if keep_batches else batches


def fetchPerFunction(storage, function_ids):
    """The pre-change fetch: one hex decode per candidate function, no sharing.

    Implemented by replacing only the slice decode inside the production fetch, so slicing,
    the thread pool and the merge loop are identical to the deduplicated path and the
    comparison isolates the decode. A hand-rolled single-cursor loop measured 2x slower than
    the production path here purely because it is single-threaded - which says nothing about
    deduplication.
    """
    original = storage._fetchCacheSlice

    def undeduplicatedSlice(collection_name, query_function_ids):
        rows = []
        signatures = []
        for function_document in storage._getDb()[collection_name].find(
            {"function_id": {"$in": query_function_ids}},
            {"_id": 0, "sample_id": 1, "minhash": 1, "function_id": 1},
        ):
            rows.append((function_document["function_id"], function_document["sample_id"], len(signatures)))
            signatures.append(bytes.fromhex(function_document["minhash"]))
        return rows, signatures

    storage._fetchCacheSlice = undeduplicatedSlice
    try:
        cache_data = storage._getCacheDataForFunctionIds(function_ids)
    finally:
        storage._fetchCacheSlice = original
    return cache_data["func_id_to_minhash"], cache_data["func_id_to_sample_id"]


def fetchDeduplicated(storage, function_ids):
    """What MongoDbStorage does now."""
    cache_data = storage._getCacheDataForFunctionIds(function_ids)
    return cache_data["func_id_to_minhash"], cache_data["func_id_to_sample_id"]


def fetchAggregated(storage, function_ids):
    """Group by signature in mongod, so each distinct signature crosses the wire once.

    Single-cursor and unsliced, unlike the other two, so its *time* is not comparable to
    theirs - it is here for how much it removes from the wire and from BSON decoding.
    """
    minhashes = {}
    sample_ids = {}
    for collection_name, wanted in _splitByCollection(function_ids):
        pipeline = [
            {"$match": {"function_id": {"$in": wanted}}},
            {"$group": {"_id": "$minhash", "functions": {"$push": {"f": "$function_id", "s": "$sample_id"}}}},
        ]
        for group in storage._getDb()[collection_name].aggregate(pipeline, allowDiskUse=True):
            minhash = bytes.fromhex(group["_id"])
            for entry in group["functions"]:
                minhashes[entry["f"]] = minhash
                sample_ids[entry["f"]] = entry["s"]
    return minhashes, sample_ids


def _splitByCollection(function_ids):
    unique_ids = set(function_ids)
    return [
        ("functions", [function_id for function_id in unique_ids if function_id >= 0]),
        ("query_functions", [function_id for function_id in unique_ids if function_id < 0]),
    ]


STRATEGIES = {
    "per_function": fetchPerFunction,
    "deduplicated": fetchDeduplicated,
    "aggregated": fetchAggregated,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mongo-host", default=os.environ.get("TEST_MONGODB", "127.0.0.1"))
    parser.add_argument("--mongo-port", default="27017")
    parser.add_argument("--db", required=True)
    parser.add_argument("--query-sha256", required=True, help="comma-separated sha256 of the query samples")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--keep-batches", type=int, default=0, help="only replay the first N cache batches of a query (0: all)")
    parser.add_argument("--config-overrides", default="", help="JSON of config field -> value")
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    from mcrit.index.MinHashIndex import MinHashIndex

    overrides = json.loads(args.config_overrides) if args.config_overrides else {}
    config = make_config(args.db, args.mongo_host, args.mongo_port, overrides)
    index = MinHashIndex(config=config)
    storage = index._storage

    all_samples = storage.getSamples(start_index=0, limit=0)
    by_sha256 = {sample.sha256: sample.sample_id for sample in all_samples}

    results = []
    for sha256 in [value.strip() for value in args.query_sha256.split(",")]:
        if sha256 not in by_sha256:
            raise KeyError("sha256 %s is not in corpus '%s'" % (sha256, args.db))
        query_sample_id = by_sha256[sha256]
        batches = collectCandidateFunctionIds(index, query_sample_id, args.keep_batches)
        num_candidates = sum(len(batch) for batch in batches)
        print("sample %d (%s): %d cache batches, %d requested function ids" % (query_sample_id, sha256[:12], len(batches), num_candidates), flush=True)

        record = {"sample_id": query_sample_id, "sha256": sha256, "num_cache_batches": len(batches), "num_requested_function_ids": num_candidates, "strategies": {}}
        reference = None
        for name, strategy in STRATEGIES.items():
            durations = []
            for _ in range(args.repeats):
                started = time.perf_counter()
                fetched = [strategy(storage, batch) for batch in batches]
                durations.append(time.perf_counter() - started)
            # memory is measured in a separate pass: tracemalloc taxes every allocation, so
            # timing under it would flatter whichever strategy allocates least - which is the
            # very thing being compared
            tracemalloc.start()
            fetched = [strategy(storage, batch) for batch in batches]
            peak_mb = tracemalloc.get_traced_memory()[1] / (1024.0 * 1024.0)
            tracemalloc.stop()
            merged_minhashes = {}
            merged_sample_ids = {}
            for minhashes, sample_ids in fetched:
                merged_minhashes.update(minhashes)
                merged_sample_ids.update(sample_ids)
            if reference is None:
                reference = (merged_minhashes, merged_sample_ids)
            elif (merged_minhashes, merged_sample_ids) != reference:
                raise AssertionError("strategy %s returned a different mapping than per_function" % name)
            distinct_signatures = len(set(merged_minhashes.values()))
            distinct_objects = len({id(minhash) for minhash in merged_minhashes.values()})
            record["strategies"][name] = {
                "median_seconds": statistics.median(durations),
                "min_seconds": min(durations),
                "seconds": durations,
                "peak_traced_mb": peak_mb,
                "num_functions": len(merged_minhashes),
                "num_distinct_signatures": distinct_signatures,
                "num_signature_objects": distinct_objects,
                "dedup_factor": len(merged_minhashes) / distinct_signatures if distinct_signatures else 1.0,
                "object_sharing_factor": len(merged_minhashes) / distinct_objects if distinct_objects else 1.0,
            }
            entry = record["strategies"][name]
            print(
                "    %-13s %7.3f s median  peak traced %6.1f MB  %d functions / %d distinct signatures (%.2fx), %d signature objects"
                % (
                    name,
                    entry["median_seconds"],
                    entry["peak_traced_mb"],
                    entry["num_functions"],
                    entry["num_distinct_signatures"],
                    entry["dedup_factor"],
                    entry["num_signature_objects"],
                ),
                flush=True,
            )
        results.append(record)

    summary = {"db": args.db, "repeats": args.repeats, "config_overrides": overrides, "queries": results}
    if args.json:
        with open(args.json, "w") as outfile:
            json.dump(summary, outfile, indent=2)
        print("wrote %s" % args.json, flush=True)


if __name__ == "__main__":
    main()
