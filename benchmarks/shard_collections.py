#!/usr/bin/env python3
"""Shard an MCRIT database on a MongoDB cluster, and report how queries route.

MCRIT stores everything in MongoDB, which shards natively, so there is nothing here that routes
queries itself - a bespoke router would duplicate mature machinery, be unmergeable upstream, and
could not be validated at the size where it matters. What this does is pick shard keys that match
how MCRIT already queries and writes, apply them, and then *check* the routing rather than assume
it.

The keys follow from the access patterns, not from taste:

  band_N          band_hash (hashed)   Every read is {band_hash: {$in: [...]}} and every write is
                                       an upsert filtered on exactly {band_hash, bucket}. Both
                                       carry the key, so both are targeted. A query names many
                                       hashes and they spread evenly, which is the point: each
                                       shard does 1/N of the lookups, in parallel.
  functions       function_id (hashed) The matching path fetches by function_id ($in from the
                                       candidate sets) and both writers filter on function_id.
                                       Sharding on sample_id instead would scatter the hot path
                                       to speed up ingest, which is the wrong trade.
  pichash_counts  _pichash (hashed)    Read and upserted by _pichash. Sharding it on _id instead
                                       makes every ingest fail outright, because an upsert on a
                                       sharded collection must carry the whole shard key.
  xcfg            _id (hashed)         Fetched by function id, which is the _id here.
  function_ranges sample_id (hashed)   Queried by sample_id since the shortlist fix.

Left unsharded deliberately: samples, families, counters. They are small, and `counters` carries
the only unique index in the schema (name), which a shard key would have to include. Unsharded
collections live on the primary shard and keep working exactly as they do now.

Usage:
    python benchmarks/shard_collections.py --db real --mongo-host 127.0.0.1 --mongo-port 27117
    python benchmarks/shard_collections.py --db real --mongo-port 27117 --report-only
"""

import argparse
import json
import os
import sys
from typing import Any, Dict

# collection -> shard key. Hashed everywhere: the values are already well distributed, and hashed
# keys avoid the monotonically-increasing-key hotspot that ranged keys have on ids handed out by a
# counter - every new function would land on the same shard until the chunk split.
SHARD_KEYS = {
    "functions": "function_id",
    # _pichash, NOT _id. The counts are read with {"_pichash": {"$in": [...]}} and written with an
    # upsert filtered on {"_pichash": ...}, and MongoDB refuses an upsert on a sharded collection
    # whose filter does not carry the whole shard key: "Failed to target upsert by query :: could
    # not extract exact shard key", which fails every ingest rather than degrading. Sharding on
    # _id looked right from the document shape and was wrong about how the collection is used.
    "pichash_counts": "_pichash",
    "xcfg": "_id",
    "function_ranges": "sample_id",
}
UNSHARDED = ("samples", "families", "counters", "query_samples", "query_functions", "matches", "candidates")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", required=True)
    parser.add_argument("--mongo-host", default=os.environ.get("TEST_MONGODB", "127.0.0.1"))
    parser.add_argument("--mongo-port", default="27117")
    parser.add_argument("--num-bands", type=int, default=20)
    parser.add_argument("--initial-chunks", type=int, default=0, help="chunks to pre-split an empty collection into (default: 2 per shard)")
    parser.add_argument("--report-only", action="store_true", help="only print the current sharding state")
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    from pymongo import MongoClient

    client = MongoClient(args.mongo_host, int(args.mongo_port))
    admin = client["admin"]

    try:
        shards = admin.command("listShards")["shards"]
    except Exception as error:
        sys.exit("not a sharded cluster (%s): %s" % (args.mongo_host, error))
    print("cluster has %d shards: %s" % (len(shards), ", ".join(s["_id"] for s in shards)))

    targets = dict(SHARD_KEYS)
    for band_number in range(args.num_bands):
        targets["band_%d" % band_number] = "band_hash"

    if not args.report_only:
        admin.command("enableSharding", args.db)
        chunks_wanted = args.initial_chunks or (len(shards) * 2)
        for collection, key in sorted(targets.items()):
            namespace = "%s.%s" % (args.db, collection)
            handle = client[args.db][collection]
            is_empty = handle.estimated_document_count() == 0
            # A hashed key needs its index first. shardCollection makes one for an empty
            # collection, but not for a populated one.
            handle.create_index([(key, "hashed")])
            # built as one command document rather than passed as keyword arguments: pymongo's
            # Database.command overloads do not cover arbitrary **kwargs, and the dict form is the
            # canonical spelling of the same call
            command: Dict[str, Any] = {"shardCollection": namespace, "key": {key: "hashed"}}
            # numInitialChunks only applies to an empty collection, and without it a hashed key
            # starts life as ONE chunk sitting on one shard - every document lands there until the
            # balancer notices and migrates, which on a fresh cluster means the first bulk load
            # goes to a single machine. Shard before ingesting, not after.
            if is_empty:
                command["numInitialChunks"] = chunks_wanted
            try:
                admin.command(command)
                print("  sharded %-18s on %-12s %s" % (collection, key, "pre-split into %d chunks" % chunks_wanted if is_empty else "(populated: one chunk, balancer will split)"))
            except Exception as error:
                if "already sharded" in str(error):
                    print("  %-18s already sharded" % collection)
                else:
                    print("  FAILED %-18s on %s: %s" % (collection, key, str(error)[:90]))

    # what actually happened, read back from the config metadata rather than assumed
    state = {"shards": [s["_id"] for s in shards], "collections": {}}
    config = client["config"]
    for collection in sorted(list(targets) + list(UNSHARDED)):
        namespace = "%s.%s" % (args.db, collection)
        entry = config["collections"].find_one({"_id": namespace})
        if entry is None or entry.get("dropped"):
            state["collections"][collection] = {"sharded": False}
            continue
        chunks = list(config["chunks"].aggregate([{"$match": {"uuid": entry["uuid"]}}, {"$group": {"_id": "$shard", "n": {"$sum": 1}}}]))
        state["collections"][collection] = {
            "sharded": True,
            "key": entry["key"],
            "chunks_per_shard": {row["_id"]: row["n"] for row in chunks},
        }

    print("\n%-20s %-22s %s" % ("collection", "shard key", "chunks per shard"))
    for collection, info in sorted(state["collections"].items()):
        if info["sharded"]:
            print("%-20s %-22s %s" % (collection, json.dumps(info["key"]), json.dumps(info["chunks_per_shard"])))
        else:
            print("%-20s %-22s %s" % (collection, "(unsharded)", "primary shard"))

    if args.json:
        with open(args.json, "w") as handle:
            json.dump(state, handle, indent=2)
        print("\nwrote %s" % args.json)


if __name__ == "__main__":
    main()
