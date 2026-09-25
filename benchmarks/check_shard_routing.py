#!/usr/bin/env python3
"""Report whether MCRIT's hot queries are routed to specific shards or broadcast to all of them.

This is the question sharding actually turns on, and it is not answered by "it works". A sharded
cluster runs every query correctly whatever the shard key; a badly chosen key just makes each
query touch every shard, so adding machines adds coordination and no capacity. mongos records
which shards it consulted in the explain output, so the answer can be read rather than reasoned
about.

Two shapes matter, and they want opposite things:

  band lookup     {band_hash: {$in: [...]}}    SHOULD spread. A query names thousands of hashes;
                                               splitting them across shards is the point, since
                                               each shard then does 1/N of the lookups in
                                               parallel. Fan-out that divides work is not the
                                               same as a broadcast that duplicates it.
  function fetch  {function_id: {$in: [...]}}  Same: the candidate set is spread by the hashed
                                               key and every shard fetches its own share.
  single lookups  {function_id: <one id>}      SHOULD be targeted to exactly one shard. If a
                                               point query touches every shard, the key is wrong.

So the check is not "targeted everywhere" but "single-document reads hit one shard, and bulk
reads spread evenly instead of piling onto one".

Usage:
    python benchmarks/check_shard_routing.py --db sharded --mongo-port 27117
"""

import argparse
import json
import os
from typing import Any, Dict, List


def shards_consulted(explain):
    """Shard names mongos actually consulted, from either explain shape it returns."""
    stage = explain.get("queryPlanner", {})
    winning = stage.get("winningPlan", {})
    shards = winning.get("shards") or explain.get("shards")
    if isinstance(shards, dict):
        return sorted(shards.keys())
    if isinstance(shards, list):
        return sorted(entry.get("shardName", "?") for entry in shards)
    return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--mongo-host", default=os.environ.get("TEST_MONGODB", "127.0.0.1"))
    parser.add_argument("--mongo-port", default="27117")
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    from pymongo import MongoClient

    client = MongoClient(args.mongo_host, int(args.mongo_port))
    db = client[args.db]
    num_shards = len(client["admin"].command("listShards")["shards"])
    # kept apart rather than as one heterogeneous dict: a {"num_shards": int, "checks": list}
    # literal makes the value type int | list, and appending to it is then not well typed
    checks: List[Dict[str, Any]] = []

    def record(label, collection, query, expectation):
        try:
            explain = db.command("explain", {"find": collection, "filter": query}, verbosity="queryPlanner")
        except Exception as error:
            checks.append({"label": label, "error": str(error)[:120]})
            print("%-34s ERROR %s" % (label, str(error)[:70]))
            return
        consulted = shards_consulted(explain)
        checks.append({"label": label, "shards": consulted, "expectation": expectation})
        print("%-34s %d/%d shards  %s" % (label, len(consulted), num_shards, ",".join(consulted) or "(unsharded: primary)"))

    # a real band hash and function id from the corpus, so the plans are the ones MCRIT produces
    band_doc = db["band_0"].find_one({}, {"band_hash": 1, "_id": 0})
    function_doc = db["functions"].find_one({}, {"function_id": 1, "_id": 0})
    if band_doc is None or function_doc is None:
        print("corpus is empty - index something through mongos first")
        return
    some_hashes = [document["band_hash"] for document in db["band_0"].find({}, {"band_hash": 1, "_id": 0}).limit(50)]
    some_functions = [document["function_id"] for document in db["functions"].find({}, {"function_id": 1, "_id": 0}).limit(50)]

    print("cluster has %d shards\n" % num_shards)
    print("%-34s %s" % ("query", "shards consulted"))
    record("band lookup, one hash", "band_0", {"band_hash": band_doc["band_hash"]}, "targeted")
    record("band lookup, %d hashes" % len(some_hashes), "band_0", {"band_hash": {"$in": some_hashes}}, "spread")
    record("function fetch, one id", "functions", {"function_id": function_doc["function_id"]}, "targeted")
    record("function fetch, %d ids" % len(some_functions), "functions", {"function_id": {"$in": some_functions}}, "spread")
    record("sample by id (unsharded)", "samples", {"sample_id": 0}, "primary only")

    print()
    single = [c for c in checks if c.get("expectation") == "targeted" and "shards" in c]
    if single and all(len(c["shards"]) == 1 for c in single):
        print("point queries are targeted to a single shard - the shard key matches the access pattern")
    elif single:
        print("WARNING: a point query touched more than one shard; the shard key does not match how this is queried")

    if args.json:
        with open(args.json, "w") as handle:
            json.dump({"num_shards": num_shards, "checks": checks}, handle, indent=2)
        print("wrote %s" % args.json)


if __name__ == "__main__":
    main()
