#!/usr/bin/env python3
"""Fingerprint a MongoDB database so a benchmark can prove it did not modify it.

The scaling corpus is read-only by policy, but the match path touches enough collections
(query samples, matching-cache persistence, job/queue bookkeeping, family counters) that
"matching only reads" is an assumption worth checking rather than asserting. This records a
per-collection document count plus the database-level statistics, and compares two such
records.

Usage:
    python benchmarks/db_fingerprint.py capture --db real --out before.json
    python benchmarks/db_fingerprint.py compare --before before.json --after after.json
"""

import argparse
import json
import sys

from pymongo import MongoClient

# dataSize/storageSize move when WiredTiger compacts or checkpoints without anything being
# written, so the comparison is on the fields that only change when documents do.
COMPARED_DB_STATS = ("collections", "objects")


def capture(args):
    client = MongoClient(args.mongo_host, int(args.mongo_port))
    database = client[args.db]
    collection_names = sorted(database.list_collection_names())
    record = {
        "db": args.db,
        "collections": {name: database[name].count_documents({}) for name in collection_names},
        "db_stats": {key: database.command("dbstats").get(key) for key in COMPARED_DB_STATS},
    }
    text = json.dumps(record, indent=2)
    if args.out:
        with open(args.out, "w") as outfile:
            outfile.write(text)
    print(text, flush=True)


def compare(args):
    with open(args.before) as handle:
        before = json.load(handle)
    with open(args.after) as handle:
        after = json.load(handle)
    differences = []
    for name in sorted(set(before["collections"]) | set(after["collections"])):
        before_count = before["collections"].get(name)
        after_count = after["collections"].get(name)
        if before_count != after_count:
            differences.append("collection %s: %s -> %s" % (name, before_count, after_count))
    for key in COMPARED_DB_STATS:
        if before["db_stats"].get(key) != after["db_stats"].get(key):
            differences.append("dbstats %s: %s -> %s" % (key, before["db_stats"].get(key), after["db_stats"].get(key)))
    if differences:
        print("MODIFIED: database '%s' changed during the run" % before["db"], flush=True)
        for difference in differences:
            print("  " + difference, flush=True)
        return 1
    print(
        "UNCHANGED: database '%s', %d collections, %s objects, identical before and after" % (before["db"], len(before["collections"]), before["db_stats"].get("objects")),
        flush=True,
    )
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mongo-host", default="127.0.0.1")
    parser.add_argument("--mongo-port", default="27017")
    subparsers = parser.add_subparsers(dest="command", required=True)

    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--db", required=True)
    capture_parser.add_argument("--out", default="")
    capture_parser.set_defaults(func=capture)

    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument("--before", required=True)
    compare_parser.add_argument("--after", required=True)
    compare_parser.set_defaults(func=compare)

    args = parser.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
