"""How far a live corpus is from two hard limits, measured read-only.

1. The 16 MB MongoDB document limit on a band posting list (one document per band hash, its
   `function_ids` array only ever grows unless STORAGE_BAND_BUCKET_SIZE splits it).
2. The 2**31 - 1 ceiling on function ids wherever they are held as int32.

Also reports how much of an average function document the hex-encoded minhash takes, which is
what storing it as binary would halve.

Only aggregations and finds are issued; nothing is written. Usage:

    python benchmarks/measure_id_and_list_headroom.py --db real --out headroom.json
"""

import argparse
import json
import time

from pymongo import MongoClient

DOCUMENT_LIMIT = 16 * 1024 * 1024
INT32_MAX = 2**31 - 1


def bandStats(database):
    bands = sorted((name for name in database.list_collection_names() if name.startswith("band_") and name[5:].isdigit()), key=lambda name: int(name[5:]))
    per_band = {}
    for name in bands:
        pipeline = [
            {"$project": {"n": {"$size": {"$ifNull": ["$function_ids", []]}}, "s": {"$bsonSize": "$$ROOT"}}},
            {
                "$group": {
                    "_id": None,
                    "documents": {"$sum": 1},
                    "postings": {"$sum": "$n"},
                    "max_ids": {"$max": "$n"},
                    "max_bytes": {"$max": "$s"},
                    "over_200": {"$sum": {"$cond": [{"$gt": ["$n", 200]}, 1, 0]}},
                    "over_10000": {"$sum": {"$cond": [{"$gt": ["$n", 10000]}, 1, 0]}},
                }
            },
        ]
        row = next(database[name].aggregate(pipeline, allowDiskUse=False), None) or {}
        row.pop("_id", None)
        per_band[name] = row
    largest = max(per_band.values(), key=lambda row: row.get("max_bytes", 0))
    bytes_per_id = largest["max_bytes"] / largest["max_ids"] if largest.get("max_ids") else None
    return {
        "bands": per_band,
        "largest_ids": largest.get("max_ids"),
        "largest_bytes": largest.get("max_bytes"),
        "largest_share_of_16mb": largest.get("max_bytes", 0) / DOCUMENT_LIMIT,
        "bytes_per_id_in_largest": bytes_per_id,
        "ids_that_fit_in_16mb": int(DOCUMENT_LIMIT / bytes_per_id) if bytes_per_id else None,
    }


def functionStats(database, sample_size):
    samples = database.samples.count_documents({})
    functions = database.functions.estimated_document_count()
    newest = database.functions.find({}, {"function_id": 1, "_id": 0}).sort("function_id", -1).limit(1)
    max_function_id = next(iter(newest), {}).get("function_id")
    pipeline = [
        {"$sample": {"size": sample_size}},
        {
            "$project": {
                "s": {"$bsonSize": "$$ROOT"},
                "m": {"$cond": [{"$eq": [{"$type": "$minhash"}, "string"]}, {"$strLenBytes": "$minhash"}, 0]},
            }
        },
        {
            "$group": {
                "_id": None,
                "n": {"$sum": 1},
                "avg_document_bytes": {"$avg": "$s"},
                "avg_minhash_hex_bytes": {"$avg": "$m"},
                "with_minhash": {"$sum": {"$cond": [{"$gt": ["$m", 0]}, 1, 0]}},
            }
        },
    ]
    sampled = next(database.functions.aggregate(pipeline), {})
    sampled.pop("_id", None)
    collection_stats = database.command("collstats", "functions")
    functions_per_sample = functions / samples if samples else None
    return {
        "samples": samples,
        "functions": functions,
        "max_function_id": max_function_id,
        "functions_per_sample": functions_per_sample,
        "int32_headroom_ids": INT32_MAX - max_function_id if max_function_id is not None else None,
        "samples_until_int32_at_this_density": int(INT32_MAX / functions_per_sample) if functions_per_sample else None,
        "sampled_documents": sampled,
        "minhash_share_of_average_document": sampled["avg_minhash_hex_bytes"] / sampled["avg_document_bytes"] if sampled else None,
        "functions_data_bytes": collection_stats.get("size"),
        "functions_storage_bytes": collection_stats.get("storageSize"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--db", required=True)
    parser.add_argument("--uri", default="mongodb://127.0.0.1:27017/")
    parser.add_argument("--sample-size", type=int, default=20000)
    parser.add_argument("--out")
    args = parser.parse_args()
    database = MongoClient(args.uri)[args.db]
    started = time.time()
    result = {
        "db": args.db,
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "bands": bandStats(database),
        "functions": functionStats(database, args.sample_size),
    }
    result["seconds"] = round(time.time() - started, 1)
    text = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w") as handle:
            handle.write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
