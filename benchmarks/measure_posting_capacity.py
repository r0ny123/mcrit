"""How many function ids one band document holds before MongoDB's 16 MB limit, measured directly.

Pushes ids into a single document in chunks, exactly as _updateBands does ($push/$each with
upsert), until the write is refused, and records the BSON size after every chunk. Run it once
with ids that fit in 32 bits and once with ids past 2**31: pymongo stores a Python int as a
BSON int32 when it fits and as int64 otherwise, so the two differ by four bytes per posting.
Use a throwaway server - it writes.

    python benchmarks/measure_posting_capacity.py --uri mongodb://127.0.0.1:27019/ --out capacity.json
"""

import argparse
import json

from pymongo import MongoClient
from pymongo.errors import PyMongoError

CHUNK = 50_000


def fill(collection, first_id):
    collection.delete_many({})
    pushed = 0
    trace = []
    while True:
        ids = list(range(first_id + pushed, first_id + pushed + CHUNK))
        try:
            collection.update_one({"band_hash": 1}, {"$push": {"function_ids": {"$each": ids}}}, upsert=True)
        except PyMongoError as error:
            size = next(collection.aggregate([{"$project": {"s": {"$bsonSize": "$$ROOT"}}}]))["s"]
            return {
                "first_id": first_id,
                "ids_held": pushed,
                "bytes_held": size,
                "bytes_per_id": size / pushed,
                "refused_at": pushed + CHUNK,
                "error": str(error)[:160],
                "trace": trace,
            }
        pushed += CHUNK
        size = next(collection.aggregate([{"$project": {"s": {"$bsonSize": "$$ROOT"}}}]))["s"]
        trace.append([pushed, size])


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--uri", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()
    collection = MongoClient(args.uri)["posting_capacity"]["band_0"]
    result = {"chunk": CHUNK, "int32_ids": fill(collection, 12_000_000), "int64_ids": fill(collection, 2**31 + 12_000_000)}
    collection.database.client.drop_database("posting_capacity")
    text = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w") as handle:
            handle.write(text + "\n")
    print(json.dumps({key: {k: v for k, v in value.items() if k != "trace"} for key, value in result.items() if isinstance(value, dict)}, indent=2))


if __name__ == "__main__":
    main()
