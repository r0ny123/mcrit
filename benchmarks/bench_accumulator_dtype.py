"""Time and peak memory of the numpy band-hit accumulator on the live corpus, read-only.

Run once per code version (int32 before the fix, int64 after) with PYTHONPATH pointing at the
worktree under test:

    PYTHONPATH=<worktree> python benchmarks/bench_accumulator_dtype.py int64 out.json
 The storage object is handed a plain MongoClient database directly, so
_initDb (which ensures indexes, a write) never runs; the accumulator itself only aggregates
band_N and reads settings.
"""

import json
import os
import subprocess
import sys
import time
import tracemalloc

from pymongo import MongoClient

import mcrit
from mcrit.config.McritConfig import McritConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.minhash.MinHash import MinHash
from mcrit.storage.MongoDbStorage import MongoDbStorage

QUERIES = {
    "win.zloader": "009363ee2a5f123ea22f1bdfd8db2193a78cff07674a2852c55f41cbe699e168",
    "win.blackpos": "00c6e653558e41a9f0c83eb506195c72b46bce24c5458e58c33bc25b4566d468",
    "win.acidbox": "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9",
}
REPEATS = 3


def main(label):
    database = MongoClient("mongodb://127.0.0.1:27017/", readPreference="secondaryPreferred")["real"]
    # the commit under test, not its path: the checkout location says nothing about the code
    root = os.path.dirname(os.path.dirname(mcrit.__file__))
    commit = subprocess.run(["git", "-C", root, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    results = {"label": label, "mcrit": commit, "runs": []}
    for cutoff in (0, 200):
        config = McritConfig()
        config.STORAGE_CONFIG = StorageConfig(STORAGE_BAND_DF_CUTOFF=cutoff)
        storage = MongoDbStorage(config)
        storage._database = database
        bits = config.MINHASH_CONFIG.MINHASH_SIGNATURE_BITS
        required = config.MINHASH_CONFIG.BAND_MATCHES_REQUIRED
        for family, sha256 in QUERIES.items():
            sample = database.samples.find_one({"sha256": sha256}, {"sample_id": 1})
            minhashes = {}
            for document in database.functions.find({"sample_id": sample["sample_id"], "minhash": {"$ne": None}}, {"function_id": 1, "minhash": 1}):
                if document["minhash"]:
                    minhashes[document["function_id"]] = MinHash(function_id=document["function_id"], minhash_bytes=bytes.fromhex(document["minhash"]), minhash_bits=bits)
            storage.getCandidateArraysForMinHashes(minhashes, band_matches_required=required)  # warm the cache
            # time and memory in separate passes: tracemalloc taxes every allocation, so timing
            # under it would skew the comparison towards whichever variant allocates less
            times, peaks = [], []
            for _ in range(REPEATS):
                started = time.perf_counter()
                candidates = storage.getCandidateArraysForMinHashes(minhashes, band_matches_required=required)
                times.append(time.perf_counter() - started)
            for _ in range(REPEATS):
                tracemalloc.start()
                storage.getCandidateArraysForMinHashes(minhashes, band_matches_required=required)
                peaks.append(tracemalloc.get_traced_memory()[1])
                tracemalloc.stop()
            pairs = sum(len(array) for array in candidates.values())
            self_found = sum(1 for function_id, array in candidates.items() if function_id in set(array.tolist()))
            results["runs"].append(
                {
                    "cutoff": cutoff,
                    "query": family,
                    "functions": len(minhashes),
                    "candidate_pairs": pairs,
                    "self_hits": self_found,
                    "seconds_median": sorted(times)[1],
                    "peak_mb_median": sorted(peaks)[1] / 2**20,
                }
            )
            print(json.dumps(results["runs"][-1]), flush=True)
    return results


if __name__ == "__main__":
    output = main(sys.argv[1])
    with open(sys.argv[2], "w") as handle:
        json.dump(output, handle, indent=2)
