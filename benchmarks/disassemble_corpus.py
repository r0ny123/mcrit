#!/usr/bin/env python3
"""Disassemble a directory of samples into cached SMDA reports.

Disassembly is by far the most expensive step of building a benchmark corpus (seconds per
sample), and it is pure function of the file: caching the reports on disk lets every later
experiment - indexing, re-indexing under a different band projection, replaying a corpus -
start from the reports instead of paying for SMDA again.

Reports are written as gzipped SMDA JSON named <sha256>.smda.gz, one per input file, with
the family taken from the sample's parent directory name (which is how both the Malpedia
API layout and the malpedia.zip layout are organised).

Usage:
    python benchmarks/disassemble_corpus.py --in data/malpedia_api --out data/reports \
        [--workers 4] [--limit N] [--timeout 300]
"""

import argparse
import gzip
import hashlib
import json
import os
import sys
import time
from multiprocessing import Pool


def find_samples(root, skip_suffixes=(".done", ".smda", ".gz", ".json", ".txt", ".md")):
    """Every candidate sample file under root, as (family, path)."""
    found = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for filename in sorted(filenames):
            if filename.endswith(skip_suffixes):
                continue
            path = os.path.join(dirpath, filename)
            if not os.path.isfile(path) or os.path.getsize(path) == 0:
                continue
            # the family is the malpedia-style directory holding the sample; with the
            # date-subdirectory layout of malpedia.zip that is one level further up
            family = os.path.basename(dirpath)
            if family and family[0].isdigit():  # a date directory such as 2023-07-29
                family = os.path.basename(os.path.dirname(dirpath))
            found.append((family, path))
    return found


def disassemble_one(task):
    family, path, out_dir = task
    # imported in the worker: SMDA pulls in capstone/lief, which need not be paid for in the parent
    from smda.Disassembler import Disassembler
    from smda.SmdaConfig import SmdaConfig

    try:
        with open(path, "rb") as infile:
            content = infile.read()
        sha256 = hashlib.sha256(content).hexdigest()
        out_path = os.path.join(out_dir, "%s.smda.gz" % sha256)
        if os.path.exists(out_path):
            return ("cached", path, 0.0, 0)
        started = time.time()
        disassembler = Disassembler(SmdaConfig())
        # samples arrive as files on disk; the unmapped path handles PE/ELF headers, and
        # falls back to a raw buffer interpretation when there is no recognisable header
        report = disassembler.disassembleUnmappedBuffer(content)
        report.filename = os.path.basename(path)
        report.family = family
        report.sha256 = sha256
        as_dict = report.toDict()
        tmp_path = out_path + ".tmp%d" % os.getpid()
        with gzip.open(tmp_path, "wt", compresslevel=6) as outfile:
            json.dump(as_dict, outfile)
        os.replace(tmp_path, out_path)  # readers never see a half-written report
        return ("ok", path, time.time() - started, len(as_dict.get("xcfg", {})))
    except Exception as error:
        return ("fail:%s" % type(error).__name__, path, 0.0, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--in", dest="input_dir", required=True)
    parser.add_argument("--out", dest="out_dir", required=True)
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    samples = find_samples(args.input_dir)
    if args.limit:
        samples = samples[: args.limit]
    print("disassembling %d samples with %d workers" % (len(samples), args.workers), flush=True)

    tasks = [(family, path, args.out_dir) for family, path in samples]
    counters = {"ok": 0, "cached": 0, "fail": 0, "functions": 0}
    started = time.time()
    with Pool(args.workers) as pool:
        for index, (status, path, duration, num_functions) in enumerate(pool.imap_unordered(disassemble_one, tasks, chunksize=1), start=1):
            if status == "ok":
                counters["ok"] += 1
                counters["functions"] += num_functions
            elif status == "cached":
                counters["cached"] += 1
            else:
                counters["fail"] += 1
                print("FAIL %s %s" % (status, path), file=sys.stderr, flush=True)
            if index % 50 == 0:
                elapsed = time.time() - started
                print(
                    "%d/%d  ok=%d cached=%d fail=%d  %d functions  %.2f samples/s"
                    % (index, len(tasks), counters["ok"], counters["cached"], counters["fail"], counters["functions"], index / max(1e-9, elapsed)),
                    flush=True,
                )
    print("done in %.0f s: %s" % (time.time() - started, counters), flush=True)


if __name__ == "__main__":
    main()
