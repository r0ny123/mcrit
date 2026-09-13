#!/usr/bin/env python3
"""Delete sample files whose SMDA report already exists, to keep a corpus build within disk.

Disassembly is the expensive, irreversible-in-practice step; the raw sample is only needed to
produce the report. On a constrained host the samples are the larger half of the corpus (5 GB
of samples against 0.7 GB of reports on this one), so once a sample's report is cached the file
can go. The `.done` markers are left alone, so a resumed fetch does not re-download what it
already has.

Reports are named by the sha256 of the file *content*, which is what this re-computes - a
sample is only deleted when its own content hashes to a report that exists.

Usage:
    python benchmarks/prune_disassembled.py --samples data/malpedia_api --reports data/reports [--apply]
"""

import argparse
import hashlib
import os


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--samples", required=True)
    parser.add_argument("--reports", required=True)
    parser.add_argument("--apply", action="store_true", help="actually delete (default: report only)")
    args = parser.parse_args()

    reports = {name[: -len(".smda.gz")] for name in os.listdir(args.reports) if name.endswith(".smda.gz")}
    print("%d cached reports" % len(reports), flush=True)
    freed = 0
    deleted = 0
    kept = 0
    for dirpath, _dirnames, filenames in os.walk(args.samples):
        for filename in filenames:
            if filename.endswith(".done"):
                continue
            path = os.path.join(dirpath, filename)
            try:
                size = os.path.getsize(path)
                with open(path, "rb") as infile:
                    digest = hashlib.sha256(infile.read()).hexdigest()
            except OSError:
                continue
            if digest in reports:
                if args.apply:
                    try:
                        os.remove(path)
                    except OSError:
                        continue
                freed += size
                deleted += 1
            else:
                kept += 1
    print("%s %d samples (%.2f GB), kept %d not yet disassembled" % ("deleted" if args.apply else "would delete", deleted, freed / 1e9, kept), flush=True)


if __name__ == "__main__":
    main()
