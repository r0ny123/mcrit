#!/usr/bin/env python3
"""Benchmark harness for MCRIT 1-vs-N matching.

Two subcommands:

    index  - load cached SMDA reports into a MongoDB-backed index, hashing as it goes
    match  - run 1-vs-N matching for one or more query samples and report per-stage timings

The point of the harness is the *per-stage* breakdown. Total wall time tells you the query
got slower; it does not tell you which of the five stages that scale with corpus size did
it (pichash lookup, band candidate generation, matching-cache fetch, pairwise scoring,
result assembly), and those have completely different fixes. Stages are timed by wrapping
the methods at runtime, so the production code carries no benchmark hooks.

Usage:
    python benchmarks/bench_matching.py index --reports data/reports --db bench_1k --limit 1000
    python benchmarks/bench_matching.py match --db bench_1k --queries 5 --json out.json
"""

import argparse
import gzip
import json

# quiet the very chatty INFO logging of the matching path; it dominates a timed run
import logging
import os
import random
import resource
import statistics
import sys
import time
from collections import OrderedDict
from typing import Any, Dict

logging.basicConfig(level=logging.WARNING)
for name in ("mcrit", "mcrit.matchers.MatcherInterface", "mcrit.Worker", "mcrit.index.MinHashIndex"):
    logging.getLogger(name).setLevel(logging.WARNING)


def make_config(db_name, mongo_host="127.0.0.1", mongo_port="27017", overrides=None):
    from mcrit.config.McritConfig import McritConfig

    config = McritConfig()
    config.STORAGE_CONFIG.STORAGE_MONGODB_DBNAME = db_name
    config.STORAGE_CONFIG.STORAGE_SERVER = mongo_host
    config.STORAGE_CONFIG.STORAGE_PORT = mongo_port
    # The harness builds a fresh index (and therefore a fresh connection pool) per measured
    # run, so pymongo's default maxPoolSize of 100 multiplies quickly. mongod answers a file
    # descriptor it cannot get by aborting the whole server with a WiredTiger panic (errno 24),
    # which looks like data loss rather than a benchmark harness holding too many sockets -
    # so the pools are kept small here.
    config.STORAGE_CONFIG.STORAGE_MONGODB_FLAGS = "maxPoolSize=8"
    config.QUEUE_CONFIG.QUEUE_SERVER = mongo_host
    config.QUEUE_CONFIG.QUEUE_PORT = mongo_port
    config.QUEUE_CONFIG.QUEUE_MONGODB_DBNAME = db_name + "_queue"
    # the harness drives Worker methods directly, so the queue only has to hand one back:
    # the fake queue runs remote calls in-process, which is also what the tests do
    from mcrit.queue.QueueFactory import QueueFactory

    config.QUEUE_CONFIG.QUEUE_METHOD = QueueFactory.QUEUE_METHOD_FAKE
    for key, value in (overrides or {}).items():
        for area in (config.STORAGE_CONFIG, config.MINHASH_CONFIG, config.SHINGLER_CONFIG, config.QUEUE_CONFIG):
            if hasattr(area, key):
                setattr(area, key, value)
                break
        else:
            raise KeyError("no config field named %s" % key)
    return config


def load_report(path):
    from smda.common.SmdaReport import SmdaReport

    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt") as infile:
        return SmdaReport.fromDict(json.load(infile))


def iter_report_paths(reports_dir, limit=0):
    paths = sorted(os.path.join(reports_dir, name) for name in os.listdir(reports_dir) if name.endswith((".smda.gz", ".smda")))
    return paths[:limit] if limit else paths


def cmd_index(args):
    from smda.SmdaConfig import SmdaConfig

    from mcrit.index.MinHashIndex import MinHashIndex

    config = make_config(args.db, args.mongo_host, args.mongo_port)
    if getattr(args, "drop_disassembly", False):
        config.STORAGE_CONFIG.STORAGE_DROP_DISASSEMBLY = True
    index = MinHashIndex(config=config)
    worker = index.queue._worker
    storage = index._storage

    if getattr(args, "hash_only", False):
        # Resume path. An interrupted index leaves every report added but only some functions
        # hashed; re-running the whole command re-parses thousands of gzipped reports purely to
        # rediscover that they are already present, which costs far more than the hashing left
        # to do. updateMinHashes(None) picks up exactly the unhashed backlog.
        print("hashing the unhashed backlog in db '%s'" % args.db, flush=True)
        started = time.time()
        worker.updateMinHashes(None)
        print("hashed backlog in %.1f s" % (time.time() - started), flush=True)
        if getattr(args, "drop_disassembly", False):
            # the resume path has to drop disassembly too, or an index interrupted before its
            # drop keeps the xcfg forever - measured at 2.5 GB of a 3.55 GB corpus, 71% of it,
            # for data the matching path never reads
            sample_ids = [sample.sample_id for sample in storage.getSamples(start_index=0, limit=0)]
            for sample_id in sample_ids:
                storage.deleteXcfgForSampleId(sample_id)
            print("dropped disassembly for %d samples" % len(sample_ids), flush=True)
        print(json.dumps(index.getStatus(), indent=2), flush=True)
        return

    paths = iter_report_paths(args.reports, args.limit)
    print("indexing %d reports into db '%s' in chunks of %d" % (len(paths), args.db, args.chunk_size), flush=True)
    started = time.time()
    num_functions = 0
    num_indexed = 0

    # Add, hash, then drop disassembly - per chunk, not once for the whole corpus.
    #
    # Two phases (add everything, then hash everything) amortises the hashing process pool,
    # which is why it exists: per-sample hashing spawns a pool per sample and measured 3.1 s a
    # sample. But it also means the xcfg of every sample in the run is resident at once, and
    # xcfg is ~70% of the stored bytes - measured 4.28 GB for 3.3M functions here, on a host
    # with 8 GB free. Chunking keeps the pool amortised over the chunk while bounding peak disk
    # to one chunk's disassembly.
    #
    # The disassembly cannot simply be skipped: it is the *input* to minhash computation
    # (Worker.calculateMinHashes reads FunctionEntry.xcfg), not merely retrievable detail.
    # Dropping it before hashing silently leaves functions unhashable - which is exactly what
    # happened on this corpus, leaving 3.97M of 5.2M functions with neither xcfg nor a minhash.
    for chunk_start in range(0, len(paths), args.chunk_size):
        chunk_paths = paths[chunk_start : chunk_start + args.chunk_size]
        chunk_sample_ids = []
        for path in chunk_paths:
            try:
                # The report file is named for the sha256 of the sample it describes, and that
                # is exactly what addSmdaReport dedupes on - so an already-indexed sample can be
                # skipped without gunzipping and parsing a report only to throw it away. This is
                # the whole cost of resuming: a restart part-way through a 7,803-report corpus
                # otherwise re-parses every report it already has.
                sha256 = os.path.basename(path).split(".")[0]
                if len(sha256) == 64 and storage.getSampleBySha256(sha256) is not None:
                    continue
                report = load_report(path)
                # SMDA writes a report even when it recovered no functions (packed, .NET, or a
                # format it cannot read); such a report has no statistics to count.
                if not report.num_functions:
                    continue
                sample_entry = storage.addSmdaReport(report)
                if sample_entry is None:  # already present
                    continue
                chunk_sample_ids.append(sample_entry.sample_id)
                num_functions += sample_entry.statistics.get("num_functions", 0)
                num_indexed += 1
            except Exception as error:
                print("FAIL %s: %s: %s" % (path, type(error).__name__, error), file=sys.stderr, flush=True)
        if chunk_sample_ids:
            worker.updateMinHashes(None)
            storage.setMinHashVersionForSamples(SmdaConfig().VERSION, chunk_sample_ids)
            if args.drop_disassembly:
                for sample_id in chunk_sample_ids:
                    storage.deleteXcfgForSampleId(sample_id)
        elapsed = time.time() - started
        print(
            "%d/%d reports  %d samples  %d functions  %.2f samples/s"
            % (min(chunk_start + args.chunk_size, len(paths)), len(paths), num_indexed, num_functions, num_indexed / max(1e-9, elapsed)),
            flush=True,
        )
    print("indexed %d samples / %d functions in %.1f s" % (num_indexed, num_functions, time.time() - started), flush=True)
    print(json.dumps(index.getStatus(), indent=2), flush=True)


class StageTimer:
    """Wraps methods in place and accumulates (calls, seconds) per label."""

    def __init__(self):
        self.stages = OrderedDict()
        self._undo = []

    def wrap(self, owner, method_name, label, observer=None):
        original = getattr(owner, method_name)
        self.stages.setdefault(label, {"calls": 0, "seconds": 0.0, "observed": {}})

        def wrapper(*args, **kwargs):
            started = time.perf_counter()
            try:
                return_value = original(*args, **kwargs)
            finally:
                duration = time.perf_counter() - started
                entry = self.stages[label]
                entry["calls"] += 1
                entry["seconds"] += duration
            if observer is not None:
                observer(self.stages[label]["observed"], return_value)
            return return_value

        setattr(owner, method_name, wrapper)
        self._undo.append((owner, method_name, original))

    def restore(self):
        for owner, method_name, original in reversed(self._undo):
            setattr(owner, method_name, original)
        self._undo = []


def _observe_candidates(observed, candidate_groups):
    """Candidate-group shape is the quantity that explains 1-vs-N cost growth."""
    sizes = [len(candidates) for candidates in candidate_groups.values()]
    observed["query_functions_with_candidates"] = observed.get("query_functions_with_candidates", 0) + len(sizes)
    observed["candidate_pairs"] = observed.get("candidate_pairs", 0) + sum(sizes)
    observed["widest_group"] = max(observed.get("widest_group", 0), max(sizes) if sizes else 0)


def _observe_pichash(observed, pichash_matches):
    observed["pichashes_with_matches"] = observed.get("pichashes_with_matches", 0) + len(pichash_matches)
    observed["pichash_match_tuples"] = observed.get("pichash_match_tuples", 0) + sum(len(value) for value in pichash_matches.values())


def cmd_match(args):
    from mcrit.index.MinHashIndex import MinHashIndex
    from mcrit.matchers.MatcherSample import MatcherSample

    overrides = json.loads(args.config_overrides) if args.config_overrides else {}
    config = make_config(args.db, args.mongo_host, args.mongo_port, overrides)
    index = MinHashIndex(config=config)
    worker = index.queue._worker
    storage = index._storage

    status = index.getStatus()
    num_samples = status["status"]["num_samples"]
    print("corpus: %d samples, %d functions, %d families" % (num_samples, status["status"]["num_functions"], status["status"]["num_families"]), flush=True)

    all_samples = storage.getSamples(start_index=0, limit=0)
    sample_ids = sorted(sample.sample_id for sample in all_samples)
    if args.query_sha256:
        # Sample ids are assigned per corpus, so the *same* sample has different ids in two
        # differently-sized corpora. Selecting by sha256 is what makes a scaling comparison
        # controlled across separately built databases rather than only within one.
        by_sha256 = {sample.sha256: sample.sample_id for sample in all_samples}
        queries = []
        for sha256 in args.query_sha256.split(","):
            sha256 = sha256.strip()
            if sha256 not in by_sha256:
                raise KeyError("sha256 %s is not in corpus '%s'" % (sha256, args.db))
            queries.append(by_sha256[sha256])
        print("resolved %d query sha256 to sample ids %s" % (len(queries), queries), flush=True)
    elif args.query_sample_ids:
        queries = [int(value) for value in args.query_sample_ids.split(",")]
    else:
        rng = random.Random(args.seed)
        queries = rng.sample(sample_ids, min(args.queries, len(sample_ids)))

    results = []
    for query_id in queries:
        timer = StageTimer()
        timer.wrap(storage, "getCandidatesForMinHashes", "band_candidate_lookup", _observe_candidates)
        timer.wrap(storage, "getCandidateArraysForMinHashes", "band_candidate_lookup", _observe_candidates)
        timer.wrap(storage, "getPicHashMatchesBySampleId", "pichash_lookup", _observe_pichash)
        timer.wrap(storage, "createMatchingCache", "matching_cache_fetch")
        timer.wrap(MatcherSample, "_performMinHashMatching", "minhash_scoring")
        timer.wrap(MatcherSample, "_craftResultDict", "result_assembly")
        # stage 1 of two-stage matching; a no-op (and untimed) when shortlisting is disabled
        timer.wrap(MatcherSample, "_computeSampleShortlist", "shortlist_stage1")
        timer.wrap(MatcherSample, "_restrictToShortlist", "shortlist_restrict")
        matcher = MatcherSample(worker)
        # Peak RSS, not just wall time. Upstream issue #69 is this same problem seen from the
        # memory side - workers reaching tens of GB on a 20M-function instance - and this
        # project's own tuning notes measured peak RSS correlating 0.98 with bytes fetched from
        # MongoDB. Bounding candidates should bound the peak, and that claim needs a number.
        # ru_maxrss is a process-wide high-water mark, so it is the peak observed up to and
        # including this query, not this query's own allocation.
        started = time.perf_counter()
        try:
            report = matcher.getMatchesForSample(query_id)
            total = time.perf_counter() - started
            peak_rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
            sample_info = report["info"]["sample"]
            record: Dict[str, Any] = {
                "sample_id": query_id,
                "sha256": sample_info.get("sha256"),
                "family": sample_info.get("family"),
                "num_query_functions": sample_info.get("statistics", {}).get("num_functions", 0),
                "total_seconds": total,
                "peak_rss_mb": peak_rss_mb,
                "num_matched_samples": len(report["matches"]["samples"]),
                "num_matched_functions": len(report["matches"]["functions"]),
                "stages": {label: dict(entry) for label, entry in timer.stages.items()},
            }
        finally:
            timer.restore()
        results.append(record)
        print(
            "sample %d (%s): %.3f s  peak RSS %.0f MB  %d query functions -> %d matched samples, %d matched functions"
            % (
                query_id,
                record["family"],
                record["total_seconds"],
                record["peak_rss_mb"],
                record["num_query_functions"],
                record["num_matched_samples"],
                record["num_matched_functions"],
            ),
            flush=True,
        )
        for label, entry in record["stages"].items():
            extra = "  " + json.dumps(entry["observed"]) if entry["observed"] else ""
            print("    %-24s %7.3f s  (%d calls)%s" % (label, entry["seconds"], entry["calls"], extra), flush=True)

    totals = [float(record["total_seconds"]) for record in results]
    summary = {
        "db": args.db,
        "num_corpus_samples": num_samples,
        "num_corpus_functions": status["status"]["num_functions"],
        "queries": results,
        "median_total_seconds": statistics.median(totals) if totals else 0.0,
        "mean_total_seconds": statistics.fmean(totals) if totals else 0.0,
        "max_total_seconds": max(totals) if totals else 0.0,
        "peak_rss_mb": max((float(record["peak_rss_mb"]) for record in results), default=0.0),
        "config_overrides": overrides,
    }
    print(
        "\nmedian %.3f s, mean %.3f s, max %.3f s over %d queries; peak RSS %.0f MB"
        % (summary["median_total_seconds"], summary["mean_total_seconds"], summary["max_total_seconds"], len(totals), summary["peak_rss_mb"]),
        flush=True,
    )
    if args.json:
        with open(args.json, "w") as outfile:
            json.dump(summary, outfile, indent=2)
        print("wrote %s" % args.json, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mongo-host", default=os.environ.get("TEST_MONGODB", "127.0.0.1"))
    parser.add_argument("--mongo-port", default="27017")
    subparsers = parser.add_subparsers(dest="command", required=True)

    index_parser = subparsers.add_parser("index")
    index_parser.add_argument("--reports", required=True)
    index_parser.add_argument("--db", required=True)
    index_parser.add_argument("--limit", type=int, default=0)
    index_parser.add_argument(
        "--chunk-size", type=int, default=500, help="samples added and hashed per chunk; bounds peak disk, since disassembly is only dropped after a chunk is hashed"
    )
    index_parser.add_argument("--hash-only", action="store_true", help="skip adding reports and just hash what is already stored (resume an interrupted index)")
    index_parser.add_argument(
        "--drop-disassembly",
        action="store_true",
        help="discard xcfg once minhashes exist (STORAGE_DROP_DISASSEMBLY). Matching never reads it, and it is ~66%% of the stored bytes",
    )
    index_parser.set_defaults(func=cmd_index)

    match_parser = subparsers.add_parser("match")
    match_parser.add_argument("--db", required=True)
    match_parser.add_argument("--queries", type=int, default=5)
    match_parser.add_argument("--query-sample-ids", default="", help="comma-separated ids, overrides --queries")
    match_parser.add_argument("--query-sha256", default="", help="comma-separated sha256, overrides both - the way to query the same samples across differently sized corpora")
    match_parser.add_argument("--seed", type=int, default=23)
    match_parser.add_argument("--json", default="")
    match_parser.add_argument("--config-overrides", default="", help="JSON of config field -> value")
    match_parser.set_defaults(func=cmd_match)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
