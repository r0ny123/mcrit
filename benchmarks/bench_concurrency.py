#!/usr/bin/env python3
"""Concurrency benchmark for MCRIT 1-vs-N matching: throughput, latency percentiles, memory.

Every latency in `docs/scaling/SUMMARY.md` was measured one query at a time, which answers
"how long does a query take" and says nothing about "how many queries a minute can this
deployment serve". Those are different questions with different answers, because the second
one is decided by whatever runs out first - cores, mongod's read tickets, or RAM - and none of
those appear in a serial measurement.

This harness runs N matching jobs at once and reports, per concurrency level:

    requests/sec, latency p50/p90/p95/p99/max, peak client RSS, peak mongod RSS,
    CPU-seconds split between the clients and the rest of the machine, and mongod's
    WiredTiger read-ticket queueing

The CPU split also polices the measurement. Machine-wide busy CPU minus the workers' own
CPU minus mongod's is CPU that belonged to something else entirely, and a throughput number
measured while something else was running is not a measurement of this software. Every level
records that share as `foreign_cpu_fraction`, so a contaminated level is visible in the JSON
rather than merely suspected afterwards.

The results this harness produced, the raw JSON it wrote and the write-up of both live on the
`research/scaling-notes` branch, under `docs/scaling/`.

How concurrency is realised, and why
------------------------------------
A production MCRIT worker is `SpawningWorker`: it polls the queue, and for each job it spawns
`python -m mcrit singlejobworker`, waits for that child to exit, and only then claims the next
job. One worker therefore runs exactly one matching job at a time, in its own OS process. A
deployment that wants to serve several queries at once runs several worker processes.

So the unit of concurrency in MCRIT is an OS process, not a thread, and this harness reproduces
that: each level runs C independent processes, started with the "spawn" method, each holding its
own `MinHashIndex`, its own storage object and its own pymongo pool. No GIL is shared between
them, exactly as in a real deployment.

Two things are deliberately left out of the measured window, and both are constants that do not
depend on the corpus or on the matching configuration:

  * the REST hop and the queue round trip (submit, poll, result fetch through GridFS), and
  * the per-job interpreter start-up that `SpawningWorker` pays, since the harness keeps each
    worker process alive for the whole level instead of spawning one per request.

Including them would add the same fixed cost to both configurations while making the run several
times longer, and it would put job and result documents in the way of the read-only guarantee
below. `--measure-spawn-cost` reports that constant separately so it can be added back by anyone
who wants a whole-system number rather than a matching number.

Read-only, and proven so rather than asserted
---------------------------------------------
The corpus this runs against is shared and must not be modified. The matching path was audited
for writes first - every storage method it reaches (`getFunctionsBySampleId`, `getSampleById`,
`getPicHashMatchesBySampleId`, `getCandidateArraysForMinHashes`, `getSampleFunctionCounts`,
`createMatchingCache`, `getSampleEntriesByIds`) only reads, and the matching cache is retained in
the matcher's own memory rather than persisted - but an audit is an argument, not evidence.

So the harness measures it. Before and after every run it records, for the storage database:
per-collection document counts, `dbstats`, and mongod's own per-namespace `top` counters, which
attribute inserts, updates and removes to the exact collection that received them. A run that
changed anything fails loudly and the JSON says so. The queue database is a scratch name of its
own (`--queue-db`), never derived from the storage database, and the queue itself is the fake
in-process one, so no job documents are written anywhere.

One thing the audit predicted and the proof then found, which is worth stating rather than
quietly excusing: `_ensureIndexAndUnknownFamily` runs on every storage construction, and it
issues write *commands* - `create_index`, plus `$max` upserts on `counters` and `$setOnInsert`
on `families`. On a populated database each one matches an existing document and modifies
nothing, but `top` counts the command regardless, so a run comes back with a handful of
`update` counts against `real.counters` and `real.families`.

Waving that away as "idempotent, so it is fine" would be an argument again, so instead those
three small collections (`counters`, `families`, `settings`) are hashed whole at each end of the
run. A write command against them with an unchanged digest is recorded as a no-op and named as
such in the JSON; a changed digest, or any write command at all against any other collection,
is a violation and fails the run.

Usage:
    python benchmarks/bench_concurrency.py --db real --queue-db wt_qps_queue \\
        --config two-stage --levels 1,2,4,8,16 --repeats 3 --json out.json
"""

import argparse
import hashlib
import json
import logging
import multiprocessing
import os
import resource
import statistics
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.WARNING)
for _name in ("mcrit", "mcrit.matchers.MatcherInterface", "mcrit.Worker", "mcrit.index.MinHashIndex"):
    logging.getLogger(_name).setLevel(logging.WARNING)

# The three query samples every earlier scaling point was measured on, addressed by sha256 so
# this comparison is against the same queries rather than against the same sample ids.
DEFAULT_QUERY_SHA256 = (
    "009363ee2a5f123ea22f1bdfd8db2193a78cff07674a2852c55f41cbe699e168",  # win.zloader, 557 functions
    "00c6e653558e41a9f0c83eb506195c72b46bce24c5458e58c33bc25b4566d468",  # win.blackpos, 650 functions
    "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9",  # win.acidbox, 158 functions
)

# The two configurations compared everywhere else in docs/scaling. "one-stage" is the upstream
# baseline with every bound disabled; "two-stage" is the shortlist configuration the headline
# result was measured with, knob for knob.
CONFIGURATIONS = {
    "one-stage": {},
    "two-stage": {
        "MINHASH_MATCHING_SHORTLIST_SIZE": 100,
        "STORAGE_BAND_DF_CUTOFF": 200,
        "MINHASH_PICHASH_MAX_MATCHES": 200,
    },
}

CLOCK_TICKS = os.sysconf("SC_CLK_TCK")

# The collections `_ensureIndexAndUnknownFamily` sends idempotent upserts at on every storage
# construction. They are small enough to hash whole, which is how the read-only proof tells a
# write command apart from a write.
BOOTSTRAP_COLLECTIONS = ("counters", "families", "settings")


def build_config(db_name: str, queue_db: str, mongo_host: str, mongo_port: str, overrides: Dict[str, Any]):
    """A McritConfig pointed at the corpus for storage and at a scratch database for the queue.

    The queue database is passed in rather than derived from the storage name on purpose: the
    obvious `db + "_queue"` would put a writable database next to a corpus that must not be
    touched, one typo away from writing into it.
    """
    from mcrit.config.McritConfig import McritConfig
    from mcrit.queue.QueueFactory import QueueFactory

    config = McritConfig()
    config.STORAGE_CONFIG.STORAGE_MONGODB_DBNAME = db_name
    config.STORAGE_CONFIG.STORAGE_SERVER = mongo_host
    config.STORAGE_CONFIG.STORAGE_PORT = mongo_port
    # One pool per worker process, and up to 16 worker processes: pymongo's default maxPoolSize
    # of 100 would let a single level open 1,600 sockets against a mongod whose container file
    # descriptor limit is the thing that takes the server down with a WiredTiger panic.
    config.STORAGE_CONFIG.STORAGE_MONGODB_FLAGS = "maxPoolSize=8"
    config.QUEUE_CONFIG.QUEUE_SERVER = mongo_host
    config.QUEUE_CONFIG.QUEUE_PORT = mongo_port
    config.QUEUE_CONFIG.QUEUE_MONGODB_DBNAME = queue_db
    config.QUEUE_CONFIG.QUEUE_METHOD = QueueFactory.QUEUE_METHOD_FAKE
    for key, value in overrides.items():
        for area in (config.STORAGE_CONFIG, config.MINHASH_CONFIG, config.SHINGLER_CONFIG, config.QUEUE_CONFIG):
            if hasattr(area, key):
                setattr(area, key, value)
                break
        else:
            raise KeyError("no config field named %s" % key)
    return config


# --------------------------------------------------------------------------------------- probes


def read_proc_stat_busy() -> float:
    """Machine-wide busy CPU-seconds (everything except idle and iowait)."""
    with open("/proc/stat") as infile:
        fields = infile.readline().split()
    values = [int(value) for value in fields[1:]]
    idle = values[3] + values[4] if len(values) > 4 else values[3]
    return (sum(values) - idle) / CLOCK_TICKS


def read_proc_rss_kb(pid: int) -> int:
    try:
        with open("/proc/%d/status" % pid) as infile:
            for line in infile:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return 0


def read_proc_cpu_seconds(pid: int) -> float:
    try:
        with open("/proc/%d/stat" % pid) as infile:
            fields = infile.read().rsplit(") ", 1)[1].split()
    except (OSError, IndexError):
        return 0.0
    # utime and stime are fields 14 and 15 of /proc/pid/stat, which are index 11 and 12 once
    # the pid and the (possibly space-carrying) comm have been split off
    return (int(fields[11]) + int(fields[12])) / CLOCK_TICKS


def read_mem_available_mb() -> float:
    with open("/proc/meminfo") as infile:
        for line in infile:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / 1024.0
    return float("inf")


def find_mongod_pid() -> Optional[int]:
    """The mongod serving this benchmark, if its process is visible on this host.

    It runs in a container here, but the container shares the host pid namespace, so /proc has
    it and its RSS and CPU time can be sampled directly. Absent that, the level records only the
    client side and says so by reporting zero.
    """
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/comm" % entry) as infile:
                if infile.read().strip() == "mongod":
                    return int(entry)
        except OSError:
            continue
    return None


def server_snapshot(client) -> Dict[str, Any]:
    status = client.admin.command("serverStatus")
    tickets = status.get("wiredTiger", {}).get("concurrentTransactions", {})
    return {
        "opcounters": dict(status["opcounters"]),
        "read_tickets_total": tickets.get("read", {}).get("totalTickets"),
        "write_tickets_total": tickets.get("write", {}).get("totalTickets"),
        "read_tickets_queued": tickets.get("read", {}).get("addedToQueue", 0),
        "read_time_queued_micros": tickets.get("read", {}).get("totalTimeQueuedMicros", 0),
        "write_tickets_queued": tickets.get("write", {}).get("addedToQueue", 0),
        "write_time_queued_micros": tickets.get("write", {}).get("totalTimeQueuedMicros", 0),
    }


def database_snapshot(client, db_name: str) -> Dict[str, Any]:
    """Everything needed to prove afterwards that the database did not change.

    Three independent witnesses, because no single one of them is sufficient:

      * per-collection counts, which catch an insert or a delete but not an update in place;
      * `dbstats` (`objects`, `dataSize`, `storageSize`, `indexSize`), where a byte-changing
        update shows up even though the counts hold still;
      * mongod's `top`, whose per-namespace `insert` / `update` / `remove` counters attribute a
        write to the exact collection that took it - which the server-wide `opcounters` cannot
        do, and which fires even for an update that happens to write the same bytes back.

    The counts come from the collection metadata rather than from `count_documents({})`. The
    exact form scans the `_id` index of every collection, which on this corpus is 28.7 million
    entries across 35 collections and takes minutes at each end of a run - and it would buy
    nothing, because `dbstats.objects` is already an exact total and `top` already catches what
    counting cannot see.

    A fourth witness covers the one place where `top` is known to fire without anything
    changing. `_ensureIndexAndUnknownFamily` runs on every storage construction and sends
    idempotent `$max` / `$setOnInsert` upserts at `counters` and `families`; on a populated
    database each of them matches an existing document and modifies nothing, but `top` counts
    the command all the same. Those three collections are small, so their entire contents are
    hashed here: that turns "mongod saw an update command" into the question that actually
    matters, which is whether any byte of them moved.
    """
    database = client[db_name]
    counts = {name: database[name].estimated_document_count() for name in sorted(database.list_collection_names())}
    stats = database.command("dbstats")
    totals = client.admin.command("top")["totals"]
    writes = {}
    for namespace, entry in totals.items():
        if not namespace.startswith(db_name + "."):
            continue
        writes[namespace] = {op: int(entry[op]["count"]) for op in ("insert", "update", "remove") if op in entry}
    digests = {}
    for name in BOOTSTRAP_COLLECTIONS:
        if name not in counts:
            continue
        documents = sorted(repr(sorted(document.items(), key=lambda item: item[0])) for document in database[name].find({}))
        digests[name] = hashlib.sha256("\n".join(documents).encode("utf-8")).hexdigest()
    return {
        "counts": counts,
        "dbstats": {key: stats[key] for key in ("collections", "objects", "dataSize", "storageSize", "indexSize") if key in stats},
        "top_writes": writes,
        "bootstrap_collection_digests": digests,
    }


def diff_read_only(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two database snapshots; `clean` is the assertion the run has to satisfy."""
    violations = []
    for name in sorted(set(before["counts"]) | set(after["counts"])):
        old, new = before["counts"].get(name), after["counts"].get(name)
        if old != new:
            violations.append("collection %s: %s -> %s documents" % (name, old, new))
    for key in sorted(set(before["dbstats"]) | set(after["dbstats"])):
        old, new = before["dbstats"].get(key), after["dbstats"].get(key)
        if old != new:
            violations.append("dbstats %s: %s -> %s" % (key, old, new))
    for name in sorted(set(before["bootstrap_collection_digests"]) | set(after["bootstrap_collection_digests"])):
        old = before["bootstrap_collection_digests"].get(name)
        new = after["bootstrap_collection_digests"].get(name)
        if old != new:
            violations.append("contents of %s changed (sha256 %s -> %s)" % (name, old, new))
    write_deltas = {}
    bootstrap_writes = {}
    for namespace in sorted(set(before["top_writes"]) | set(after["top_writes"])):
        old = before["top_writes"].get(namespace, {})
        new = after["top_writes"].get(namespace, {})
        delta = {op: new.get(op, 0) - old.get(op, 0) for op in ("insert", "update", "remove")}
        if not any(delta.values()):
            continue
        write_deltas[namespace] = delta
        collection = namespace.split(".", 1)[1]
        if collection in BOOTSTRAP_COLLECTIONS and not delta["insert"] and not delta["remove"]:
            # the storage constructor's idempotent upserts, whose no-op-ness is established by
            # the digest above rather than by this counter
            bootstrap_writes[namespace] = delta
        else:
            violations.append("top counters for %s: %s" % (namespace, delta))
    return {
        "clean": not violations,
        "violations": violations,
        "top_write_deltas": write_deltas,
        "bootstrap_no_op_writes": bootstrap_writes,
        "bootstrap_note": "update commands from _ensureIndexAndUnknownFamily; the digests show they changed nothing",
    }


# ------------------------------------------------------------------------------------- the worker


def worker_main(worker_index, settings, task_queue, result_queue, abort_flag):
    """One worker process: build the index once, then serve requests until the queue is drained.

    Mirrors what `singlejobworker` does per job, minus the process start-up, which is amortised
    over the level instead of paid per request (see the module docstring).
    """
    if settings["worktree"] and settings["worktree"] not in sys.path:
        sys.path.insert(0, settings["worktree"])
    logging.basicConfig(level=logging.WARNING)
    for name in ("mcrit", "mcrit.matchers.MatcherInterface", "mcrit.Worker", "mcrit.index.MinHashIndex"):
        logging.getLogger(name).setLevel(logging.WARNING)

    import mcrit
    from mcrit.index.MinHashIndex import MinHashIndex
    from mcrit.matchers.MatcherSample import MatcherSample

    config = build_config(settings["db"], settings["queue_db"], settings["mongo_host"], settings["mongo_port"], settings["overrides"])
    index = MinHashIndex(config=config)
    mcrit_worker = index.queue._worker

    # Announce readiness and then block on the task queue. The parent only enqueues work once
    # every worker has said this, so the measured window contains matching and nothing else -
    # no interpreter start-up, no index construction, no connection handshake, and no worker
    # sitting idle while its peers are still importing numpy.
    result_queue.put({"worker_ready": worker_index})
    served = 0
    failure = None
    try:
        served = _serve(worker_index, task_queue, result_queue, abort_flag, mcrit_worker, MatcherSample)
    except Exception as error:  # a worker that dies quietly leaves the parent waiting for a summary that never comes
        failure = "%s: %s" % (type(error).__name__, error)
    usage = resource.getrusage(resource.RUSAGE_SELF)
    result_queue.put(
        {
            "worker_summary": worker_index,
            "served": served,
            "failure": failure,
            "peak_rss_mb": usage.ru_maxrss / 1024.0,
            "cpu_seconds": usage.ru_utime + usage.ru_stime,
            "mcrit_from": os.path.dirname(os.path.dirname(os.path.abspath(mcrit.__file__))),
        }
    )


def _serve(worker_index, task_queue, result_queue, abort_flag, mcrit_worker, matcher_class) -> int:
    served = 0
    while True:
        # a blocking get against a queue carrying one sentinel per worker, rather than a
        # non-blocking one against a queue whose feeder thread may not have caught up yet:
        # get_nowait silently retires a worker early and understates the level
        task = task_queue.get()
        if task is None or abort_flag.value:
            break
        request_index, sample_id = task
        started = time.perf_counter()
        report = matcher_class(mcrit_worker).getMatchesForSample(sample_id)
        latency = time.perf_counter() - started
        served += 1
        result_queue.put(
            {
                "worker": worker_index,
                "request": request_index,
                "sample_id": sample_id,
                "latency_seconds": latency,
                "finished_at": time.perf_counter(),
                "num_matched_samples": len(report["matches"]["samples"]),
                "num_matched_functions": len(report["matches"]["functions"]),
            }
        )
    return served


# -------------------------------------------------------------------------------------- sampling


class ResourceSampler(threading.Thread):
    """Samples client RSS, mongod RSS and free memory while a level runs.

    It also enforces the memory guard. The one-stage baseline needs the better part of a
    gigabyte per concurrent query on this corpus, so a high concurrency level can genuinely
    exhaust the machine - and if it does, the OOM killer is as likely to take mongod as it is to
    take a worker. Aborting the level on our own terms turns that into a recorded result instead
    of a wrecked test environment.
    """

    def __init__(self, pids, mongod_pid, abort_flag, min_available_mb, interval=0.1):
        super().__init__(daemon=True)
        self._pids = list(pids)
        self._mongod_pid = mongod_pid
        self._abort_flag = abort_flag
        self._min_available_mb = min_available_mb
        self._interval = interval
        # not `_stop`: threading.Thread already owns that name (join() calls it), and shadowing
        # it makes the thread unjoinable in a way that only surfaces at the end of a level
        self._stop_event = threading.Event()
        self.peak_client_rss_mb = 0.0
        self.peak_mongod_rss_mb = 0.0
        self.min_available_mb = float("inf")
        self.samples = 0
        self.tripped_guard = False

    def run(self):
        while not self._stop_event.is_set():
            client_rss = sum(read_proc_rss_kb(pid) for pid in self._pids) / 1024.0
            self.peak_client_rss_mb = max(self.peak_client_rss_mb, client_rss)
            if self._mongod_pid:
                self.peak_mongod_rss_mb = max(self.peak_mongod_rss_mb, read_proc_rss_kb(self._mongod_pid) / 1024.0)
            available = read_mem_available_mb()
            self.min_available_mb = min(self.min_available_mb, available)
            self.samples += 1
            if available < self._min_available_mb:
                self.tripped_guard = True
                self._abort_flag.value = 1
            self._stop_event.wait(self._interval)

    def stop(self):
        self._stop_event.set()


def percentile(values: List[float], fraction: float) -> float:
    """Nearest-rank percentile; with few samples it is the honest one (no interpolation)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, min(len(ordered), int(round(fraction * len(ordered) + 0.5))))
    return ordered[rank - 1]


# ------------------------------------------------------------------------------------------ level


def run_level(context, settings, concurrency: int, sample_ids: List[int], requests_per_worker: int, mongod_pid, mongo_client, min_available_mb) -> Dict[str, Any]:
    # Rounded up to a whole number of passes over the query set. The queries differ in cost by a
    # factor of five here, so a level whose request count is not a multiple of the query count
    # runs a different *mix* from its neighbours, and its throughput then differs partly because
    # of the mix rather than because of the concurrency. Measured before this was enforced: at
    # concurrency 1 with 4 requests per worker the level ran 50% win.zloader against 25% each of
    # the other two, against even thirds at concurrency 16 - and concurrency 1 is the baseline
    # every speedup on the level is divided by.
    passes = -(-concurrency * requests_per_worker // len(sample_ids))
    total_requests = passes * len(sample_ids)
    task_queue = context.Queue()
    result_queue = context.Queue()
    abort_flag = context.Value("i", 0)

    processes = []
    for worker_index in range(concurrency):
        process = context.Process(target=worker_main, args=(worker_index, settings, task_queue, result_queue, abort_flag))
        process.start()
        processes.append(process)

    ready = 0
    while ready < concurrency:
        item = result_queue.get(timeout=600)
        if "worker_ready" not in item:
            raise RuntimeError("unexpected message while waiting for workers to come up: %r" % item)
        ready += 1

    # every worker has built its index and is blocked on the task queue; enqueueing the work is
    # what starts the level, so module import, index construction and connection set-up sit
    # outside the measured window for every level alike
    server_before = server_snapshot(mongo_client)
    busy_before = read_proc_stat_busy()
    mongod_cpu_before = read_proc_cpu_seconds(mongod_pid) if mongod_pid else 0.0
    sampler = ResourceSampler([process.pid for process in processes], mongod_pid, abort_flag, min_available_mb)
    sampler.start()
    started = time.perf_counter()
    for request_index in range(total_requests):
        # round-robin over the query set, so every level runs the same mix of query sizes and a
        # level's throughput is not an accident of which query happened to land on it
        task_queue.put((request_index, sample_ids[request_index % len(sample_ids)]))
    for _ in range(concurrency):
        task_queue.put(None)

    records: List[Dict[str, Any]] = []
    summaries: List[Dict[str, Any]] = []
    lost_workers = 0
    while len(summaries) + lost_workers < concurrency:
        try:
            item = result_queue.get(timeout=120)
        except Exception:
            # A worker killed outright - by the OOM killer, most plausibly, which is exactly the
            # regime the high one-stage levels are here to probe - never sends its summary, and
            # waiting on a queue for it would hang the whole run rather than report the fact.
            if all(not process.is_alive() for process in processes):
                lost_workers = concurrency - len(summaries)
                break
            continue
        if "worker_summary" in item:
            summaries.append(item)
        else:
            records.append(item)
    wall_seconds = time.perf_counter() - started

    sampler.stop()
    sampler.join(timeout=5)
    busy_after = read_proc_stat_busy()
    mongod_cpu_after = read_proc_cpu_seconds(mongod_pid) if mongod_pid else 0.0
    server_after = server_snapshot(mongo_client)
    for process in processes:
        process.join(timeout=60)

    latencies = [record["latency_seconds"] for record in records]
    client_cpu = sum(summary["cpu_seconds"] for summary in summaries)
    machine_cpu = busy_after - busy_before
    mongod_cpu = mongod_cpu_after - mongod_cpu_before
    return {
        "concurrency": concurrency,
        "requests_issued": total_requests,
        "requests_completed": len(records),
        "aborted_low_memory": bool(sampler.tripped_guard),
        "lost_workers": lost_workers,
        "worker_failures": [summary["failure"] for summary in summaries if summary.get("failure")],
        "mcrit_loaded_from": sorted({summary["mcrit_from"] for summary in summaries}),
        "wall_seconds": wall_seconds,
        "requests_per_second": len(records) / wall_seconds if wall_seconds else 0.0,
        "latency_mean": statistics.fmean(latencies) if latencies else 0.0,
        "latency_p50": percentile(latencies, 0.50),
        "latency_p90": percentile(latencies, 0.90),
        "latency_p95": percentile(latencies, 0.95),
        "latency_p99": percentile(latencies, 0.99),
        "latency_max": max(latencies) if latencies else 0.0,
        "peak_client_rss_mb": sampler.peak_client_rss_mb,
        "peak_rss_per_worker_mb": max((summary["peak_rss_mb"] for summary in summaries), default=0.0),
        "peak_mongod_rss_mb": sampler.peak_mongod_rss_mb,
        "min_mem_available_mb": sampler.min_available_mb if sampler.samples else 0.0,
        "client_cpu_seconds": client_cpu,
        "mongod_cpu_seconds": mongod_cpu,
        "machine_busy_cpu_seconds": machine_cpu,
        "cpu_cores_busy": machine_cpu / wall_seconds if wall_seconds else 0.0,
        # whatever burned CPU that was neither a worker of ours nor mongod. On a dedicated box
        # this is kernel noise in the low percent; anything more means something else was
        # running and the level's throughput is not a measurement of this software. Recording
        # it makes a contaminated level visible in the JSON instead of merely suspicious.
        "foreign_cpu_seconds": max(0.0, machine_cpu - client_cpu - mongod_cpu),
        "foreign_cpu_fraction": max(0.0, machine_cpu - client_cpu - mongod_cpu) / machine_cpu if machine_cpu > 0 else 0.0,
        "read_tickets_total": server_after["read_tickets_total"],
        "read_tickets_queued": server_after["read_tickets_queued"] - server_before["read_tickets_queued"],
        "read_queued_seconds": (server_after["read_time_queued_micros"] - server_before["read_time_queued_micros"]) / 1e6,
        "write_tickets_queued": server_after["write_tickets_queued"] - server_before["write_tickets_queued"],
        "opcounter_deltas": {key: server_after["opcounters"][key] - server_before["opcounters"][key] for key in server_after["opcounters"]},
        "requests": records,
    }


def measure_spawn_cost(repeats: int = 3) -> Dict[str, Any]:
    """The per-job constant a real SpawningWorker pays and this harness does not.

    `singlejobworker` is a fresh interpreter that imports mcrit (and numpy, and smda) before it
    touches the corpus. Timing that import alone puts a floor under the overhead the measured
    window excludes, so a whole-system figure can be reconstructed from a matching figure.
    """
    durations = []
    for _ in range(repeats):
        started = time.perf_counter()
        subprocess.run([sys.executable, "-c", "import mcrit.Worker, mcrit.matchers.MatcherSample"], check=True)
        durations.append(time.perf_counter() - started)
    return {"repeats": repeats, "median_seconds": statistics.median(durations), "seconds": durations}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", required=True, help="storage database; read-only, and the run proves it")
    parser.add_argument("--queue-db", default="wt_qps_queue", help="scratch queue database - never derive this from --db")
    parser.add_argument("--mongo-host", default=os.environ.get("TEST_MONGODB", "127.0.0.1"))
    parser.add_argument("--mongo-port", default="27017")
    parser.add_argument("--config", default="two-stage", choices=sorted(CONFIGURATIONS), help="which of the two documented configurations to measure")
    parser.add_argument("--levels", default="1,2,4,8,16", help="comma-separated concurrency levels")
    parser.add_argument("--repeats", type=int, default=3, help="repeats per level; the spread across them is the reported variance")
    parser.add_argument(
        "--requests-per-worker",
        type=int,
        default=6,
        help="requests each worker serves in a repeat; the level total is this x the level, rounded up to whole passes over the query set",
    )
    parser.add_argument("--query-sha256", default=",".join(DEFAULT_QUERY_SHA256), help="comma-separated query samples, by sha256")
    parser.add_argument("--min-available-mb", type=float, default=2000.0, help="abort a level if free memory falls below this, rather than letting the OOM killer choose")
    parser.add_argument("--warmup-requests", type=int, default=3, help="serial requests run and discarded before the first level")
    parser.add_argument("--measure-spawn-cost", action="store_true", help="also time a bare interpreter start-up plus mcrit import")
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    from pymongo import MongoClient

    worktree = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if worktree not in sys.path:
        sys.path.insert(0, worktree)
    import mcrit

    mcrit_root = os.path.dirname(os.path.dirname(os.path.abspath(mcrit.__file__)))
    if mcrit_root != worktree:
        raise SystemExit("mcrit resolves to %s, not to this checkout (%s); run with PYTHONPATH=%s" % (mcrit_root, worktree, worktree))

    mongo_client = MongoClient("mongodb://%s:%s/?maxPoolSize=4" % (args.mongo_host, args.mongo_port))
    if args.queue_db.startswith(args.db):
        raise SystemExit("--queue-db %r is derived from the storage database %r; give it an unrelated scratch name" % (args.queue_db, args.db))

    overrides = CONFIGURATIONS[args.config]
    settings = {
        "db": args.db,
        "queue_db": args.queue_db,
        "mongo_host": args.mongo_host,
        "mongo_port": args.mongo_port,
        "overrides": overrides,
        "worktree": worktree,
    }

    database = mongo_client[args.db]
    by_sha256 = {}
    for sha256 in [value.strip() for value in args.query_sha256.split(",") if value.strip()]:
        document = database.samples.find_one({"sha256": sha256}, {"sample_id": 1, "family": 1, "statistics": 1})
        if document is None:
            raise SystemExit("sha256 %s is not in corpus %r" % (sha256, args.db))
        by_sha256[sha256] = document
    sample_ids = [document["sample_id"] for document in by_sha256.values()]
    num_corpus_samples = database.samples.count_documents({})

    mongod_pid = find_mongod_pid()
    context = multiprocessing.get_context("spawn")

    print("corpus %r: %d samples; querying %s" % (args.db, num_corpus_samples, [(d["family"], d["sample_id"]) for d in by_sha256.values()]), flush=True)
    print("configuration %r: %s" % (args.config, overrides or "defaults (every bound disabled)"), flush=True)
    print("mongod pid %s, %d cores, %.0f MB available" % (mongod_pid, os.cpu_count() or 0, read_mem_available_mb()), flush=True)

    before = database_snapshot(mongo_client, args.db)
    print(
        "recorded the read-only baseline: %d collections, %d objects, %d bytes of data"
        % (before["dbstats"]["collections"], before["dbstats"]["objects"], before["dbstats"]["dataSize"]),
        flush=True,
    )

    if args.warmup_requests:
        print("warm-up: %d serial requests (discarded)" % args.warmup_requests, flush=True)
        run_level(context, settings, 1, sample_ids, args.warmup_requests, mongod_pid, mongo_client, args.min_available_mb)

    levels = [int(value) for value in args.levels.split(",") if value.strip()]
    results: List[Dict[str, Any]] = []
    for concurrency in levels:
        repeats: List[Dict[str, Any]] = []
        for repeat_index in range(args.repeats):
            outcome = run_level(context, settings, concurrency, sample_ids, args.requests_per_worker, mongod_pid, mongo_client, args.min_available_mb)
            outcome["repeat"] = repeat_index
            repeats.append(outcome)
            print(
                "c=%-3d repeat %d: %5.3f req/s  p50 %6.2f s  p95 %6.2f s  max %6.2f s  client RSS %5.0f MB  mongod RSS %5.0f MB  %.2f cores busy%s"
                % (
                    concurrency,
                    repeat_index,
                    outcome["requests_per_second"],
                    outcome["latency_p50"],
                    outcome["latency_p95"],
                    outcome["latency_max"],
                    outcome["peak_client_rss_mb"],
                    outcome["peak_mongod_rss_mb"],
                    outcome["cpu_cores_busy"],
                    ("  ABORTED (low memory)" if outcome["aborted_low_memory"] else "")
                    + ("  CONTAMINATED (%.0f%% foreign CPU)" % (100 * outcome["foreign_cpu_fraction"]) if outcome["foreign_cpu_fraction"] > 0.05 else ""),
                ),
                flush=True,
            )
            if outcome["worker_failures"]:
                print("  worker failures: %s" % outcome["worker_failures"], flush=True)
            if outcome["lost_workers"]:
                print("  %d workers died without reporting (OOM kill is the likely cause)" % outcome["lost_workers"], flush=True)
            if outcome["mcrit_loaded_from"] and outcome["mcrit_loaded_from"] != [os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]:
                raise SystemExit("workers imported mcrit from %s, not from this checkout" % outcome["mcrit_loaded_from"])
            if outcome["aborted_low_memory"] or outcome["lost_workers"]:
                break
        throughputs = [repeat["requests_per_second"] for repeat in repeats]
        pooled = [record["latency_seconds"] for repeat in repeats for record in repeat["requests"]]
        results.append(
            {
                "concurrency": concurrency,
                "repeats": repeats,
                "requests_per_second_median": statistics.median(throughputs),
                "requests_per_second_min": min(throughputs),
                "requests_per_second_max": max(throughputs),
                "requests_per_second_stdev": statistics.stdev(throughputs) if len(throughputs) > 1 else 0.0,
                "pooled_requests": len(pooled),
                "pooled_latency_p50": percentile(pooled, 0.50),
                "pooled_latency_p90": percentile(pooled, 0.90),
                "pooled_latency_p95": percentile(pooled, 0.95),
                "pooled_latency_p99": percentile(pooled, 0.99),
                "pooled_latency_max": max(pooled) if pooled else 0.0,
                "peak_client_rss_mb": max(repeat["peak_client_rss_mb"] for repeat in repeats),
                "peak_mongod_rss_mb": max(repeat["peak_mongod_rss_mb"] for repeat in repeats),
                "min_mem_available_mb": min(repeat["min_mem_available_mb"] for repeat in repeats),
                "cpu_cores_busy_median": statistics.median([repeat["cpu_cores_busy"] for repeat in repeats]),
                "client_cpu_seconds_total": sum(repeat["client_cpu_seconds"] for repeat in repeats),
                "mongod_cpu_seconds_total": sum(repeat["mongod_cpu_seconds"] for repeat in repeats),
                "foreign_cpu_fraction_max": max(repeat["foreign_cpu_fraction"] for repeat in repeats),
                "read_queued_seconds_total": sum(repeat["read_queued_seconds"] for repeat in repeats),
                "read_tickets_queued_total": sum(repeat["read_tickets_queued"] for repeat in repeats),
                "aborted_low_memory": any(repeat["aborted_low_memory"] for repeat in repeats),
                "lost_workers": sum(repeat["lost_workers"] for repeat in repeats),
                "worker_failures": [failure for repeat in repeats for failure in repeat["worker_failures"]],
            }
        )

    after = database_snapshot(mongo_client, args.db)
    read_only = diff_read_only(before, after)

    summary: Dict[str, Any] = {
        "db": args.db,
        "queue_db": args.queue_db,
        "configuration": args.config,
        "config_overrides": overrides,
        "num_corpus_samples": num_corpus_samples,
        "queries": [
            {"sha256": sha256, "sample_id": d["sample_id"], "family": d["family"], "num_query_functions": d.get("statistics", {}).get("num_functions", 0)}
            for sha256, d in by_sha256.items()
        ],
        "machine": {
            "cores": os.cpu_count(),
            "mem_total_mb": round(_mem_total_mb(), 1),
            "mongod_pid": mongod_pid,
            "mongod_read_tickets": server_snapshot(mongo_client)["read_tickets_total"],
            "wiredtiger_cache_gb": round(mongo_client.admin.command("serverStatus")["wiredTiger"]["cache"]["maximum bytes configured"] / 2**30, 2),
        },
        "concurrency_model": "one OS process per concurrent query (spawn), mirroring SpawningWorker/singlejobworker; REST and queue hops excluded",
        "requests_per_worker": args.requests_per_worker,
        "repeats_per_level": args.repeats,
        "warmup_requests": args.warmup_requests,
        "levels": results,
        "read_only_check": {"before": before, "after": after, "result": read_only},
    }
    if args.measure_spawn_cost:
        summary["spawn_cost"] = measure_spawn_cost()

    print("\nread-only check on %r: %s" % (args.db, "CLEAN" if read_only["clean"] else "VIOLATED"), flush=True)
    for violation in read_only["violations"]:
        print("  ! %s" % violation, flush=True)
    for namespace, delta in read_only["bootstrap_no_op_writes"].items():
        print("  (no-op bootstrap write commands at %s: %s; contents unchanged)" % (namespace, delta), flush=True)

    if args.json:
        with open(args.json, "w") as outfile:
            json.dump(summary, outfile, indent=2)
        print("wrote %s" % args.json, flush=True)
    if not read_only["clean"]:
        raise SystemExit("the run modified %r" % args.db)


def _mem_total_mb() -> float:
    with open("/proc/meminfo") as infile:
        return int(infile.readline().split()[1]) / 1024.0


if __name__ == "__main__":
    main()
