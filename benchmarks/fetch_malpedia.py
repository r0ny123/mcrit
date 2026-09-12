#!/usr/bin/env python3
"""Fetch the Malpedia corpus (unpacked/dumped samples) for scaling benchmarks.

Malpedia's API serves each sample as JSON carrying a base64-encoded, password-protected
zip ("infected"). The list endpoint gives family -> [{sha256, status, version}], and only
`unpacked` and `dumped` samples are useful here: `packed` ones would have SMDA disassemble
the packer stub rather than the malware, which is not the code we want to index.

Usage:
    python benchmarks/fetch_malpedia.py --token <apitoken> --out data/malpedia_api \
        [--status unpacked dumped] [--limit N] [--threads 8]

The token is read from MALPEDIA_API_TOKEN when --token is omitted, so it need not appear
in a shell history or a process listing.
"""

import argparse
import base64
import io
import json
import os
import sys
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

import requests

API = "https://malpedia.caad.fkie.fraunhofer.de/api"
ZIP_PASSWORD = b"infected"


def _session(token):
    session = requests.Session()
    session.headers["Authorization"] = "apitoken %s" % token
    return session


def list_samples(session, statuses, limiter=None, cache_path=None):
    """[(family, sha256, status, version)] for every sample in a wanted status.

    Cached on disk: this call is subject to the same quota as the downloads, so on a restart
    during a cooldown it would 429 and take the whole fetch down before a single sample was
    retried. The listing changes on Malpedia's release cadence, not ours.
    """
    listing = None
    if cache_path and os.path.exists(cache_path):
        try:
            with open(cache_path) as infile:
                listing = json.load(infile)
        except (OSError, ValueError):
            listing = None
    if listing is None:
        if limiter is not None:
            response = get_with_retry(session, "%s/list/samples" % API, limiter)
        else:
            response = session.get("%s/list/samples" % API, timeout=300)
            response.raise_for_status()
        listing = response.json()
        if cache_path:
            with open(cache_path, "w") as outfile:
                json.dump(listing, outfile)
    wanted = []
    for family, samples in listing.items():
        for sample in samples:
            if sample["status"] in statuses:
                wanted.append((family, sample["sha256"], sample["status"], sample.get("version", "")))
    return wanted


class RateLimiter:
    """Token bucket shared by every worker thread.

    Malpedia answers serial requests happily (measured ~1 req/s at 200) but returns 429 for
    concurrent bursts, so the fetch is paced globally rather than by thread count: eight
    threads at 8 req/s got 1378 failures against 136 successes, which is not a fetch.
    """

    def __init__(self, rate_per_second):
        self._min_interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._next_slot = 0.0

    def acquire(self):
        if not self._min_interval:
            return
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_slot - now)
            self._next_slot = max(now, self._next_slot) + self._min_interval
        if wait:
            time.sleep(wait)


def get_with_retry(session, url, limiter, attempts=9, timeout=90):
    """GET with the shared pacing and exponential backoff on 429/5xx."""
    last_error = None
    for attempt in range(attempts):
        limiter.acquire()
        try:
            response = session.get(url, timeout=timeout)
            if response.status_code == 429 or response.status_code >= 500:
                last_error = "HTTP %d" % response.status_code
                # the server is telling us the global pace is still too high; backing off
                # here (rather than failing the sample) is what keeps a long fetch intact
                time.sleep(min(120.0, 3.0 * (2**attempt)))
                continue
            response.raise_for_status()
            return response
        except requests.RequestException as error:
            last_error = error
            time.sleep(min(120.0, 3.0 * (2**attempt)))
    raise RuntimeError("giving up on %s after %d attempts: %s" % (url, attempts, last_error))


def fetch_one(session, out_dir, family, sha256, limiter):
    """Write every member of the sample's zip; returns how many files landed."""
    target_dir = os.path.join(out_dir, family)
    marker = os.path.join(target_dir, "%s.done" % sha256)
    if os.path.exists(marker):
        return 0
    response = get_with_retry(session, "%s/get/sample/%s/zip" % (API, sha256), limiter)
    payload = response.json()
    if "zipped" not in payload:
        raise ValueError("no payload for %s: %s" % (sha256, sorted(payload)))
    archive = zipfile.ZipFile(io.BytesIO(base64.b64decode(payload["zipped"])))
    os.makedirs(target_dir, exist_ok=True)
    written = 0
    for name in archive.namelist():
        content = archive.read(name, pwd=ZIP_PASSWORD)
        # names carry the sha256 and a variant suffix; keep them, they identify the variant
        with open(os.path.join(target_dir, os.path.basename(name)), "wb") as outfile:
            outfile.write(content)
        written += 1
    open(marker, "w").close()
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--token", default=os.environ.get("MALPEDIA_API_TOKEN"), help="Malpedia API token (default: $MALPEDIA_API_TOKEN)")
    parser.add_argument("--out", required=True, help="output directory")
    parser.add_argument("--status", nargs="+", default=["unpacked", "dumped"], help="sample states to fetch")
    parser.add_argument("--limit", type=int, default=0, help="stop after N samples (0: all)")
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--rate", type=float, default=1.5, help="global requests per second (Malpedia 429s above ~2)")
    args = parser.parse_args()
    if not args.token:
        parser.error("no API token: pass --token or set MALPEDIA_API_TOKEN")

    session = _session(args.token)
    limiter = RateLimiter(args.rate)
    samples = list_samples(session, set(args.status), limiter=limiter, cache_path=os.path.join(os.path.dirname(os.path.abspath(args.out)), "malpedia_sample_list.json"))
    if args.limit:
        samples = samples[: args.limit]
    print("fetching %d samples into %s" % (len(samples), args.out), flush=True)
    os.makedirs(args.out, exist_ok=True)

    counters = {"ok": 0, "files": 0, "fail": 0}
    lock = threading.Lock()
    started = time.time()
    # one session per thread: requests.Session is not documented as thread-safe
    local = threading.local()

    def worker(item):
        family, sha256, _status, _version = item
        if not hasattr(local, "session"):
            local.session = _session(args.token)
        try:
            written = fetch_one(local.session, args.out, family, sha256, limiter)
        except Exception as error:  # a single bad sample must not end a multi-hour fetch
            with lock:
                counters["fail"] += 1
            print("FAIL %s/%s: %s" % (family, sha256, error), file=sys.stderr, flush=True)
            return
        with lock:
            counters["ok"] += 1
            counters["files"] += written
            done = counters["ok"] + counters["fail"]
            if done % 100 == 0:
                rate = done / max(1e-9, time.time() - started)
                print("%d/%d  %d files  %d failed  %.1f samples/s" % (done, len(samples), counters["files"], counters["fail"], rate), flush=True)

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        list(pool.map(worker, samples))
    print("done: %d ok, %d files, %d failed in %.0f s" % (counters["ok"], counters["files"], counters["fail"], time.time() - started), flush=True)


if __name__ == "__main__":
    main()
