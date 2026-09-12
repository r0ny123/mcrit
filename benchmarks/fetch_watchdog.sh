#!/bin/bash
# Keep the Malpedia fetch alive.
#
# Malpedia enforces a cumulative quota: after a few hundred samples every request 429s even
# when issued serially, and only time clears it. A fetcher that burns its retry budget during
# such a cooldown exits (or spins on failures) and the corpus stops growing silently. This
# watchdog notices that the .done count has stopped moving and restarts the fetcher, which is
# resumable by design - the .done markers mean a restart costs nothing already fetched.
#
# Usage: nohup ./benchmarks/fetch_watchdog.sh <out_dir> <log_dir> &   (MALPEDIA_API_TOKEN in env)
set -u
OUT_DIR="${1:-/home/user/data/malpedia_api}"
LOG_DIR="${2:-/home/user/data}"
PYTHON="${PYTHON:-/home/user/venv/bin/python}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK_INTERVAL="${CHECK_INTERVAL:-300}"   # how often to look
STALL_CHECKS="${STALL_CHECKS:-3}"         # consecutive idle checks before restarting
RATE="${RATE:-0.4}"

count_done() { find "$OUT_DIR" -name '*.done' 2>/dev/null | wc -l; }

last_count=$(count_done)
idle=0
while true; do
    sleep "$CHECK_INTERVAL"
    current=$(count_done)
    alive=$(pgrep -f "fetch_malpedia.py" | grep -v $$ | wc -l)
    if [ "$current" -gt "$last_count" ]; then
        idle=0
    else
        idle=$((idle + 1))
    fi
    echo "$(date -Is) done=$current (+$((current - last_count))) alive=$alive idle_checks=$idle" >> "$LOG_DIR/watchdog.log"
    last_count=$current
    if [ "$current" -ge 7587 ]; then
        echo "$(date -Is) corpus complete, watchdog exiting" >> "$LOG_DIR/watchdog.log"
        exit 0
    fi
    # restart when the fetcher died, or when it is alive but has made no progress for a while
    # (stuck in a quota cooldown its retry budget cannot outlast)
    if [ "$alive" -eq 0 ] || [ "$idle" -ge "$STALL_CHECKS" ]; then
        echo "$(date -Is) restarting fetcher (alive=$alive idle=$idle)" >> "$LOG_DIR/watchdog.log"
        pkill -9 -f "fetch_malpedia.py" 2>/dev/null
        sleep 30
        nohup "$PYTHON" "$SCRIPT_DIR/fetch_malpedia.py" --out "$OUT_DIR" --threads 1 --rate "$RATE" \
            >> "$LOG_DIR/fetch_watchdog_runs.log" 2>&1 &
        disown
        idle=0
    fi
done
