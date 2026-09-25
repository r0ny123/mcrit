#!/bin/bash
# Bring the corpus-building pipelines up, idempotently.
#
# A long corpus build outlives the thing running it: containers restart, daemons die, and the
# OOM killer takes whatever is largest. Every piece here is resumable by design - the fetch
# skips samples with a .done marker, disassembly skips samples with a cached report, and the
# pruner only deletes what has already been disassembled - so the recovery procedure is simply
# to run this again. Nothing is re-downloaded and nothing is re-disassembled.
#
# Usage: MALPEDIA_API_TOKEN=... ./benchmarks/start_pipelines.sh [data_dir]
set -u
DATA_DIR="${1:-/home/user/data}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-/home/user/venv/bin/python}"
MONGO_CONTAINER="${MONGO_CONTAINER:-mcrit-mongo3}"

start_if_absent() {  # name, command...
    local name="$1"; shift
    if pgrep -f "$name" > /dev/null 2>&1; then
        echo "already running: $name"
        return
    fi
    echo "starting: $name"
    setsid nohup "$@" >> "$DATA_DIR/${name%%.*}.log" 2>&1 < /dev/null &
    disown
}

# mongod: the container's default nofile is 1024, and WiredTiger answers EMFILE by aborting the
# whole server with a panic that looks like data loss. Cap its cache too - the default is half
# of RAM, which is what invited the OOM killer to take the fetchers instead.
if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${MONGO_CONTAINER}$"; then
    if ! docker info > /dev/null 2>&1; then
        echo "starting dockerd"
        sudo dockerd > /tmp/dockerd.log 2>&1 &
        sleep 12
    fi
    echo "starting mongo container ${MONGO_CONTAINER}"
    docker start "$MONGO_CONTAINER" > /dev/null 2>&1 || \
        docker run -d --name "$MONGO_CONTAINER" --ulimit nofile=20000:20000 --memory=6g \
            -v /home/user/mongodata_full:/data/db -p 27017:27017 mongo:7.0 --wiredTigerCacheSizeGB 3 > /dev/null
    sleep 15
fi

cd "$REPO_DIR" || exit 1
# The watchdog is started, never the fetcher directly: the watchdog owns the fetcher's
# lifecycle and restarts it by pkill'ing every fetch_malpedia.py it finds, so a second one
# started by hand is simply killed - and while both are alive they double the request rate
# against an API that answers concurrency with a cumulative quota.
start_if_absent "fetch_watchdog.sh" ./benchmarks/fetch_watchdog.sh "$DATA_DIR/malpedia_api" "$DATA_DIR"
start_if_absent "disassemble_corpus.py" "$PYTHON" benchmarks/disassemble_corpus.py --in "$DATA_DIR/malpedia_api" --out "$DATA_DIR/reports" --workers 3

echo
echo "malpedia: $(find "$DATA_DIR/malpedia_api" -name '*.done' 2>/dev/null | wc -l) / 7587 downloaded"
echo "reports:  $(ls "$DATA_DIR/reports" 2>/dev/null | wc -l) disassembled"
echo "disk:     $(df -h / | tail -1 | awk '{print $4}') free"
