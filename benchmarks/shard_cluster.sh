#!/bin/bash
# Stand up a real sharded MongoDB cluster: 1 config server, 2 shards, 1 mongos.
#
# Real rather than simulated on purpose. The question sharding has to answer is not "does the
# code run" but "does a query reach one shard or all of them", and that is a property of the
# shard key and the query shape which only a genuine mongos can report. Running two mongods and
# pretending is exactly the kind of measurement that looks like evidence and is not.
#
# Small by design: one node per replica set, tiny caches, a two-report corpus. Routing behaviour
# does not depend on data volume, and there is ~4 GB of disk here.
set -u
NET=mcrit-shard
IMAGE=mongo:7.0
CACHE=0.25

say() { echo "=== $(date -Is) $* ==="; }

wait_for() {
    local name=$1 port=$2
    for _ in $(seq 1 60); do
        docker exec "$name" mongosh --quiet --port "$port" --eval 'db.adminCommand({ping:1}).ok' >/dev/null 2>&1 && return 0
        sleep 2
    done
    echo "$name did not come up"; return 1
}

say "tearing down any previous cluster"
docker rm -f mcrit-cfg mcrit-shard0 mcrit-shard1 mcrit-mongos >/dev/null 2>&1
docker network rm "$NET" >/dev/null 2>&1
docker network create "$NET" >/dev/null

say "config server"
docker run -d --name mcrit-cfg --network "$NET" "$IMAGE" \
    mongod --configsvr --replSet cfgrs --port 27019 --bind_ip_all --wiredTigerCacheSizeGB "$CACHE" >/dev/null
wait_for mcrit-cfg 27019 || exit 1
docker exec mcrit-cfg mongosh --quiet --port 27019 --eval \
    'rs.initiate({_id:"cfgrs", configsvr:true, members:[{_id:0, host:"mcrit-cfg:27019"}]})' >/dev/null

say "shard servers"
for n in 0 1; do
    docker run -d --name "mcrit-shard$n" --network "$NET" "$IMAGE" \
        mongod --shardsvr --replSet "shard${n}rs" --port 27018 --bind_ip_all --wiredTigerCacheSizeGB "$CACHE" >/dev/null
done
for n in 0 1; do
    wait_for "mcrit-shard$n" 27018 || exit 1
    docker exec "mcrit-shard$n" mongosh --quiet --port 27018 --eval \
        "rs.initiate({_id:\"shard${n}rs\", members:[{_id:0, host:\"mcrit-shard$n:27018\"}]})" >/dev/null
done

say "waiting for replica sets to elect primaries"
for target in mcrit-cfg:27019 mcrit-shard0:27018 mcrit-shard1:27018; do
    name=${target%%:*}; port=${target##*:}
    for _ in $(seq 1 60); do
        state=$(docker exec "$name" mongosh --quiet --port "$port" --eval 'try { rs.status().myState } catch (e) { 0 }' 2>/dev/null | tr -dc '0-9')
        [ "$state" = "1" ] && break
        sleep 2
    done
    echo "  $name myState=$state"
done

say "mongos on host port 27117"
docker run -d --name mcrit-mongos --network "$NET" -p 27117:27017 "$IMAGE" \
    mongos --configdb cfgrs/mcrit-cfg:27019 --port 27017 --bind_ip_all >/dev/null
wait_for mcrit-mongos 27017 || exit 1

say "adding shards"
docker exec mcrit-mongos mongosh --quiet --eval '
sh.addShard("shard0rs/mcrit-shard0:27018");
sh.addShard("shard1rs/mcrit-shard1:27018");
db.adminCommand({listShards:1}).shards.forEach(function(s){ print("  shard " + s._id + " -> " + s.host); });
'

say "CLUSTER READY on 127.0.0.1:27117"
