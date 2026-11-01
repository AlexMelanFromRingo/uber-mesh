#!/usr/bin/env bash
# Build + run a scaled uber-mesh cluster (1 bootstrap + N-1 nodes) under tc-netem, with Prometheus
# scraping every node, then query Prometheus for aggregate metrics, then tear down.
#
#   NODES=100 DURATION=90 bash docker/run-cluster.sh
set -euo pipefail
cd "$(dirname "$0")/.."

NODES="${NODES:-100}"
DURATION="${DURATION:-90}"
SCALE=$((NODES - 1))
COMPOSE="docker compose -f docker/compose.yml"
PROM="http://127.0.0.1:9090"

# Per-run secrets (never hardcoded): a fresh cohort PSK and Grafana admin password unless provided.
gen_hex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
export UMESH_PSK="${UMESH_PSK:-$(gen_hex 32)}"
export GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-$(gen_hex 16)}"

echo "=== building image (prebuilt binary) ==="
docker build -q -t uber-mesh:bench -f docker/Dockerfile . >/dev/null

echo "=== bringing up cluster: 1 bootstrap + ${SCALE} nodes + prometheus, under tc-netem ==="
$COMPOSE up -d --force-recreate --scale node="$SCALE" >/dev/null 2>&1
trap '$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true' EXIT

HALF=$((DURATION / 2))
echo "running for ${DURATION}s (nodes form the mesh; prometheus scrapes every 5s)..."
sleep "$HALF"

# Optional chaos: kill CHAOS node containers mid-run to test mesh resilience to churn/partition.
if [ "${CHAOS:-0}" -gt 0 ]; then
    echo "=== CHAOS: killing ${CHAOS} node containers mid-run ==="
    $COMPOSE ps -q node | head -n "$CHAOS" | xargs -r docker kill >/dev/null 2>&1 || true
fi
sleep $((DURATION - HALF))

# Query Prometheus instant vectors via its HTTP API.
q() { curl -sG "$PROM/api/v1/query" --data-urlencode "query=$1" \
        | python3 -c "import sys,json; r=json.load(sys.stdin).get('data',{}).get('result',[]); print(r[0]['value'][1] if r else 'n/a')" 2>/dev/null || echo "n/a"; }

echo ""
echo "=== Prometheus-scraped cluster metrics (${NODES} nodes under impairment) ==="
printf "  nodes scraped (up targets):     %s\n" "$(q 'count(umesh_peers_connected)')"
printf "  total live peer connections:    %s\n" "$(q 'sum(umesh_peers_connected)')"
printf "  total peer connections (cum):   %s\n" "$(q 'sum(umesh_peers_total)')"
printf "  total gossip msgs received:     %s\n" "$(q 'sum(umesh_gossip_received_total)')"
printf "  total gossip msgs published:    %s\n" "$(q 'sum(umesh_gossip_published_total)')"
printf "  gossip msgs rejected (forgery):  %s\n" "$(q 'sum(umesh_gossip_rejected_total)')"
printf "  obfs handshakes (count):        %s\n" "$(q 'sum(umesh_handshake_seconds_count)')"
printf "  obfs handshake p50 (s):         %s\n" "$(q 'histogram_quantile(0.50, sum(umesh_handshake_seconds_bucket) by (le))')"
printf "  obfs handshake p95 (s):         %s\n" "$(q 'histogram_quantile(0.95, sum(umesh_handshake_seconds_bucket) by (le))')"
printf "  probe/gate failures:            %s\n" "$(q 'sum(umesh_handshake_failures_total)')"

echo ""
echo "=== per-node resource usage (Prometheus-scraped from /proc/self) ==="
printf "  resident MB/node  avg / max:    %s / %s\n" \
    "$(q 'avg(umesh_process_resident_bytes)/1024/1024')" "$(q 'max(umesh_process_resident_bytes)/1024/1024')"
printf "  open fds/node     avg / max:    %s / %s\n" \
    "$(q 'avg(umesh_process_open_fds)')" "$(q 'max(umesh_process_open_fds)')"
printf "  threads/node      avg / max:    %s / %s\n" \
    "$(q 'avg(umesh_process_threads)')" "$(q 'max(umesh_process_threads)')"
printf "  total cluster CPU-seconds:      %s\n" "$(q 'sum(umesh_process_cpu_seconds_total)')"
echo "  --- docker stats sample (live CPU%/mem, 5 containers) ---"
docker stats --no-stream --format '    {{.Name}}: cpu={{.CPUPerc}} mem={{.MemUsage}}' $($COMPOSE ps -q | head -5) 2>/dev/null || true
echo ""
echo "=== Grafana pipeline (Prometheus -> Grafana) ==="
GRAF="http://127.0.0.1:3000"
GAUTH="admin:${GRAFANA_ADMIN_PASSWORD}"
printf "  grafana health:                 %s\n" "$(curl -s $GRAF/api/health | python3 -c 'import sys,json;print(json.load(sys.stdin).get("database","?"))' 2>/dev/null || echo n/a)"
printf "  provisioned datasource:         %s\n" "$(curl -s -u "$GAUTH" $GRAF/api/datasources | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d[0]["name"] if d else "none")' 2>/dev/null || echo n/a)"
printf "  provisioned dashboard:          %s\n" "$(curl -s -u "$GAUTH" "$GRAF/api/search?query=uber-mesh" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d[0]["title"] if d else "none")' 2>/dev/null || echo n/a)"
printf "  query via grafana (nodes up):   %s\n" "$(curl -s -u "$GAUTH" -G "$GRAF/api/datasources/proxy/uid/umesh-prom/api/v1/query" --data-urlencode 'query=count(umesh_peers_connected)' | python3 -c 'import sys,json;r=json.load(sys.stdin)["data"]["result"];print(r[0]["value"][1] if r else "n/a")' 2>/dev/null || echo n/a)"
echo "  (Grafana UI: http://127.0.0.1:3000 — dashboard 'uber-mesh cluster', login admin / \$GRAFANA_ADMIN_PASSWORD)"
echo "=== done (tearing down) ==="
