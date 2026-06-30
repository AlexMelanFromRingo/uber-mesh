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
PROM="http://localhost:9090"

echo "=== building image (prebuilt binary) ==="
docker build -q -t uber-mesh:bench -f docker/Dockerfile . >/dev/null

echo "=== bringing up cluster: 1 bootstrap + ${SCALE} nodes + prometheus, under tc-netem ==="
$COMPOSE up -d --force-recreate --scale node="$SCALE" >/dev/null 2>&1
trap '$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true' EXIT

echo "running for ${DURATION}s (nodes form the mesh; prometheus scrapes every 5s)..."
sleep "$DURATION"

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
echo "=== done (tearing down) ==="
