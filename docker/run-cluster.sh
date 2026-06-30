#!/usr/bin/env bash
# Build + run the uber-mesh netem cluster, collect metrics from container logs, tear down.
set -euo pipefail
cd "$(dirname "$0")/.."

DURATION="${DURATION:-50}"
COMPOSE="docker compose -f docker/compose.yml"

echo "=== building image (prebuilt binary) ==="
docker build -q -t uber-mesh:bench -f docker/Dockerfile . >/dev/null

echo "=== bringing up 4-node cluster under tc-netem ==="
$COMPOSE up -d --force-recreate >/dev/null
trap '$COMPOSE down -v >/dev/null 2>&1 || true' EXIT

echo "running for ${DURATION}s under impairment (heartbeat interval is 15s)..."
sleep "$DURATION"

echo ""
echo "=== per-node summary (signed heartbeats crossing the impaired mesh) ==="
total_hb=0
for svc in boot node1 node2 node3; do
    logs=$($COMPOSE logs "$svc" 2>/dev/null || true)
    conns=$(printf '%s' "$logs" | grep -c "peer connected" || true)
    hbs=$(printf '%s' "$logs" | grep -c "uber-mesh/global" || true)
    netem=$(printf '%s' "$logs" | grep -o "netem on .*" | head -1 || true)
    printf "  %-6s peer_connections=%-2s heartbeats_received=%-2s | %s\n" "$svc" "$conns" "$hbs" "$netem"
    total_hb=$((total_hb + hbs))
done
echo "  ---- total signed heartbeats delivered across the cluster: $total_hb"

echo ""
echo "=== sample delivered heartbeats (sender authenticated by app PeerId b3:...) ==="
$COMPOSE logs 2>/dev/null | grep "uber-mesh/global" | tail -4 || true
