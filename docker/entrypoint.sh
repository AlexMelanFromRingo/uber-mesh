#!/bin/sh
# Apply tc-netem impairment to the container's primary interface, then run a mesh node.
# Env: UMESH_PSK (hex), NETEM (e.g. "delay 80ms 20ms loss 10%"), BOOTSTRAP (optional multiaddr).
set -e

# Primary non-loopback interface; strip the veth "@ifNN" peer suffix so `tc` gets the real name.
IFACE=$(ip -o link show | awk -F': ' '$2 != "lo" { print $2; exit }' | cut -d'@' -f1)

if [ -n "$NETEM" ] && [ -n "$IFACE" ]; then
    if tc qdisc add dev "$IFACE" root netem $NETEM 2>/dev/null; then
        echo "netem on $IFACE: $NETEM"
    else
        echo "WARN: could not apply netem on $IFACE (need NET_ADMIN); running without impairment"
    fi
fi

uber-mesh --data-dir /data init >/dev/null 2>&1 || true

set -- uber-mesh --data-dir /data mesh --psk "$UMESH_PSK" --listen /ip4/0.0.0.0/tcp/4001
if [ -n "$BOOTSTRAP" ]; then
    sleep 6 # let the bootstrap node come up first (mesh dials it once at startup)
    set -- "$@" --bootstrap "$BOOTSTRAP"
fi
exec "$@"
