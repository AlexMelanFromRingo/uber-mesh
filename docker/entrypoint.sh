#!/bin/sh
# Optionally apply tc-netem impairment to the container's primary interface, then run a mesh node as
# the unprivileged `umesh` user.
#
# Env:
#   UMESH_PSK_FILE  path to a file holding the obfs PSK (hex), readable by uid 10001 (e.g. a secret)
#   UMESH_PSK       obfs PSK (hex) — read by the binary from the environment, never put on argv
#   NETEM           e.g. "delay 80ms 20ms loss 10%" (needs root + NET_ADMIN; see compose.yml)
#   BOOTSTRAP       optional bootstrap multiaddr
#   UMESH_METRICS_ADDR  opt-in /metrics bind address (e.g. 0.0.0.0:9100 on a private network)
set -eu

if [ "$(id -u)" = "0" ]; then
    if [ -n "${NETEM:-}" ]; then
        # Primary non-loopback interface; strip the veth "@ifNN" suffix so `tc` gets the real name.
        IFACE=$(ip -o link show | awk -F': ' '$2 != "lo" { print $2; exit }' | cut -d'@' -f1)
        # shellcheck disable=SC2086 # NETEM is intentionally word-split into tc arguments
        if [ -n "$IFACE" ] && tc qdisc add dev "$IFACE" root netem $NETEM 2>/dev/null; then
            echo "netem on $IFACE: $NETEM"
        else
            echo "WARN: could not apply netem (need NET_ADMIN); running without impairment"
        fi
    fi
    # Drop root for good: no supplementary groups, empty inheritable caps; no-new-privileges (set
    # in compose) prevents regaining privilege via setuid binaries.
    exec setpriv --reuid=umesh --regid=umesh --clear-groups --inh-caps=-all "$0" "$@"
fi

if [ -z "${UMESH_PSK_FILE:-}" ] && [ -z "${UMESH_PSK:-}" ]; then
    echo "ERROR: set UMESH_PSK_FILE or UMESH_PSK (e.g. \$(openssl rand -hex 32))" >&2
    exit 3
fi

uber-mesh --data-dir /data init >/dev/null 2>&1 || true

# The PSK is passed via --psk-file or inherited UMESH_PSK env, never as an argv value (visible in ps).
set -- uber-mesh --data-dir /data mesh --listen /ip4/0.0.0.0/tcp/4001
if [ -n "${UMESH_PSK_FILE:-}" ]; then
    set -- "$@" --psk-file "$UMESH_PSK_FILE"
fi
if [ -n "${BOOTSTRAP:-}" ]; then
    sleep 6 # let the bootstrap node come up first (mesh dials it once at startup)
    set -- "$@" --bootstrap "$BOOTSTRAP"
fi
exec "$@"
