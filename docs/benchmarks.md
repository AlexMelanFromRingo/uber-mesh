# uber-mesh — multi-node validation & benchmarks

Two harnesses exercise the **real code** beyond unit/integration tests: an in-process N-node benchmark
and a Docker cluster under real `tc netem` impairment. Results below were measured on this machine
(12 cores, mid-2026). These validate functionality and relative behavior under impairment — they are
**not** a real-world DPI/TSPU test, nor a geographic-scale deployment (see *Caveats*).

## 1. In-process N-node benchmark — `cargo run --release --example cluster`

Spins up N real `MeshNode`s (real libp2p + obfuscated transport over loopback TCP), forms a mesh
(star + ring), and measures gossip propagation of one message from node 0 to the other N−1, optionally
through a latency middlebox.

```
NODES=20 LATENCY_MS=0    cargo run --release --example cluster
NODES=20 LATENCY_MS=150  cargo run --release --example cluster
```

**Measured (20 nodes):**

| Link latency (each way) | Peer connections | Delivery ratio | Propagation p50 / p95 / max |
|---|---|---|---|
| 0 ms (baseline) | 76 | 19/19 = 100% | 0 / 1 / 1 ms |
| +30 ms | 76 | 19/19 = 100% | 31 / 31 / 31 ms |
| +150 ms | 76 | 19/19 = 100% | 151 / 152 / 152 ms |

100% delivery at every latency; propagation tracks one impaired hop (flood-publish reaches subscribers
in ~1×link-latency). *(Running this caught a harness bug — the latency proxy returned a `SocketAddr`
where `dial` wants a multiaddr; the mesh was fine.)*

## 2. Docker cluster under `tc netem` — `docker/run-cluster.sh`

4 containers (1 bootstrap + 3 nodes) on an isolated bridge network, each with `cap_add: NET_ADMIN` and
**real packet loss + latency** applied to `eth0`:

```
netem: delay 80ms 20ms distribution normal loss 10%
```

Each runs `uber-mesh mesh` over the obfuscated transport with a shared PSK; nodes dial the bootstrap by
static IP. Run: `bash docker/run-cluster.sh` (builds the image from the prebuilt binary, runs 50 s,
prints per-node metrics, tears down).

**Measured (50 s, 10% loss + 80±20 ms delay on every node):**

| Node | Peer connections | Signed heartbeats received |
|---|---|---|
| boot | 3 | 7 |
| node1 | 1 | 8 |
| node2 | 1 | 9 |
| node3 | 1 | 8 |
| **total delivered** | | **32** |

Despite 10% loss + latency, the gossip mesh forms and **signed heartbeats propagate across the cluster**
(each authenticated by an app PeerId `b3:…`), relayed via the bootstrap's gossipsub. TCP retransmission +
libp2p absorb the loss. *(First run also surfaced a harness bug — interface detection grabbed the veth
`eth0@ifNN` peer name instead of `eth0`, so `tc` silently failed; fixed to strip the `@ifNN` suffix.)*

## Caveats — what these do and do not prove

- ✅ The full stack (obfs transport → Noise → gossipsub + signed messages) works across **real isolated
  containers** under **real packet loss + latency**, and across many in-process nodes with controlled latency.
- ✅ Relative behavior is sane: 100% gossip delivery; propagation scales with link latency; the mesh
  survives 10% loss.
- ❌ **Not** a real DPI/TSPU test. netem does loss/latency/reorder, not entropy classification or active
  probing. The transport's anti-DPI properties are covered separately by `umesh-obfs` unit tests
  (TLS-record framing, probe silence/fallback) — not by a real censor.
- ❌ **Not** scale-tested (4 containers / 20 in-process nodes; star topology), **not** geographically
  distributed (single host, one bridge), and there is **no** metrics pipeline (Prometheus/Grafana) or
  soak/partition/chaos testing yet. Throughput and large-N propagation are unmeasured.
- ❌ Performance success criteria in the spec (e.g. handshake ≤150 ms, rotation ≤10 s) are **design
  targets**, validated only at this small scale, not as load benchmarks.
