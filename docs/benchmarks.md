# uber-mesh — multi-node validation, metrics & impairment

Harnesses that exercise the **real code** beyond unit/integration tests: an in-process N-node
benchmark, a scalable Docker cluster under real `tc netem` with a Prometheus pipeline, and a DPI
middlebox that genuinely censors. Numbers measured on this machine (12 cores / 27 GiB, mid-2026).

## 1. In-process N-node benchmark — `cargo run --release --example cluster`

N real `MeshNode`s (real libp2p + obfuscated transport over loopback TCP), star+ring topology,
gossip one message from node 0 to the other N−1, optionally through a latency middlebox.

| Nodes | Link latency | Peer connections | Delivery | Propagation p50 / p95 / max |
|---|---|---|---|---|
| 20 | 0 ms | 76 | 100% | 0 / 1 / 1 ms |
| 20 | +30 ms | 76 | 100% | 31 / 31 / 31 ms |
| 20 | +150 ms | 76 | 100% | 151 / 152 / 152 ms |
| **100** | 0 ms | **396** | **100%** | **2 / 3 / 4 ms** |

## 2. Docker cluster + Prometheus — `NODES=100 bash docker/run-cluster.sh`

Isolated bridge network: 1 bootstrap (static IP) + N−1 scaled `node` replicas + Prometheus
(DNS-SD scrape of every node's `/metrics`). Each node runs `uber-mesh mesh` over the obfuscated
transport under `tc netem`; the runner queries Prometheus for cluster aggregates.

**100 nodes, `netem: delay 50ms 10ms loss 2%`:**

| Metric (Prometheus, cluster-wide) | Value |
|---|---|
| nodes scraped (up targets) | **100 / 100** |
| live peer connections | 198 |
| gossip messages received | **25 540** |
| gossip messages published | 562 |
| gossip rejected (forgery) | 0 |
| obfs handshakes | 198 |
| **obfs handshake p50 / p95** | **57 ms / 147 ms** |
| probe/gate failures | 0 |

The obfs-handshake **p95 = 147 ms is under the spec's ≤150 ms target** (SC), measured over 198 real
handshakes through the obfuscated carrier under impairment.

Every node exposes Prometheus metrics: `umesh_peers_connected`, `umesh_gossip_{received,published,
rejected}_total`, `umesh_blobs_{served,received}_total`, `umesh_sync_completed_total`,
`umesh_handshake_failures_total`, and the `umesh_handshake_seconds` histogram.

## 3. Heavy impairment + chaos — `NODES=50 CHAOS=12 NETEM="…" bash docker/run-cluster.sh`

**50 nodes, `delay 60ms 15ms loss 3% reorder 20% 50% duplicate 1% corrupt 0.1%`, killing 12 nodes
mid-run:**

| Metric | Value |
|---|---|
| nodes scraped after chaos | 38 (= 50 − 12 killed) |
| live peer connections (survivors) | 74 |
| gossip messages received | **3 741** |
| gossip rejected | 0 |
| obfs handshake p50 / p95 | 60 ms / 642 ms |

The mesh **survives node churn + packet loss/reorder/duplication/corruption** and keeps gossiping
among survivors. Handshake p95 degrades to 642 ms under bit-corruption (honest: corruption forces TCP
retransmits + AEAD-failure retries) — handshakes still complete.

## 4. DPI middlebox — `cargo test -p umesh-obfs --test dpi_middlebox`

A censor box in the connection path applies the USENIX'23 fully-encrypted heuristic
(`umesh_obfs::wire::looks_fully_encrypted`: no recognizable header + high popcount → DROP). Verified:

- ✅ the **obfs transport passes** — its TLS-record-framed first flight is exempt; the handshake +
  data exchange complete *through* the censor.
- ✅ a **raw high-entropy flow is blocked** — proving the box genuinely censors, so the pass is real.

## Caveats — honest scope

- ✅ Now done: **100 nodes** (in-process + Docker), **Prometheus metrics pipeline**, **real `tc netem`**
  (loss/latency/reorder/duplicate/corrupt), **chaos/partition** (node kills), a **DPI middlebox** that
  cuts by entropy and which the obfuscation passes, and the **SC handshake p95 ≤ 150 ms** target met
  under normal impairment.
- ❌ The DPI middlebox uses the same entropy heuristic the obfs is *designed* to defeat; it is a
  faithful model of the primary modern censor, **not** a nation-state DPI with active probing at scale,
  ML classifiers, or TLS-state-machine analysis. Real in-country (Iran/Russia) survivability is still
  unproven and can only be measured in the field.
- ❌ **Single host, one bridge network** — not geographically distributed; netem approximates RTT but
  not real internet paths/CGNAT/asymmetry. Star topology (all dial one bootstrap).
- ❌ No long **soak** (minutes, not hours/days); throughput is observed via message counts, not a
  saturating throughput benchmark; no Grafana dashboards (Prometheus only).
- ❌ `corrupt`/`reorder` degrade handshake p95 (642 ms) — acceptable but unoptimized.
