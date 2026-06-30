# uber-mesh — multi-node validation, metrics, impairment & throughput

Harnesses exercising the **real code** beyond unit/integration tests. Numbers measured on this machine
(12 cores / 27 GiB, mid-2026). Each result is reproducible via the commands shown.

## 1. In-process N-node gossip benchmark — `cargo run --release --example cluster`

| Nodes | Link latency | Peer conns | Delivery | Propagation p50 / p95 / max |
|---|---|---|---|---|
| 20 | 0 ms | 76 | 100% | 0 / 1 / 1 ms |
| 20 | +30 ms | 76 | 100% | 31 / 31 / 31 ms |
| 20 | +150 ms | 76 | 100% | 151 / 152 / 152 ms |
| **100** | 0 ms | 396 | **100%** | 2 / 3 / 4 ms |

(The in-process latency middlebox delays inbound only — a uniform-link model, not geo; see §7.)

## 2. Docker cluster + Prometheus + per-node resources — `NODES=100 bash docker/run-cluster.sh`

1 bootstrap + N−1 scaled `node` replicas + Prometheus (DNS-SD scrape of every `/metrics`) under
`tc netem`. **100 nodes, `delay 50ms 10ms loss 2%`:**

| Metric (cluster-wide, via Prometheus) | Value |
|---|---|
| nodes scraped | **100 / 100** |
| live peer connections | 198 |
| gossip messages received | 25 540 |
| gossip rejected (forgery) | 0 |
| **obfs handshake p50 / p95** | **57 ms / 147 ms** (under the 150 ms SC target) |

**Per-node resources** (`umesh_process_*` from `/proc/self`, 40-node run): RSS **~4 MB leaf / ~33 MB
bootstrap** (`docker stats`), CPU **near-idle** (2.96 CPU-s / 50 s for 40 nodes; leaf 0.01–0.1%), ~14
threads, ~16 fds/node. Lightweight.

## 3. Heavy impairment + chaos — `NODES=50 CHAOS=12 NETEM="…" bash docker/run-cluster.sh`

`delay 60ms 15ms loss 3% reorder 20% 50% duplicate 1% corrupt 0.1%`, killing 12/50 nodes mid-run:
**38 survivors keep gossiping (3 741 msgs), 0 forgeries.** Handshake p95 degrades to 642 ms under
bit-corruption (TCP retransmits + AEAD retries) — handshakes still complete.

## 4. DPI middlebox — `cargo test -p umesh-obfs --test dpi_middlebox`

A censor in the connection path. Verified:

- ✅ **Entropy/no-header filter** (USENIX'23 fully-encrypted heuristic): obfs **passes** (TLS-record
  framing exempt; handshake + data complete through the censor); a **raw high-entropy flow is blocked**.
- ✅ **Active probing**: the censor probes suspect servers — obfs answers with **silence** → not
  unmasked → allowed; a naive always-answering proxy **is unmasked** → blocked.
- ✅ **TLS state-machine** ("a real TLS flow must open with a ClientHello, not application-data"): obfs
  **passes** — its first flight is a structurally-valid TLS 1.3 ClientHello (`0x16`) with a PQ-hybrid
  X25519MLKEM768 key_share; an **app-data-first flow (the old carrier) is blocked**, proving the box
  genuinely enforces the state machine.

## 5. Throughput (saturation) — `cargo run --release --example throughput`

Obfuscated transport (hybrid-PQ keyed, XChaCha20-Poly1305 records, loopback):

| Mode | Goodput |
|---|---|
| no shaping | **267 MB/s** (34k msgs/s) |
| light shaping | 289 MB/s |
| aggressive (IAT jitter) | **1.4 MB/s** — per-record timing jitter caps bulk *by design* (covert rate); should be per-burst for bulk |

## 6. Metrics pipeline — Prometheus → Grafana

Every node serves `/metrics`; Prometheus scrapes via DNS-SD; Grafana auto-provisions a datasource +
`uber-mesh cluster` dashboard. `run-cluster.sh` verifies: grafana health `ok`, datasource `Prometheus`,
dashboard loaded, and a query **through Grafana's proxy** returned the live node count. UIs at
`:9090` (Prometheus) and `:3000` (Grafana).

## 7. Geo-emulation — `docker compose -f docker/compose.geo.yml up --scale region_*=…`

Three regions with distinct per-container `netem` on `eth0` (near 20 ms / mid 90 ms / far 200 ms+1% loss)
so each node's latency applies to **all** its traffic (link RTT ≈ sum of endpoints' delays — the faithful
model). 3×7 nodes: **22 up, 1 754 gossip msgs across regions, 0 forgeries**, obfs handshake p95 = 487 ms
(reflecting the far region's 200 ms links; well under the 10 s handshake timeout).

## 8. Soak — `NODES=20 DURATION=180 bash docker/run-cluster.sh`

20 nodes for 3 minutes: all 20 up throughout, 4 192 gossip msgs, **RSS stable ~12 MB avg / 24 MB max
(no leak)**, threads flat at 14, handshake p95 = 147 ms, 0 forgeries.

## Caveats — honest scope

**Closed by the above:** 100 nodes (in-process + Docker), Prometheus **+ Grafana** pipeline, per-node
resource metrics, real `tc netem` (loss/latency/reorder/duplicate/corrupt), chaos/partition, an
entropy **+ active-probing** DPI middlebox the obfs passes, saturation throughput, geo-emulation (faithful
per-region RTT), and a multi-minute soak with no leak. Handshake p95 ≤ 150 ms (SC) met under normal netem.

**Closed since:** the obfs first flight is now a **structurally-valid TLS 1.3 ClientHello** (`0x16`,
PQ-hybrid X25519MLKEM768 key_share; PSK gate in the `session_id`), so the flow opens *ClientHello →
ServerHello → app-data* and passes the TLS-state-machine heuristic (test §4). What remains deferred is
**byte-exact uTLS fingerprint** mimicry (JA3/JA4: a fixed extension set, single default SNI) and a full
TLS-1.3 transcript — those need a real TLS stack (native REALITY, `docs/security-and-deferred.md`).

**Still NOT closed — fundamentally out of reach here (will not fake):**
- **Real nation-state DPI / in-country (Iran/Russia) survivability** — needs access to those networks;
  the middlebox is a faithful model of the primary heuristics (entropy, active-probing, TLS state machine),
  not a real censor with ML classifiers or full-transcript TLS analysis at scale.
- **Byte-exact TLS fingerprint (JA3/JA4) + full TLS-1.3 transcript** — the ClientHello is structurally
  valid but not byte-identical to a specific browser, and there is no real EncryptedExtensions/Certificate/
  Finished; a DPI doing full-transcript validation would still distinguish it (deferred native-REALITY).
- **True geographic distribution** across real datacenters/CGNAT/asymmetric paths — emulated via netem on
  a single host, not real.
- **Long soak** (hours/days) and **Grafana visual** validation (verified via API, not a rendered screen).
