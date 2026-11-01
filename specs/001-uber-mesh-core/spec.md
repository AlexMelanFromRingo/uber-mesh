# Feature Specification: uber-mesh — Decentralized Censorship-Resistant Mesh

**Feature Branch**: `001-uber-mesh-core`

**Created**: 2026-06-28

**Status**: Implemented through v0.10.0 (QUIC/AmneziaWG/local-RF transports deferred). Requirement → test
traceability and evidence levels: [`docs/threat-model.md`](../../docs/threat-model.md).

**Input**: User description: "Decentralized, censorship-resistant P2P mesh network built on modern,
standardized, audited cryptography. Must establish stable connectivity even under harsh DPI/TSPU
conditions (Iran, Russia). Stack direction: libp2p, Noise, BLAKE3, Ed25519, ML-KEM, ChaCha20-Poly1305,
Merkle trees, gossipsub, peer discovery, NAT traversal, pluggable obfuscation inspired by
VLESS/Reality/Hysteria/AmneziaWG."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Stay connected under active censorship (Priority: P1)

A person inside a network controlled by an aggressive censor (DPI that classifies fully-encrypted
traffic, probes suspected proxies, inspects SNI, and throttles/freezes foreign flows) starts a node and
obtains a working, private link to at least one other mesh peer. The link survives passive
classification and active probing, and when one carrier is blocked the node automatically rotates to a
surviving transport without user intervention.

**Why this priority**: Reachability under censorship is the entire reason the project exists. Without it,
nothing else delivers value. This is the MVP.

**Independent Test**: Start two nodes separated by a simulated DPI middlebox (drops high-entropy flows,
sends active probes, resets after a volume threshold). Verify the nodes complete a handshake, exchange
data, that an active probe to the listener receives an indistinguishable/cover response, and that
killing the active transport triggers automatic rotation to a working one — all without manual config.

**Acceptance Scenarios**:

1. **Given** a censor that drops connections whose first packets look high-entropy, **When** a node dials
   a peer, **Then** the obfuscated transport's traffic does not trip the entropy classifier and the
   session establishes.
2. **Given** an active prober connects to a node's listener without valid credentials, **When** it probes,
   **Then** it receives cryptographic silence or genuine cover traffic and cannot distinguish the node
   from a non-mesh host.
3. **Given** the currently-used transport becomes blocked mid-session, **When** the health-check detects
   the silent failure, **Then** the node automatically re-establishes over an alternate transport/endpoint.
4. **Given** an operator selects an environment profile (e.g. "aggressive DPI"), **When** the node starts,
   **Then** it uses transport, fingerprint, and shaping defaults appropriate to that hostility level.

---

### User Story 2 - Decentralized authenticated messaging without a central server (Priority: P2)

Two or more peers join the mesh, discover each other without any mandatory central server, and exchange
messages over a publish/subscribe topic. Every message is authenticated to its sender and confidential
on the wire; forged, tampered, or replayed messages are rejected.

**Why this priority**: The mesh's purpose is to carry trustworthy traffic peer-to-peer. Discovery and
authenticated pub/sub are the core "network" value once connectivity (P1) exists.

**Independent Test**: Start a small cluster with one bootstrap peer; have a new node discover the others
via the peer-discovery mechanism, subscribe to a topic, publish a signed message, and confirm all
subscribers accept it. Then inject a forged/tampered/replayed message and confirm every node rejects it.

**Acceptance Scenarios**:

1. **Given** a running peer and a bootstrap reference, **When** a new node joins, **Then** it discovers
   live peers and forms a connected overlay without contacting any project-operated central service.
2. **Given** a node publishes a message on a subscribed topic, **When** subscribers receive it, **Then**
   they verify the sender's signature and accept it.
3. **Given** an attacker replays a previously-valid message or forges a sender, **When** peers receive it,
   **Then** they reject it (replay window + signature verification) and the sender's local reputation drops.
4. **Given** content is referenced by its content identifier, **When** any peer serves it, **Then** the
   receiver can verify the bytes match the identifier before accepting them.

---

### User Story 3 - Reach peers behind NAT/CGNAT (Priority: P3)

A peer behind a home NAT or carrier-grade NAT (CGNAT), unable to accept inbound connections directly,
still participates fully: it is reachable through relaying and, when possible, upgraded to a direct
peer-to-peer connection via coordinated hole punching.

**Why this priority**: Most real users are behind NAT; in censored regions CGNAT is common. Connectivity
that only works for publicly-reachable nodes would exclude the majority of the target population.

**Independent Test**: Place a node behind a simulated symmetric NAT with no port forwarding. Verify it
joins via a relay, is reachable by other peers, and (for compatible NAT types) is upgraded to a direct
connection; verify it remains reachable via relay when direct upgrade is impossible.

**Acceptance Scenarios**:

1. **Given** a node cannot accept inbound connections, **When** it joins, **Then** it becomes reachable
   through an available relay peer.
2. **Given** two NATed peers want to talk, **When** hole punching is coordinated, **Then** they upgrade to
   a direct connection when their NAT types permit, otherwise they keep communicating via relay.
3. **Given** the node detects its own reachability status, **When** it is publicly reachable, **Then** it
   may offer limited relay capacity to others.

---

### User Story 4 - Operate and observe a node simply (Priority: P3)

An operator runs a node from a single binary with a small configuration, generates/keeps a stable
identity, and can observe node health (connected peers, active transports, reachability, rotation events)
through structured logs and a status command — without secrets ever appearing in output.

**Why this priority**: Resilience depends on operators being able to run, tune, and trust nodes. Poor
operability undermines decentralization (fewer relays/bootstrap peers).

**Independent Test**: Start a node from a config file, confirm a persistent identity is created and reused
across restarts, run the status command to see peers/transports/health as both human-readable and JSON,
and confirm no key material is present in any output.

**Acceptance Scenarios**:

1. **Given** no prior identity, **When** the node first starts, **Then** it generates and persists a
   keypair-derived identity and reuses it on subsequent starts.
2. **Given** a running node, **When** the operator requests status, **Then** they receive peer count,
   active transport(s), reachability, and recent rotation/health events in human and JSON form.
3. **Given** any log level including trace, **When** logs are emitted, **Then** no private keys or session
   secrets appear.

---

### Edge Cases

- **Total egress blackout** (all transports blocked / protocol whitelist-only): the node MUST fail safe,
  keep retrying surviving carriers, and surface a clear "no reachable transport" status rather than
  leaking a distinguishable signature by hammering one blocked protocol. (A local-RF fallback tier is out
  of scope for this feature but the architecture MUST not preclude it.)
- **Volumetric throttle/freeze** (foreign-flow freeze after a packet/byte threshold): bulk transfer MUST
  avoid behaviors that trigger the freeze sooner (e.g. naive multiplexing onto one long connection).
- **Clock skew**: handshakes with bounded timestamp windows MUST tolerate reasonable skew without becoming
  replayable.
- **Adversarial peers**: Sybil/eclipse attempts, spam, and invalid-message floods MUST degrade a misbehaving
  peer's standing and MUST NOT partition or stall honest peers.
- **Untrusted relay/serving peer**: a relay or content-serving peer MUST be unable to read or tamper with
  payloads it forwards (end-to-end authenticity/confidentiality).
- **Stale identity / key rotation**: long-lived identities MUST support session-key rotation so past
  traffic is not exposed by a later key compromise.

## Requirements *(mandatory)*

### Functional Requirements

**Connectivity & censorship resistance**
- **FR-001**: The system MUST establish authenticated, confidential peer links over at least one transport
  that resists passive fully-encrypted/entropy classification (no high-entropy "random" first packets
  without mitigation, no static plaintext protocol header).
- **FR-002**: Every listener MUST implement probe-resistant authentication so an unauthenticated connection
  cannot distinguish the node from a non-participating host (silence or genuine cover response).
- **FR-003**: The system MUST support multiple interchangeable transports behind one pluggable abstraction
  and MUST select defaults by an operator-chosen environment profile (at minimum: Open, Moderate, Aggressive).
- **FR-004**: The system MUST actively health-check transports, detect silent failures, and automatically
  rotate transport/endpoint without user intervention.
- **FR-005**: The system MUST treat UDP/QUIC carriers as opportunistic and automatically fall back to a
  TCP-survivable carrier when UDP is blocked.
- **FR-006**: The system MUST provide a traffic-shaping capability (padding and timing) that is independently
  toggleable from the transport and tunable per profile.

**Security & cryptography**
- **FR-007**: All key agreement MUST be hybrid post-quantum (a classical primitive combined with a
  post-quantum KEM) such that a failure of the post-quantum part alone does not compromise a session.
- **FR-008**: All on-the-wire payloads MUST be authenticated-encrypted; no unauthenticated or cleartext
  application data may be sent.
- **FR-009**: Node identity and all control/gossip messages MUST be signed; recipients MUST reject invalid
  signatures and MUST NOT propagate unsigned/invalid messages.
- **FR-010**: The system MUST provide forward secrecy: per-link ephemeral session keys and support for
  session-key rotation/re-keying.
- **FR-011**: Content MUST be self-certifying: addressable by a cryptographic content identifier that any
  recipient can verify against the received bytes before acceptance.
- **FR-012**: The system MUST reject replays via per-sender monotonic sequencing, a bounded deduplication
  window, and timestamp validation tolerant of bounded clock skew.
- **FR-013**: Secret material MUST never be exposed in logs, errors, serialized cleartext, or telemetry,
  and MUST be zeroized when dropped.

**Decentralization, discovery & NAT**
- **FR-014**: The system MUST operate with no mandatory central server; discovery, relay, and bootstrap
  MUST be peer-providable and substitutable.
- **FR-015**: The system MUST provide peer discovery that is not enumerable via unrelated public networks
  (private namespace) and MUST support authenticated publish/subscribe message dissemination.
- **FR-016**: The system MUST allow NATed/CGNATed peers to participate via relaying, and MUST attempt to
  upgrade to direct connections via coordinated hole punching where NAT types permit.
- **FR-017**: The system MUST detect its own reachability and MAY contribute limited relay capacity when
  publicly reachable.

**Anti-abuse**
- **FR-018**: The system MUST apply peer scoring/reputation that penalizes invalid messages and abusive
  behavior, and MUST resist Sybil/eclipse attempts via identity-derived node IDs plus structural defenses
  (creation friction, lookup diversity, colocation penalties).

**Operability**
- **FR-019**: The system MUST run from a single binary configured by a file and/or CLI flags, generating
  and persisting a stable identity on first run and reusing it thereafter.
- **FR-020**: The system MUST expose node status (peers, active transports, reachability, recent
  rotation/health events) in both human-readable and JSON form, and MUST emit structured logs.

### Key Entities *(include if feature involves data)*

- **Node Identity**: a self-generated long-term signing keypair; the public key derives a stable peer
  identifier. Authenticates the node; never used directly for bulk encryption.
- **Peer**: a remote node known by its identifier, its reachable addresses/transports, capabilities, and a
  locally-computed reputation score.
- **Session / Link**: a live authenticated, forward-secret channel to a peer, bound to a chosen transport
  and shaping policy, with ephemeral keys subject to rotation.
- **Transport Profile**: a named environment hostility level mapping to a transport, fingerprint, and
  shaping configuration.
- **Message**: a signed, authenticated unit carrying topic, payload, sender identity, sequence number, and
  timestamp; identified and integrity-checked by a content identifier.
- **Content Object**: arbitrary data addressed and verified by its cryptographic content identifier.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Across the supported environment profiles against a representative DPI simulation (entropy
  classifier, active prober, SNI inspection, volumetric reset), at least one transport establishes a
  working session in **≥ 95%** of attempts, and an active probe never yields a positive proxy
  identification in the test suite.
- **SC-002**: When the active transport is blocked mid-session, the node detects the failure and restores
  connectivity over an alternate transport in **≤ 10 seconds** in the simulation.
- **SC-003**: Two fresh peers separated by a bootstrap-only topology discover each other and exchange an
  authenticated message in **≤ 5 seconds** on a normal network.
- **SC-004**: **100%** of forged, tampered, or replayed messages are rejected by every honest peer in the
  test suite (zero false accepts).
- **SC-005**: A peer behind a (non-symmetric) NAT becomes reachable via relay in **≤ 5 seconds** and, where
  the NAT type permits, is upgraded to a direct connection; symmetric-NAT peers remain reachable via relay
  for the session's lifetime.
- **SC-006**: An operator can start a node, see its status, and confirm a persistent identity in **≤ 2
  minutes** from a single binary, with **zero** secret material present in any log or status output.
- **SC-007**: All cryptographic and wire-parsing components pass known-answer/property tests and parser
  fuzzing in CI with **zero** known-answer mismatches before any release.

## Assumptions

- Target users run a native node (desktop/server/mobile-capable host); browser-only participation is out of
  scope for this feature.
- "Audited where possible" is accepted: some post-quantum components are not yet independently audited; the
  hybrid design keeps the classical half authoritative to bound that risk (per constitution Principle I).
- A node both dials and accepts connections (every node may act as a peer, and reachable nodes may relay),
  so probe-resistant listener behavior is required on every node, not just dedicated servers.
- The local-RF "total blackout" tier (BLE/Wi-Fi-Aware/LoRa) is out of scope for this feature but the
  transport abstraction MUST NOT preclude adding it later.
- Empirical, in-country DPI survivability cannot be fully proven in a unit/integration suite; success
  criteria are evaluated against a documented DPI **simulation**, with real-world measurement tracked separately.
- Initial bootstrap/relay references are distributed out of band (the secure distribution of bridge
  parameters is acknowledged as a related but separate problem).
