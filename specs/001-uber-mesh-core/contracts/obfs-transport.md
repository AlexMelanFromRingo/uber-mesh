# Contract: `ObfsTransport` abstraction

The load-bearing extensibility point (constitution Principle II). Every concrete carrier implements it; the
dialer selects one by profile. Stateless stream-shaping is a separate composable wrapper.

## Trait (umesh-obfs)

```rust
/// An obfuscated, authenticated byte-stream carrier. Implementations hide any static
/// protocol fingerprint and provide probe-resistant accept().
#[async_trait::async_trait]
pub trait ObfsTransport: Send + Sync + 'static {
    /// Stable kind tag (e.g. "obfs-tcp", "reality", "quic-salamander").
    fn kind(&self) -> &'static str;

    /// Dial `addr`, perform the obfuscated handshake, return a framed secure stream.
    async fn connect(&self, addr: &MeshAddr, params: &ObfsParams) -> Result<ObfsStream, ObfsError>;

    /// Accept one inbound connection. MUST be probe-resistant: an unauthenticated peer
    /// gets cryptographic silence or genuine cover traffic — never a distinguishing reply.
    async fn accept(&self, listener: &mut ObfsListener) -> Result<ObfsStream, ObfsError>;
}

/// AsyncRead + AsyncWrite secure framed stream (AEAD records, no cleartext header).
pub struct ObfsStream { /* … */ }
```

## Guarantees each implementation MUST uphold

1. **No static fingerprint.** No fixed plaintext header, no fixed handshake length, and the first record's
   byte distribution MUST NOT fall in the entropy band flagged by fully-encrypted classifiers (popcount
   mitigation). Verified by the `entropy_band` test. obfs-tcp additionally imitates a specific browser
   (ClientHello JA4 = Chrome 133+, `tests/fingerprint.rs`) and, in cover mode, its cover site's server-flight
   layout (`tests/cover_mimicry.rs`).
2. **Probe resistance.** `accept()` on a connection that fails authentication (including a *replayed*
   authentic first flight) MUST drain/delay and close without a distinguishable response, or transparently
   forward **every byte received** to a cover upstream. A non-protocol opening (e.g. HTTP) MUST be handed to the
   probe response immediately. Verified by `dpi_sim::active_probe_gets_silence`,
   `handshake_security::audit_replayed_client_hello_goes_to_fallback` and `…_http_probe_forwarded_…`.
3. **Authenticated confidentiality.** Post-handshake bytes are AEAD-protected; tampering yields a decrypt error
   and connection close. Verified by `tamper_detected`.
4. **Shaping is external.** Padding/timing shaping is applied by a `Shaper` wrapper around `ObfsStream`, toggled
   by `ShapingPolicy`, not baked into the transport.
5. **Mutual authentication of the carrier.** The dialer MUST verify that the listener holds the PSK (key
   confirmation) before sending any application byte, and vice versa. Verified by
   `handshake_security::audit_mitm_without_psk_is_rejected_by_client`.
6. **Liveness.** Dial MUST be bounded (connect + handshake timeouts) so a silent freeze triggers rotation;
   accept MUST NOT let one slow/silent peer delay others (per-connection handshake tasks, bounded concurrency).
   Verified by `handshake_security::client_timeout_rotates_past_silent_endpoint` and
   `…listener_not_blocked_by_silent_probe`.

## obfs-tcp concrete API (umesh-obfs, obfs wire v2.1)

```rust
// Dial (bounded by ClientConfig::{connect_timeout, handshake_timeout}). SNI = ClientConfig::cover_domain
// (env UMESH_COVER_DOMAIN) — set it to the listener's cover domain; if unset, a per-connection pick from
// ClientConfig::cover_snis (UMESH_SNI) — weaker mimicry.
ObfsTcp::connect(addr, &psk, shaping) -> Result<SecureStream<TcpStream>>
ObfsTcp::connect_with(addr, &psk, shaping, &ClientConfig) -> Result<SecureStream<TcpStream>>
connect_first_working(&[Endpoint], shaping) / connect_first_working_with(.., &ClientConfig)

// Accept — preferred: background accept loop, one task per handshake (cap
// ListenerConfig::max_inflight_handshakes, default 256), sessions delivered over a channel.
let mut l = ObfsListener::bind(addr, psk, shaping, ListenerConfig { probe, .. }).await?;   // or ObfsListener::new(tcp_listener, ..)
// Cover mode (REALITY-style): probes proxied to `upstream`, authenticated flights imitate its learned layout.
let cfg = ListenerConfig::default().with_cover("www.example.com:443", None)?;  // domain defaults to the host
//   = ListenerConfig { probe: ProbeResponse::cover(upstream, Some(domain))?, .. }
//   = ProbeResponse::Cover(CoverSite::spawn(upstream, domain)?)  // learns now + every 30 min ± 5 min
// CoverSite::new(..) (no refresher) + .start(CoverRefresh {..}) / .refresh(timeout).await / .set_profile(p)
let (stream, peer) = l.accept().await?;      // only fully key-confirmed sessions
// Legacy: ObfsTcp::accept(&TcpListener, ..) runs handshakes concurrently within the call (a probe never
// blocks it and is never returned), but abandons handshakes still in flight when it returns.

// Raw handshakes over any AsyncRead+AsyncWrite (used by the libp2p transport)
client_handshake(&mut io, &psk) / client_handshake_with(&mut io, &psk, &ClientConfig)
server_handshake(&mut io, &psk) / server_handshake_probe(&mut io, &psk, &ProbeResponse)
server_handshake_detached(io, &psk, &ProbeResponse)   // ProbeResponse::Cover also selects the flight layout

ObfsPsk::new([u8; 32])   // no public field; Zeroize-on-drop; redacted Debug
```

Wire format: `contracts/handshake-wire.md` (obfs wire v2.1: Chrome 133+ ClientHello, cover-profile server flight).

## ShapingPolicy

```rust
pub struct ShapingPolicy {
    pub pad_to: Option<usize>,     // pad records up to a bucket size
    pub min_pad: usize,            // minimum random padding bytes
    pub max_pad: usize,            // maximum random padding bytes
    pub iat_jitter_ms: u32,        // inter-arrival timing jitter (0 = off)
    pub decoy: bool,               // emit cover traffic when idle
}
```

## Selection by profile

`ProfileSelector::select(profile, udp_available) -> Vec<Box<dyn ObfsTransport>>` returns an ordered preference
list. `Open → [quic, obfs-tcp]`, `Moderate → [obfs-tcp, quic]`, `Aggressive → [obfs-tcp]`, `Shutdown →
[obfs-tcp(local), …future local-RF]`. UDP probe failure removes QUIC at runtime.
