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
   mitigation). Verified by the `entropy_band` test.
2. **Probe resistance.** `accept()` on a connection that fails authentication MUST drain/delay and close
   without a distinguishable response. Verified by the `active_probe` test (a probe sees the same behavior as a
   non-mesh service).
3. **Authenticated confidentiality.** Post-handshake bytes are AEAD-protected; tampering yields a decrypt error
   and connection close. Verified by `tamper_detected`.
4. **Shaping is external.** Padding/timing shaping is applied by a `Shaper` wrapper around `ObfsStream`, toggled
   by `ShapingPolicy`, not baked into the transport.

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
