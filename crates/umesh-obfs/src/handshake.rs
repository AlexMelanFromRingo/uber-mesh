//! Obfuscated, probe-resistant, **mutually key-confirmed** handshake riding a Chrome-shaped TLS 1.3
//! handshake (wire format: `specs/001-uber-mesh-core/contracts/handshake-wire.md`, obfs wire v2).
//!
//! ```text
//! C → S  ClientHello (0x16)    Chrome template; X25519MLKEM768 share = ML-KEM-768 ek ‖ X25519;
//!                              session_id = MAC_gate(epoch, whole ClientHello with session_id = 0³²)
//! S → C  ServerHello (0x16)    echoes session_id; suite / group / extension order and therefore
//!                              length as the cover site's (X25519MLKEM768: ML-KEM-768 ct ‖ X25519;
//!                              x25519: X25519 only, ct masked at the start of the encrypted flight)
//!        [ChangeCipherSpec]    14 03 03 00 01 01 — iff the cover site sends one
//!        0x17 record(s)        "encrypted handshake": exactly the cover site's record sizes
//!                              ([`crate::cover::CoverProfile`]; a PSK-derived default layout until one
//!                              is learned); random bodies; the final 53 bytes of the last record
//!                              = AEAD(k_server_confirm, 0¹³, aad = label ‖ transcript). The client
//!                              accepts any layout within ≤ 8 records / ≤ 32 KiB and finds the
//!                              confirmation by trial-opening the tail of each record.
//! C → S  ChangeCipherSpec, 0x17 record (Finished-sized for the suite: 53 B, or 69 B for 1302)
//!                              ending in AEAD(k_client_confirm, 0¹³, aad = label ‖ transcript)
//! C ⇄ S  0x17 application data (SecureStream / ObfsByteStream)
//! ```
//!
//! **Key schedule** (all BLAKE3 `derive_key` with distinct v2 labels, constitution Principle I):
//! `transcript = H(ClientHello ‖ ServerHello)`, `master = KDF(ss ‖ psk_ks ‖ transcript)` where `ss`
//! is the hybrid X25519+ML-KEM-768 secret and `psk_ks = KDF(psk)`; the confirm keys and the two
//! directional traffic keys are separate derivations of `master`. Hence:
//! - a party without the PSK cannot produce the server confirmation, so a **PSK-less MITM is
//!   rejected by the client** before any application byte is sent, and cannot decrypt (the PSK is in
//!   every session key);
//! - the server only returns a session after verifying the client's confirmation (proves `ss` and
//!   PSK knowledge — a replayer of a captured ClientHello cannot complete);
//! - any on-path modification of either hello changes `transcript` and breaks both confirmations.
//!
//! **Probe resistance**: the `session_id` is a keyed MAC (PSK- and epoch-keyed) over the *entire*
//! ClientHello, so all 32 bytes are pseudorandom (no cleartext epoch) and SNI/random/key_share are
//! non-malleable. The server tries epochs `e−1, e, e+1`. A hello that fails the gate, has already
//! been seen (bounded [`ReplayCache`]), or does not look like a ClientHello at all is handed to the
//! [`ProbeResponse`] with **every byte read so far** — silence, or a transparent splice to a real
//! cover site.
//!
//! *Peer identity* (which node) is still established above this layer (signed hello / Noise); this
//! layer authenticates PSK membership of the carrier.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::Rng;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use subtle::{Choice, ConstantTimeEq};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use umesh_crypto::aead::{self, AeadKey, NONCE_LEN, TAG_LEN};
use umesh_crypto::hash::{Hash32, derive_key, keyed_mac};
use umesh_crypto::kem;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cover::{
    CT_IN_FLIGHT_LEN, CoverProfile, CoverSite, MAX_CIPHERTEXT_RECORD, MAX_FLIGHT_BYTES,
    MAX_FLIGHT_RECORDS,
};
use crate::error::{ObfsError, Result};
use crate::tls::{self, ServerGroup, ServerHelloShape};
use crate::wire::{self, HEADER_LEN, HelloRead, MAX_RECORD};

/// Domain-separation labels for every derivation in the v2 obfs handshake. Each use has its own
/// label; none is shared with any other part of uber-mesh (constitution Principle I).
mod label {
    /// PSK → gate MAC key.
    pub const PSK_GATE: &str = "uber-mesh v2 obfs psk gate-key";
    /// PSK → key-schedule input.
    pub const PSK_KEY_SCHEDULE: &str = "uber-mesh v2 obfs psk key-schedule";
    /// PSK → server encrypted-flight shape (public sizes only).
    pub const PSK_FLIGHT_SHAPE: &str = "uber-mesh v2 obfs psk flight-shape";
    /// PSK key-schedule key ‖ H(ClientHello ‖ ServerHello) → mask for an ML-KEM ciphertext carried in
    /// the encrypted flight (server selected plain x25519).
    pub const CT_MASK: &str = "uber-mesh v2 obfs flight kem-ct mask";
    /// Transcript hash over ClientHello ‖ ServerHello.
    pub const TRANSCRIPT: &str = "uber-mesh v2 obfs transcript";
    /// Master secret from ss ‖ psk_ks ‖ transcript.
    pub const MASTER: &str = "uber-mesh v2 obfs master";
    /// Server key-confirmation AEAD key.
    pub const SERVER_CONFIRM: &str = "uber-mesh v2 obfs server confirm";
    /// Client key-confirmation AEAD key.
    pub const CLIENT_CONFIRM: &str = "uber-mesh v2 obfs client confirm";
    /// Client → server traffic key.
    pub const TRAFFIC_C2S: &str = "uber-mesh v2 obfs traffic c2s";
    /// Session channel binding exported to upper layers (not a key).
    pub const CHANNEL_BINDING: &str = "uber-mesh v2 obfs channel binding";
    /// Server → client traffic key.
    pub const TRAFFIC_S2C: &str = "uber-mesh v2 obfs traffic s2c";
    /// Context bound into the gate MAC input.
    pub const GATE_CTX: &[u8] = b"uber-mesh v2 obfs gate";
    /// AAD prefix of the server confirmation.
    pub const SERVER_CONFIRM_AAD: &[u8] = b"uber-mesh v2 obfs server finished";
    /// AAD prefix of the client confirmation.
    pub const CLIENT_CONFIRM_AAD: &[u8] = b"uber-mesh v2 obfs client finished";
}

/// How the server treats a connection that fails the obfs gate (active-probe resistance) — and,
/// for [`ProbeResponse::Cover`], which site its own TLS flight imitates.
#[derive(Clone, Debug, Default)]
pub enum ProbeResponse {
    /// Drain + randomized delay + close, sending no distinguishing reply (obfs4 model).
    #[default]
    Silence,
    /// Reverse-proxy the connection to a real upstream `host:port`, forwarding **every byte already
    /// received**, then relaying both directions until either side closes, so a prober transparently
    /// talks to a genuine site (REALITY/ShadowTLS model). On `:443` this is stronger than silence.
    /// The authenticated server flight keeps the PSK-derived default layout (weaker: it does not
    /// match the upstream's real flight — prefer [`ProbeResponse::Cover`]).
    Fallback(String),
    /// [`ProbeResponse::Fallback`] to the cover site's upstream **plus** cover mimicry: the
    /// authenticated server flight reproduces the record layout learned from that site
    /// ([`CoverSite`]). Clients should send the cover domain as SNI
    /// ([`ClientConfig::cover_domain`]).
    Cover(CoverSite),
}

impl ProbeResponse {
    /// Cover mode for `upstream` (`host:port`) with SNI `domain` (default: the upstream host), with
    /// the default refresh schedule started (learn now, then every 30 min ± 5 min; failures keep the
    /// last good profile). Must be called inside a Tokio runtime.
    pub fn cover(upstream: impl Into<String>, domain: Option<&str>) -> Result<Self> {
        Ok(ProbeResponse::Cover(CoverSite::spawn(upstream, domain)?))
    }

    /// The upstream a failed-gate connection is proxied to, if any.
    fn upstream(&self) -> Option<&str> {
        match self {
            ProbeResponse::Silence => None,
            ProbeResponse::Fallback(u) => Some(u),
            ProbeResponse::Cover(site) => Some(site.upstream()),
        }
    }

    /// The layout of this connection's server flight: the cover site's learned profile, else the
    /// PSK-derived default.
    fn flight_profile(&self, psk: &ObfsPsk) -> Arc<CoverProfile> {
        match self {
            ProbeResponse::Cover(site) => site.profile(),
            _ => None,
        }
        .unwrap_or_else(|| Arc::new(psk.default_profile()))
    }
}

/// Direction tags bound into record AAD (also pick the directional traffic key).
pub(crate) const DIR_C2S: u8 = 0;
pub(crate) const DIR_S2C: u8 = 1;

/// Default bound on each handshake phase (client: whole handshake; server: each flight read).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Default TCP connect timeout for dialers.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for connecting to the fallback (cover) upstream.
const FALLBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard cap on one fallback relay (connect + forward + bidirectional copy). A prober browsing the
/// cover site longer than this is cut off — an acceptable tell versus letting probers pin
/// unbounded resources.
pub const FALLBACK_MAX_DURATION: Duration = Duration::from_secs(90);
/// Process-wide cap on concurrent fallback relays; beyond it a probe gets silence (bounded at
/// ~400 ms) so a probe flood cannot exhaust sockets/tasks or the accept/upgrade slots.
pub const MAX_CONCURRENT_FALLBACKS: usize = 64;
static FALLBACK_SLOTS: LazyLock<std::sync::Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_FALLBACKS)));
/// Hard cap on bytes drained from a rejected/probing connection (DoS bound).
const MAX_DRAIN_BYTES: usize = 64 * 1024;
/// Plaintext length of a key confirmation; sealed = 24 + 13 + 16 = 53 bytes, the size of a real
/// TLS 1.3 Finished record under TLS_AES_128_GCM_SHA256 (32 verify_data + 4 + 1 + 16).
const CONFIRM_PT_LEN: usize = 13;
/// Sealed key-confirmation length (= TLS 1.3 SHA-256 Finished record payload).
pub const CONFIRM_LEN: usize = NONCE_LEN + CONFIRM_PT_LEN + TAG_LEN;
/// Epoch length (seconds) for the gate MAC; the server accepts e−1, e, e+1.
const EPOCH_SECS: u64 = 60;
/// Replay-cache capacity per epoch bucket (only gate-authenticated hellos are inserted).
const REPLAY_CAP_PER_EPOCH: usize = 1 << 16;

/// Default cover SNIs used when neither the config nor `UMESH_SNI` provides a list. Operators SHOULD
/// configure names consistent with their fallback upstream / IP (a name the IP plainly does not
/// serve is itself a weak signal).
pub const DEFAULT_COVER_SNIS: &[&str] = &[
    "www.cloudflare.com",
    "www.microsoft.com",
    "www.apple.com",
    "www.amazon.com",
    "www.mozilla.org",
    "www.bing.com",
];

/// A per-listener pre-shared key (the "bridge secret") that gates the obfs handshake and is mixed
/// into every session key. Zeroized on drop; never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ObfsPsk([u8; 32]);

impl ObfsPsk {
    /// Wrap 32 secret bytes. (The caller should zeroize its own copy.)
    pub fn new(bytes: [u8; 32]) -> Self {
        ObfsPsk(bytes)
    }

    /// PSK-derived key for the session_id gate MAC.
    fn gate_key(&self) -> Zeroizing<Hash32> {
        Zeroizing::new(derive_key(label::PSK_GATE, &self.0))
    }

    /// PSK-derived input to the session key schedule.
    fn key_schedule_key(&self) -> Zeroizing<Hash32> {
        Zeroizing::new(derive_key(label::PSK_KEY_SCHEDULE, &self.0))
    }

    /// Public, PSK-deterministic shape of the server's encrypted flight (record payload sizes).
    fn flight_shape(&self) -> Vec<usize> {
        let s = derive_key(label::PSK_FLIGHT_SHAPE, &self.0);
        // "Certificate" size in [2500, 5000].
        let cert = 2500 + (u16::from_le_bytes([s[1], s[2]]) as usize % 2501);
        if s[0] & 1 == 0 {
            // BoringSSL-style: EE+Cert+CV+Finished coalesced into one record.
            vec![cert]
        } else {
            // OpenSSL-style: EE, Certificate, CertificateVerify, Finished as separate records.
            let ee = CONFIRM_LEN - 13 + (s[3] as usize % 16); // 40..=55
            let cv = if s[4] & 1 == 0 {
                281 // RSA-2048
            } else {
                96 + (s[5] as usize % 16) // ECDSA P-256
            };
            vec![ee, cert - ee - cv - CONFIRM_LEN, cv, CONFIRM_LEN]
        }
    }

    /// The layout used when no cover profile is known: default ServerHello (`1301`,
    /// `X25519MLKEM768`), CCS, and the PSK-derived record sizes (the wire-v2 0.9.0 shape, so 0.9.0
    /// clients interoperate with a server that has no cover profile).
    pub(crate) fn default_profile(&self) -> CoverProfile {
        CoverProfile {
            server_hello: ServerHelloShape::default(),
            ccs: true,
            records: self.flight_shape(),
        }
    }

    /// Mask for an ML-KEM-768 ciphertext carried inside the encrypted flight (PSK holders only, so the
    /// ciphertext's non-uniform byte distribution is not visible to a censor).
    fn ct_mask(&self, transcript0: &Hash32) -> Zeroizing<Vec<u8>> {
        let mut ikm = Zeroizing::new([0u8; 64]);
        ikm[..32].copy_from_slice(&*self.key_schedule_key());
        ikm[32..].copy_from_slice(transcript0);
        let key = Zeroizing::new(derive_key(label::CT_MASK, &*ikm));
        // PRF in counter mode (SP 800-108) over BLAKE3-keyed.
        let mut out = Zeroizing::new(Vec::with_capacity(CT_IN_FLIGHT_LEN + 32));
        let mut i = 0u32;
        while out.len() < CT_IN_FLIGHT_LEN {
            out.extend_from_slice(&keyed_mac(&key, &i.to_le_bytes()));
            i += 1;
        }
        out.truncate(CT_IN_FLIGHT_LEN);
        out
    }
}

fn xor_in_place(buf: &mut [u8], mask: &[u8]) {
    for (b, m) in buf.iter_mut().zip(mask) {
        *b ^= m;
    }
}

impl From<[u8; 32]> for ObfsPsk {
    fn from(bytes: [u8; 32]) -> Self {
        ObfsPsk::new(bytes)
    }
}

impl fmt::Debug for ObfsPsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObfsPsk(<redacted>)")
    }
}

/// Directional AEAD keys + direction tags established by the handshake.
pub struct SessionKeys {
    /// Key for data this side sends.
    pub send: AeadKey,
    /// Key for data this side receives.
    pub recv: AeadKey,
    /// Direction tag for sent records (bound into AAD).
    pub send_dir: u8,
    /// Direction tag for received records (bound into AAD).
    pub recv_dir: u8,
    /// Channel binding: identical on both ends of THIS obfs session and different for every other
    /// session (a separate `derive_key` of the session master). Upper layers sign it to bind an
    /// identity proof to the session — a PSK-holding relay that splices two sessions together gets
    /// two different values and cannot forward a valid proof. Not secret, but not a key either.
    pub channel_binding: [u8; 32],
}

/// Dial-side options: cover domain / cover-SNI list and timeouts.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// The listener's cover domain (its [`CoverSite::domain`]). When set (and a valid DNS name) every
    /// connection sends it as SNI, consistent with the server's cover-mimicking flight and with
    /// what a replayed hello gets from the real site. When `None`, an SNI is picked per connection
    /// from `cover_snis` — mimicry is then weaker: the SNI need not match the site whose flight the
    /// server imitates.
    pub cover_domain: Option<String>,
    /// Cover SNIs used when `cover_domain` is unset; one is chosen uniformly per connection.
    /// Invalid entries are ignored.
    pub cover_snis: Vec<String>,
    /// TCP connect timeout (used by [`crate::ObfsTcp`]).
    pub connect_timeout: Duration,
    /// Bound on the whole client handshake (silent-freeze detection → rotation).
    pub handshake_timeout: Duration,
}

impl Default for ClientConfig {
    /// Cover domain from `UMESH_COVER_DOMAIN` if set; cover SNIs from `UMESH_SNI`
    /// (comma-separated) if set, else [`DEFAULT_COVER_SNIS`]; 10 s timeouts.
    fn default() -> Self {
        let cover_domain = std::env::var("UMESH_COVER_DOMAIN")
            .ok()
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| tls::sni_is_valid(d));
        let from_env: Vec<String> = std::env::var("UMESH_SNI")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| tls::sni_is_valid(s))
                    .collect()
            })
            .unwrap_or_default();
        let cover_snis = if from_env.is_empty() {
            DEFAULT_COVER_SNIS.iter().map(|s| s.to_string()).collect()
        } else {
            from_env
        };
        ClientConfig {
            cover_domain,
            cover_snis,
            connect_timeout: CONNECT_TIMEOUT,
            handshake_timeout: HANDSHAKE_TIMEOUT,
        }
    }
}

impl ClientConfig {
    /// Pick this connection's cover SNI: the cover domain if configured, else one from the list.
    fn pick_sni(&self) -> String {
        if let Some(d) = self
            .cover_domain
            .as_deref()
            .filter(|d| tls::sni_is_valid(d))
        {
            return d.to_string();
        }
        let valid: Vec<&String> = self
            .cover_snis
            .iter()
            .filter(|s| tls::sni_is_valid(s))
            .collect();
        match valid.choose(&mut OsRng) {
            Some(s) => (*s).clone(),
            None => DEFAULT_COVER_SNIS[OsRng.gen_range(0..DEFAULT_COVER_SNIS.len())].to_string(),
        }
    }
}

/// The current gate epoch (`unix_seconds / 60`).
pub fn current_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / EPOCH_SECS)
        .unwrap_or(0)
}

fn timed_out(what: &str) -> ObfsError {
    ObfsError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{what} timed out"),
    ))
}

// ── Gate ─────────────────────────────────────────────────────────────────────────────────────────

/// MAC input: `GATE_CTX ‖ epoch_le(8) ‖ ClientHello-record-with-session_id-zeroed`. Returns `None`
/// if the record is too short to hold a session_id.
fn gate_input(record: &[u8]) -> Option<Vec<u8>> {
    let sid_end = tls::SESSION_ID_OFFSET + tls::SESSION_ID_LEN;
    if record.len() < sid_end {
        return None;
    }
    let mut data = Vec::with_capacity(label::GATE_CTX.len() + 8 + record.len());
    data.extend_from_slice(label::GATE_CTX);
    data.extend_from_slice(&[0u8; 8]);
    data.extend_from_slice(record);
    let off = label::GATE_CTX.len() + 8 + tls::SESSION_ID_OFFSET;
    data[off..off + tls::SESSION_ID_LEN].fill(0);
    Some(data)
}

fn gate_tag(gate_key: &Hash32, data: &mut [u8], epoch: u64) -> Hash32 {
    let ctx = label::GATE_CTX.len();
    data[ctx..ctx + 8].copy_from_slice(&epoch.to_le_bytes());
    keyed_mac(gate_key, data)
}

/// Build a complete, gated ClientHello record: a Chrome-shaped hello (see [`tls`]) whose
/// `session_id` is the gate MAC for `epoch` over the whole record. Randomness comes from `rng`.
pub fn build_gated_client_hello<R: rand::RngCore + ?Sized>(
    rng: &mut R,
    psk: &ObfsPsk,
    epoch: u64,
    hybrid_share: &[u8],
    sni: &str,
) -> Vec<u8> {
    let mut ch = tls::build_client_hello(rng, hybrid_share, sni);
    let mut data = gate_input(&ch).expect("built ClientHello always holds a session_id");
    let tag = gate_tag(&psk.gate_key(), &mut data, epoch);
    ch[tls::SESSION_ID_OFFSET..tls::SESSION_ID_OFFSET + tls::SESSION_ID_LEN].copy_from_slice(&tag);
    ch
}

/// A ClientHello that passed the PSK gate.
#[derive(Clone, Debug)]
pub struct VerifiedHello {
    /// The epoch whose gate key authenticated it.
    pub epoch: u64,
    /// The gate tag (= session_id) — unique per hello; the replay-cache key.
    pub session_id: [u8; 32],
    /// The `X25519MLKEM768` client share.
    pub hybrid_share: Vec<u8>,
}

/// Pure gate check (no replay state): strictly parse `record` as a ClientHello and verify its
/// session_id against the gate MAC for epochs `now−1, now, now+1` in constant time.
pub fn verify_client_hello(psk: &ObfsPsk, record: &[u8], now_epoch: u64) -> Option<VerifiedHello> {
    let info = tls::parse_client_hello(record)?;
    let mut data = gate_input(record)?;
    let key = psk.gate_key();
    let mut ok = Choice::from(0);
    let mut matched = 0u64;
    for epoch in [
        now_epoch.wrapping_sub(1),
        now_epoch,
        now_epoch.wrapping_add(1),
    ] {
        let tag = gate_tag(&key, &mut data, epoch);
        let hit = tag[..].ct_eq(&info.session_id[..]);
        // Branch-free select of the matching epoch.
        let mask = (hit.unwrap_u8() as u64).wrapping_neg();
        matched = (matched & !mask) | (epoch & mask);
        ok |= hit;
    }
    bool::from(ok).then_some(VerifiedHello {
        epoch: matched,
        session_id: info.session_id,
        hybrid_share: info.hybrid_share,
    })
}

/// Bounded replay cache of gate tags, bucketed by epoch. Only gate-authenticated hellos are
/// inserted (so only PSK holders can fill it); buckets older than the ±1-epoch acceptance window
/// are pruned, and a full bucket fails closed (the hello is treated as a probe).
pub struct ReplayCache {
    buckets: VecDeque<(u64, HashSet<[u8; 16]>)>,
    cap_per_epoch: usize,
}

impl ReplayCache {
    /// A cache holding at most `cap_per_epoch` tags per epoch bucket (≤ 4 live buckets).
    pub fn new(cap_per_epoch: usize) -> Self {
        ReplayCache {
            buckets: VecDeque::new(),
            cap_per_epoch,
        }
    }

    /// Record `tag` (from a hello authenticated for `epoch`) at server time `now_epoch`. Returns
    /// `true` if it is fresh (accept), `false` if it is a replay or the bucket is full (reject).
    pub fn check_and_insert(&mut self, epoch: u64, now_epoch: u64, tag: &[u8; 32]) -> bool {
        // Keep buckets that can still match: hello epoch ≥ now−1.
        self.buckets
            .retain(|(e, _)| e.saturating_add(1) >= now_epoch);
        let key: [u8; 16] = tag[..16].try_into().expect("16 ≤ 32");
        if self.buckets.iter().any(|(_, set)| set.contains(&key)) {
            return false;
        }
        let idx = match self.buckets.iter().position(|(e, _)| *e == epoch) {
            Some(i) => i,
            None => {
                if self.buckets.len() >= 4 {
                    return false; // epoch outside any sane window
                }
                self.buckets.push_back((epoch, HashSet::new()));
                self.buckets.len() - 1
            }
        };
        let set = &mut self.buckets[idx].1;
        if set.len() >= self.cap_per_epoch {
            tracing::warn!("obfs replay cache full for current epoch; rejecting hello");
            return false;
        }
        set.insert(key);
        true
    }

    /// Number of tags currently held.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|(_, s)| s.len()).sum()
    }

    /// True if no tags are held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Process-wide replay cache shared by every server handshake (tags are PSK-keyed MACs, so one
/// cache serves all listeners).
static REPLAY_CACHE: LazyLock<Mutex<ReplayCache>> =
    LazyLock::new(|| Mutex::new(ReplayCache::new(REPLAY_CAP_PER_EPOCH)));

/// Full server-side gate: strict parse + MAC verification + replay check against `cache`.
pub fn gate_client_hello(
    psk: &ObfsPsk,
    record: &[u8],
    now_epoch: u64,
    cache: &mut ReplayCache,
) -> Option<VerifiedHello> {
    let v = verify_client_hello(psk, record, now_epoch)?;
    cache
        .check_and_insert(v.epoch, now_epoch, &v.session_id)
        .then_some(v)
}

fn gate_global(psk: &ObfsPsk, record: &[u8]) -> Option<VerifiedHello> {
    let now = current_epoch();
    // MAC work outside the lock; only the cache insert is serialized.
    let v = verify_client_hello(psk, record, now)?;
    let mut cache = REPLAY_CACHE.lock().unwrap_or_else(|p| p.into_inner());
    cache
        .check_and_insert(v.epoch, now, &v.session_id)
        .then_some(v)
}

// ── Key schedule ─────────────────────────────────────────────────────────────────────────────────

/// `H(ClientHello ‖ ServerHello ‖ ct_in_flight)` — both hellos are self-delimiting TLS records;
/// `ct_in_flight` is the (unmasked) ML-KEM-768 ciphertext when the ServerHello selected plain
/// x25519, else empty (so the PQ-ServerHello transcript is exactly v2's `H(CH ‖ SH)`).
fn transcript_hash(client_hello: &[u8], server_hello: &[u8], ct_in_flight: &[u8]) -> Hash32 {
    let mut t = Vec::with_capacity(client_hello.len() + server_hello.len() + ct_in_flight.len());
    t.extend_from_slice(client_hello);
    t.extend_from_slice(server_hello);
    t.extend_from_slice(ct_in_flight);
    derive_key(label::TRANSCRIPT, &t)
}

struct KeySchedule {
    master: Zeroizing<Hash32>,
    transcript: Hash32,
}

impl KeySchedule {
    fn new(ss: &Hash32, psk: &ObfsPsk, transcript: Hash32) -> Self {
        let mut ikm = Zeroizing::new([0u8; 96]);
        ikm[..32].copy_from_slice(ss);
        ikm[32..64].copy_from_slice(&*psk.key_schedule_key());
        ikm[64..].copy_from_slice(&transcript);
        KeySchedule {
            master: Zeroizing::new(derive_key(label::MASTER, &*ikm)),
            transcript,
        }
    }

    fn confirm_aad(&self, prefix: &[u8]) -> Vec<u8> {
        let mut aad = prefix.to_vec();
        aad.extend_from_slice(&self.transcript);
        aad
    }

    fn seal_confirm(&self, key_label: &str, aad_label: &[u8]) -> Vec<u8> {
        let key = AeadKey::derive(key_label, &*self.master);
        aead::seal(&key, &[0u8; CONFIRM_PT_LEN], &self.confirm_aad(aad_label))
    }

    fn open_confirm(&self, key_label: &str, aad_label: &[u8], sealed: &[u8]) -> bool {
        if sealed.len() != CONFIRM_LEN {
            return false;
        }
        let key = AeadKey::derive(key_label, &*self.master);
        matches!(
            aead::open(&key, sealed, &self.confirm_aad(aad_label)),
            Ok(pt) if pt == [0u8; CONFIRM_PT_LEN]
        )
    }

    fn server_confirm(&self) -> Vec<u8> {
        self.seal_confirm(label::SERVER_CONFIRM, label::SERVER_CONFIRM_AAD)
    }
    fn check_server_confirm(&self, sealed: &[u8]) -> bool {
        self.open_confirm(label::SERVER_CONFIRM, label::SERVER_CONFIRM_AAD, sealed)
    }
    fn client_confirm(&self) -> Vec<u8> {
        self.seal_confirm(label::CLIENT_CONFIRM, label::CLIENT_CONFIRM_AAD)
    }
    fn check_client_confirm(&self, sealed: &[u8]) -> bool {
        self.open_confirm(label::CLIENT_CONFIRM, label::CLIENT_CONFIRM_AAD, sealed)
    }

    fn client_keys(&self) -> SessionKeys {
        SessionKeys {
            send: AeadKey::derive(label::TRAFFIC_C2S, &*self.master),
            recv: AeadKey::derive(label::TRAFFIC_S2C, &*self.master),
            send_dir: DIR_C2S,
            recv_dir: DIR_S2C,
            channel_binding: self.channel_binding(),
        }
    }

    fn server_keys(&self) -> SessionKeys {
        SessionKeys {
            send: AeadKey::derive(label::TRAFFIC_S2C, &*self.master),
            recv: AeadKey::derive(label::TRAFFIC_C2S, &*self.master),
            send_dir: DIR_S2C,
            recv_dir: DIR_C2S,
            channel_binding: self.channel_binding(),
        }
    }

    fn channel_binding(&self) -> [u8; 32] {
        derive_key(label::CHANNEL_BINDING, &*self.master)
    }
}

/// Deterministic derivation of the session keys from public transcript pieces + secrets, exposed for
/// the key-schedule known-answer test. Returns `(server_confirm_key, client_confirm_key, c2s, s2c)`
/// fingerprints as `BLAKE3(key)` so no key bytes leave the module.
#[doc(hidden)]
pub fn key_schedule_fingerprint(
    ss: &Hash32,
    psk: &ObfsPsk,
    client_hello: &[u8],
    server_hello: &[u8],
) -> [Hash32; 4] {
    let ks = KeySchedule::new(ss, psk, transcript_hash(client_hello, server_hello, &[]));
    let fp = |l: &str| umesh_crypto::hash::hash(&derive_key(l, &*ks.master));
    [
        fp(label::SERVER_CONFIRM),
        fp(label::CLIENT_CONFIRM),
        fp(label::TRAFFIC_C2S),
        fp(label::TRAFFIC_S2C),
    ]
}

/// The server's encrypted flight after the ServerHello: `[CCS] ‖ 0x17 records` exactly as `profile`
/// lays them out. The record bodies are random except: `ct_masked` (if any) at the start of the
/// concatenated payloads, and `confirm` as the last [`CONFIRM_LEN`] bytes of the last record.
/// `profile` must validate (guaranteed for learned and default profiles).
fn encrypted_flight(profile: &CoverProfile, confirm: &[u8], ct_masked: &[u8]) -> Vec<u8> {
    let total = profile.flight_bytes();
    debug_assert!(profile.validate() && ct_masked.len() + CONFIRM_LEN <= total);
    let mut payload = vec![0u8; total];
    rand::RngCore::fill_bytes(&mut OsRng, &mut payload);
    payload[..ct_masked.len()].copy_from_slice(ct_masked);
    payload[total - CONFIRM_LEN..].copy_from_slice(confirm);
    let mut out = Vec::with_capacity(6 + 5 * profile.records.len() + total);
    if profile.ccs {
        out.extend_from_slice(&tls::CCS_RECORD);
    }
    let mut p = 0;
    for &len in &profile.records {
        out.extend_from_slice(&wire::TLS_PREFIX);
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(&payload[p..p + len]);
        p += len;
    }
    out
}

/// The complete server flight for one connection: ServerHello shaped like `profile`, then the
/// encrypted flight carrying the server confirmation (and, for an x25519 ServerHello, the masked
/// ML-KEM ciphertext). Returns the flight and the session's key schedule.
fn server_flight(
    psk: &ObfsPsk,
    profile: &CoverProfile,
    client_hello: &[u8],
    session_id: &[u8; 32],
    ss: &Hash32,
    resp: &kem::ResponderMessage,
) -> (Vec<u8>, KeySchedule) {
    let shape = &profile.server_hello;
    let (sh, ct_in_flight): (Vec<u8>, &[u8]) = match shape.group {
        ServerGroup::X25519MlKem768 => {
            let mut share = Vec::with_capacity(tls::HYBRID_SERVER_SHARE_LEN);
            share.extend_from_slice(&resp.mlkem_ct);
            share.extend_from_slice(&resp.x25519_pub);
            let sh = tls::build_server_hello_shaped(&mut OsRng, session_id, shape, &share);
            (sh, &[])
        }
        ServerGroup::X25519 => {
            let sh =
                tls::build_server_hello_shaped(&mut OsRng, session_id, shape, &resp.x25519_pub);
            (sh, &resp.mlkem_ct)
        }
    };
    let ks = KeySchedule::new(ss, psk, transcript_hash(client_hello, &sh, ct_in_flight));
    let mut ct_masked = ct_in_flight.to_vec();
    if !ct_masked.is_empty() {
        xor_in_place(
            &mut ct_masked,
            &psk.ct_mask(&transcript_hash(client_hello, &sh, &[])),
        );
    }
    let mut flight = sh;
    flight.extend_from_slice(&encrypted_flight(profile, &ks.server_confirm(), &ct_masked));
    (flight, ks)
}

/// Read one `0x17 03 03` record (bounded by `MAX_RECORD`), returning its payload.
async fn read_appdata_record<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut hdr = [0u8; HEADER_LEN];
    stream.read_exact(&mut hdr).await?;
    read_appdata_body(stream, &hdr, MAX_RECORD).await
}

/// Given a just-read record header, require `17 03 03`, `len ≤ max`, and read the payload.
async fn read_appdata_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    hdr: &[u8; HEADER_LEN],
    max: usize,
) -> Result<Vec<u8>> {
    if hdr[..3] != wire::TLS_PREFIX {
        return Err(ObfsError::AuthFailed);
    }
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > max {
        return Err(ObfsError::RecordTooLarge);
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

async fn expect_ccs<S: AsyncRead + Unpin>(stream: &mut S) -> Result<()> {
    let mut ccs = [0u8; 6];
    stream.read_exact(&mut ccs).await?;
    if ccs != tls::CCS_RECORD {
        return Err(ObfsError::AuthFailed);
    }
    Ok(())
}

// ── Client ───────────────────────────────────────────────────────────────────────────────────────

/// Client side of the handshake with default [`ClientConfig`] (cover SNI rotation, 10 s bound).
pub async fn client_handshake<S>(stream: &mut S, psk: &ObfsPsk) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    client_handshake_with(stream, psk, &ClientConfig::default()).await
}

/// Client side of the handshake. The whole exchange is bounded by `cfg.handshake_timeout`; the
/// server must prove PSK + KEM-secret knowledge (key confirmation) before this returns, and no
/// application byte is ever written before that.
pub async fn client_handshake_with<S>(
    stream: &mut S,
    psk: &ObfsPsk,
    cfg: &ClientConfig,
) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let sni = cfg.pick_sni();
    tokio::time::timeout(
        cfg.handshake_timeout,
        client_handshake_inner(stream, psk, &sni),
    )
    .await
    .map_err(|_| timed_out("obfs client handshake"))?
}

async fn client_handshake_inner<S>(stream: &mut S, psk: &ObfsPsk, sni: &str) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (initiator, init) = kem::Initiator::start();
    let mut share = Vec::with_capacity(tls::HYBRID_CLIENT_SHARE_LEN);
    share.extend_from_slice(&init.mlkem_ek);
    share.extend_from_slice(&init.x25519_pub);
    let ch = build_gated_client_hello(&mut OsRng, psk, current_epoch(), &share, sni);
    stream.write_all(&ch).await?;
    stream.flush().await?;

    // ServerHello: strict parse, exact session_id echo, a TLS 1.3 suite we offered.
    let sh = wire::read_record_raw(stream).await?;
    let info = tls::parse_server_hello(&sh).ok_or(ObfsError::Malformed)?;
    let sid = &ch[tls::SESSION_ID_OFFSET..tls::SESSION_ID_OFFSET + tls::SESSION_ID_LEN];
    if info.session_id[..] != *sid {
        return Err(ObfsError::AuthFailed);
    }
    let mut x = [0u8; kem::X25519_LEN];
    // PQ ServerHello: the KEM finishes now. x25519 ServerHello: the ML-KEM ciphertext is the first
    // 1088 bytes of the encrypted flight (masked), so the KEM finishes once those have arrived.
    let mut initiator = Some(initiator);
    let mut ks = None;
    let mut ct_mask = None;
    match info.shape.group {
        ServerGroup::X25519MlKem768 => {
            let split = kem::MLKEM768_CT_LEN;
            x.copy_from_slice(&info.key_share[split..]);
            let resp = kem::ResponderMessage {
                x25519_pub: x,
                mlkem_ct: info.key_share[..split].to_vec(),
            };
            let ss = initiator.take().expect("set above").finish(&resp)?; // zeroized on drop
            ks = Some(KeySchedule::new(
                ss.expose(),
                psk,
                transcript_hash(&ch, &sh, &[]),
            ));
        }
        ServerGroup::X25519 => {
            x.copy_from_slice(&info.key_share);
            ct_mask = Some(psk.ct_mask(&transcript_hash(&ch, &sh, &[])));
        }
    }

    // Server flight: an optional CCS, then up to MAX_FLIGHT_RECORDS 0x17 records (≤ MAX_FLIGHT_BYTES
    // in total) of ANY sizes — the server imitates its cover site's layout. The confirmation is the
    // tail of the last one: trial-open the last CONFIRM_LEN bytes of each record (≤ 8 AEAD opens).
    let mut flight: Vec<u8> = Vec::new();
    let mut records = 0usize;
    let mut ccs_allowed = true; // only directly after the ServerHello
    let ks = loop {
        let mut hdr = [0u8; HEADER_LEN];
        stream.read_exact(&mut hdr).await?;
        if std::mem::replace(&mut ccs_allowed, false) && hdr == tls::CCS_RECORD[..HEADER_LEN] {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await?;
            if b[0] != tls::CCS_RECORD[HEADER_LEN] {
                return Err(ObfsError::AuthFailed);
            }
            continue;
        }
        let body = read_appdata_body(stream, &hdr, MAX_CIPHERTEXT_RECORD).await?;
        records += 1;
        if flight.len() + body.len() > MAX_FLIGHT_BYTES {
            return Err(ObfsError::AuthFailed);
        }
        flight.extend_from_slice(&body);
        if ks.is_none() && flight.len() >= CT_IN_FLIGHT_LEN {
            let mut ct = flight[..CT_IN_FLIGHT_LEN].to_vec();
            xor_in_place(&mut ct, ct_mask.as_deref().ok_or(ObfsError::Malformed)?);
            let resp = kem::ResponderMessage {
                x25519_pub: x,
                mlkem_ct: ct,
            };
            let init = initiator.take().ok_or(ObfsError::Malformed)?;
            let ss = init.finish(&resp)?;
            ks = Some(KeySchedule::new(
                ss.expose(),
                psk,
                transcript_hash(&ch, &sh, &resp.mlkem_ct),
            ));
        }
        let ct_len = if ct_mask.is_some() {
            CT_IN_FLIGHT_LEN
        } else {
            0
        };
        if let Some(k) = &ks
            && body.len() >= CONFIRM_LEN
            && flight.len() >= ct_len + CONFIRM_LEN
            && k.check_server_confirm(&flight[flight.len() - CONFIRM_LEN..])
        {
            break ks.take().expect("checked");
        }
        if records >= MAX_FLIGHT_RECORDS {
            // Bound reached without a confirmation: not our server (or a MITM) — fail closed,
            // having sent nothing after the ClientHello.
            return Err(ObfsError::AuthFailed);
        }
    };

    // Our CCS + Finished-sized record (53 B, or 69 B under the SHA-384 suite) ending in the client
    // confirmation, then the session is live.
    let fin_len = tls::finished_record_len(info.shape.cipher_suite);
    let mut out = Vec::with_capacity(6 + HEADER_LEN + fin_len);
    out.extend_from_slice(&tls::CCS_RECORD);
    out.extend_from_slice(&wire::TLS_PREFIX);
    out.extend_from_slice(&(fin_len as u16).to_be_bytes());
    let mut pad = vec![0u8; fin_len - CONFIRM_LEN];
    rand::RngCore::fill_bytes(&mut OsRng, &mut pad);
    out.extend_from_slice(&pad);
    out.extend_from_slice(&ks.client_confirm());
    stream.write_all(&out).await?;
    stream.flush().await?;
    Ok(ks.client_keys())
}

// ── Server ───────────────────────────────────────────────────────────────────────────────────────

/// Result of the server handshake before any probe response is run.
pub(crate) enum ServerOutcome {
    /// Mutually key-confirmed session.
    Accepted(SessionKeys),
    /// Not (or not provably) a fresh uber-mesh client and **nothing has been sent yet**: run the
    /// probe response over the stream, forwarding these already-read bytes.
    Probe(Vec<u8>),
    /// Failed after our ServerHello flight was sent (bad client confirmation, timeout, I/O).
    Failed(ObfsError),
}

/// Server handshake up to (but excluding) the probe response. `probe` also selects the flight
/// layout (the cover site's learned profile for [`ProbeResponse::Cover`]).
pub(crate) async fn server_handshake_core<S>(
    stream: &mut S,
    psk: &ObfsPsk,
    probe: &ProbeResponse,
) -> ServerOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (ch, status) =
        wire::read_client_hello_record(stream, Instant::now() + HANDSHAKE_TIMEOUT).await;
    if status != HelloRead::Complete {
        return ServerOutcome::Probe(ch);
    }
    // Strict parse + gate + replay check; every failure is a probe (no reply sent yet).
    let Some(hello) = gate_global(psk, &ch) else {
        return ServerOutcome::Probe(ch);
    };
    let split = kem::MLKEM768_EK_LEN;
    let mut x = [0u8; kem::X25519_LEN];
    x.copy_from_slice(&hello.hybrid_share[split..]);
    let init = kem::InitiatorMessage {
        x25519_pub: x,
        mlkem_ek: hello.hybrid_share[..split].to_vec(),
    };
    let Ok((ss, resp)) = kem::respond(&init) else {
        return ServerOutcome::Probe(ch);
    };

    let profile = probe.flight_profile(psk);
    let (flight, ks) = server_flight(psk, &profile, &ch, &hello.session_id, ss.expose(), &resp);
    let fin_len = tls::finished_record_len(profile.server_hello.cipher_suite);
    let confirmed = async {
        stream.write_all(&flight).await?;
        stream.flush().await?;
        expect_ccs(stream).await?;
        let fin = read_appdata_record(stream).await?;
        if fin.len() == fin_len && ks.check_client_confirm(&fin[fin_len - CONFIRM_LEN..]) {
            Ok(())
        } else {
            Err(ObfsError::AuthFailed)
        }
    };
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, confirmed).await {
        Ok(Ok(())) => ServerOutcome::Accepted(ks.server_keys()),
        Ok(Err(e)) => ServerOutcome::Failed(e),
        Err(_) => ServerOutcome::Failed(timed_out("obfs client confirmation")),
    }
}

/// Drain and discard input (bounded by time and byte count), sending no distinguishing reply.
async fn silence<S>(stream: &mut S)
where
    S: AsyncRead + Unpin,
{
    let delay_ms = OsRng.gen_range(50..400u64);
    let _ = tokio::time::timeout(Duration::from_millis(delay_ms), async {
        let mut buf = [0u8; 1024];
        let mut drained = 0usize;
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    drained += n;
                    if drained >= MAX_DRAIN_BYTES {
                        break;
                    }
                }
            }
        }
    })
    .await;
}

/// Run the configured probe response, forwarding `prefix` (every byte already read) to the cover
/// upstream and splicing both directions until either side closes.
pub(crate) async fn handle_probe<S>(stream: &mut S, prefix: &[u8], probe: &ProbeResponse)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match probe.upstream() {
        None => silence(stream).await,
        Some(upstream) => {
            // Bounded: at most MAX_CONCURRENT_FALLBACKS relays, each at most FALLBACK_MAX_DURATION.
            let Ok(_slot) = FALLBACK_SLOTS.clone().try_acquire_owned() else {
                return silence(stream).await;
            };
            let relay = async {
                match tokio::time::timeout(FALLBACK_CONNECT_TIMEOUT, TcpStream::connect(upstream))
                    .await
                {
                    Ok(Ok(mut up)) => {
                        let _ = up.set_nodelay(true);
                        if up.write_all(prefix).await.is_ok() {
                            let _ = tokio::io::copy_bidirectional(stream, &mut up).await;
                        }
                        true
                    }
                    _ => false,
                }
            };
            match tokio::time::timeout(FALLBACK_MAX_DURATION, relay).await {
                Ok(true) | Err(_) => {}
                // Upstream unreachable ⇒ silence rather than a distinguishing error.
                Ok(false) => silence(stream).await,
            }
        }
    }
}

/// Like [`server_handshake_probe`], but takes ownership of the stream and runs the probe response
/// in a detached task, returning `AuthFailed` immediately. Use this where the caller holds a scarce
/// slot for the duration of the handshake (libp2p's pending-incoming connection cap): a fallback
/// relay to the cover site can last up to [`FALLBACK_MAX_DURATION`] and must not occupy that slot.
pub async fn server_handshake_detached<S>(
    mut stream: S,
    psk: &ObfsPsk,
    probe: &ProbeResponse,
) -> Result<(S, SessionKeys)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match server_handshake_core(&mut stream, psk, probe).await {
        ServerOutcome::Accepted(keys) => Ok((stream, keys)),
        ServerOutcome::Probe(prefix) => {
            let probe = probe.clone();
            tokio::spawn(async move { handle_probe(&mut stream, &prefix, &probe).await });
            Err(ObfsError::AuthFailed)
        }
        ServerOutcome::Failed(e) => Err(e),
    }
}

/// Server side of the handshake, defaulting to silent probe rejection.
pub async fn server_handshake<S>(stream: &mut S, psk: &ObfsPsk) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    server_handshake_probe(stream, psk, &ProbeResponse::Silence).await
}

/// Server side of the handshake with an explicit probe-response policy. Anything that is not a
/// fresh, gate-authenticated ClientHello (non-TLS bytes, implausible record, no/wrong PSK, stale
/// epoch, replay) gets `probe` (silence or fallback-proxy) and [`ObfsError::AuthFailed`]. A client
/// that passes the gate but fails key confirmation gets the connection closed.
pub async fn server_handshake_probe<S>(
    stream: &mut S,
    psk: &ObfsPsk,
    probe: &ProbeResponse,
) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match server_handshake_core(stream, psk, probe).await {
        ServerOutcome::Accepted(keys) => Ok(keys),
        ServerOutcome::Probe(prefix) => {
            handle_probe(stream, &prefix, probe).await;
            Err(ObfsError::AuthFailed)
        }
        ServerOutcome::Failed(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn share() -> Vec<u8> {
        (0..tls::HYBRID_CLIENT_SHARE_LEN).map(|i| i as u8).collect()
    }

    #[tokio::test]
    async fn handshake_agrees_over_duplex() {
        let psk = ObfsPsk::new([9u8; 32]);
        let (mut c, mut s) = tokio::io::duplex(64 * 1024);
        let psk2 = psk.clone();
        let server = tokio::spawn(async move {
            let k = server_handshake(&mut s, &psk2).await.unwrap();
            (k, s)
        });
        let ck = client_handshake(&mut c, &psk).await.unwrap();
        let (sk, _s) = server.await.unwrap();
        // Directional keys line up: client.send == server.recv and vice versa.
        let w = aead::seal(&ck.send, b"x", b"");
        assert_eq!(aead::open(&sk.recv, &w, b"").unwrap(), b"x");
        let w = aead::seal(&sk.send, b"y", b"");
        assert_eq!(aead::open(&ck.recv, &w, b"").unwrap(), b"y");
        assert!(aead::open(&ck.send, &w, b"").is_err());
    }

    #[tokio::test]
    async fn wrong_psk_fails_auth() {
        let (mut c, mut s) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            server_handshake(&mut s, &ObfsPsk::new([1u8; 32]))
                .await
                .map(|_| ())
        });
        let cfg = ClientConfig {
            handshake_timeout: Duration::from_secs(3),
            ..ClientConfig::default()
        };
        let client = client_handshake_with(&mut c, &ObfsPsk::new([2u8; 32]), &cfg).await;
        assert!(matches!(server.await.unwrap(), Err(ObfsError::AuthFailed)));
        assert!(client.is_err());
    }

    /// A forged server that even reproduces the exact PSK-derived flight shape, but runs the key
    /// schedule without the PSK, is rejected purely by the key-confirmation check.
    #[tokio::test]
    async fn shape_perfect_forgery_without_psk_is_rejected() {
        let psk = ObfsPsk::new([0x31; 32]);
        let (mut c, mut m) = tokio::io::duplex(64 * 1024);
        let psk_shape = psk.clone();
        let mitm = tokio::spawn(async move {
            let ch = wire::read_record_raw(&mut m).await.unwrap();
            let info = tls::parse_client_hello(&ch).unwrap();
            let mut x = [0u8; 32];
            x.copy_from_slice(&info.hybrid_share[1184..]);
            let (ss, resp) = kem::respond(&kem::InitiatorMessage {
                x25519_pub: x,
                mlkem_ek: info.hybrid_share[..1184].to_vec(),
            })
            .unwrap();
            let mut share = resp.mlkem_ct.clone();
            share.extend_from_slice(&resp.x25519_pub);
            let sh = tls::build_server_hello(&mut OsRng, &info.session_id, &share);
            let wrong = ObfsPsk::new([0x32; 32]);
            let ks = KeySchedule::new(ss.expose(), &wrong, transcript_hash(&ch, &sh, &[]));
            let mut flight = sh;
            flight.extend_from_slice(&encrypted_flight(
                &psk_shape.default_profile(),
                &ks.server_confirm(),
                &[],
            ));
            m.write_all(&flight).await.unwrap();
            let mut rest = Vec::new();
            let _ =
                tokio::time::timeout(Duration::from_millis(300), m.read_to_end(&mut rest)).await;
            rest
        });
        // The client never finds a confirmation; it fails when the forger goes quiet and closes.
        let r = client_handshake(&mut c, &psk).await;
        assert!(r.is_err());
        drop(c);
        assert!(
            mitm.await.unwrap().is_empty(),
            "nothing sent after the ClientHello"
        );
    }

    fn profile(
        group: ServerGroup,
        cipher_suite: u16,
        ccs: bool,
        records: &[usize],
    ) -> CoverProfile {
        CoverProfile {
            server_hello: ServerHelloShape {
                cipher_suite,
                group,
                key_share_first: cipher_suite == 0x1303,
            },
            ccs,
            records: records.to_vec(),
        }
    }

    fn cover_with(p: &CoverProfile) -> ProbeResponse {
        let site = CoverSite::new("127.0.0.1:9", Some("www.example.com")).unwrap();
        assert!(site.set_profile(p.clone()), "{p:?}");
        ProbeResponse::Cover(site)
    }

    /// Record layout of `bytes` as `(content_type, payload_len)` pairs.
    fn layout(bytes: &[u8]) -> Vec<(u8, usize)> {
        let mut out = Vec::new();
        let mut p = 0;
        while p + 5 <= bytes.len() {
            let len = u16::from_be_bytes([bytes[p + 3], bytes[p + 4]]) as usize;
            out.push((bytes[p], len));
            p += 5 + len;
        }
        out
    }

    /// Duplex handshake through a tap; returns (client keys ok, server→client bytes, c→s bytes).
    async fn tapped_handshake(psk: &ObfsPsk, probe: ProbeResponse) -> (Vec<u8>, Vec<u8>) {
        let (mut c, mut tc) = tokio::io::duplex(128 * 1024);
        let (mut ts, mut s) = tokio::io::duplex(128 * 1024);
        let psk2 = psk.clone();
        let server =
            tokio::spawn(
                async move { server_handshake_probe(&mut s, &psk2, &probe).await.unwrap() },
            );
        let tap = tokio::spawn(async move {
            let (mut s2c, mut c2s) = (Vec::new(), Vec::new());
            let (mut cr, mut cw) = tokio::io::split(&mut tc);
            let (mut sr, mut sw) = tokio::io::split(&mut ts);
            let up = async {
                let mut b = [0u8; 4096];
                while let Ok(n) = cr.read(&mut b).await {
                    if n == 0 {
                        break;
                    }
                    c2s.extend_from_slice(&b[..n]);
                    sw.write_all(&b[..n]).await.unwrap();
                }
            };
            let down = async {
                let mut b = [0u8; 4096];
                while let Ok(n) = sr.read(&mut b).await {
                    if n == 0 {
                        break;
                    }
                    s2c.extend_from_slice(&b[..n]);
                    cw.write_all(&b[..n]).await.unwrap();
                }
            };
            let _ =
                tokio::time::timeout(Duration::from_millis(500), async { tokio::join!(up, down) })
                    .await;
            (s2c, c2s)
        });
        let ck = client_handshake(&mut c, psk).await.unwrap();
        let sk = server.await.unwrap();
        let w = aead::seal(&ck.send, b"x", b"");
        assert_eq!(aead::open(&sk.recv, &w, b"").unwrap(), b"x");
        assert_eq!(ck.channel_binding, sk.channel_binding);
        drop(c);
        tap.await.unwrap()
    }

    /// The server reproduces each profile's layout exactly, and the client (which knows nothing of
    /// the profile) accepts every one of them.
    #[tokio::test]
    async fn server_replicates_profile_and_client_accepts_varied_layouts() {
        let psk = ObfsPsk::new([0x44; 32]);
        let cases = [
            profile(ServerGroup::X25519MlKem768, 0x1301, true, &[3561]),
            profile(
                ServerGroup::X25519MlKem768,
                0x1303,
                false,
                &[23, 4100, 79, 53],
            ),
            profile(ServerGroup::X25519, 0x1302, true, &[36, 2875, 281, 69]),
            profile(ServerGroup::X25519, 0x1301, false, &[1088, 53]),
            profile(
                ServerGroup::X25519,
                0x1301,
                true,
                &[200, 200, 200, 200, 200, 200, 200, 300],
            ),
            profile(
                ServerGroup::X25519MlKem768,
                0x1302,
                true,
                &[16401, 9000, 69],
            ),
            profile(ServerGroup::X25519MlKem768, 0x1301, true, &[53]),
        ];
        for p in cases {
            let (s2c, c2s) = tapped_handshake(&psk, cover_with(&p)).await;
            let mut want = vec![(0x16u8, p.server_hello_len() - 5)];
            if p.ccs {
                want.push((0x14, 1));
            }
            want.extend(p.records.iter().map(|&l| (0x17u8, l)));
            assert_eq!(layout(&s2c), want, "{p:?}");
            let sh_len = p.server_hello_len();
            assert_eq!(
                tls::parse_server_hello(&s2c[..sh_len]).unwrap().shape,
                p.server_hello
            );
            // Client: ClientHello, CCS, Finished-sized record for the suite.
            let c = layout(&c2s);
            assert_eq!(c[1], (0x14, 1));
            assert_eq!(
                c[2],
                (0x17, tls::finished_record_len(p.server_hello.cipher_suite))
            );
        }
    }

    /// Without a learned profile, a Cover server falls back to the PSK default layout (= v2 shape).
    #[tokio::test]
    async fn cover_without_profile_uses_psk_default_layout() {
        let psk = ObfsPsk::new([0x45; 32]);
        let site = CoverSite::new("127.0.0.1:9", Some("www.example.com")).unwrap();
        let (s2c, _) = tapped_handshake(&psk, ProbeResponse::Cover(site)).await;
        let d = psk.default_profile();
        let got: Vec<usize> = layout(&s2c).iter().skip(2).map(|r| r.1).collect();
        assert_eq!(got, d.records);
        assert_eq!(layout(&s2c)[0].1 + 5, d.server_hello_len());
    }

    /// A server that knows the PSK but violates the client's bounds is rejected, and so is a flight
    /// whose confirmation is corrupted. Nothing is sent after the ClientHello in any case.
    #[tokio::test]
    async fn client_rejects_unconfirmed_or_oversized_flights() {
        let psk = ObfsPsk::new([0x46; 32]);
        // (records, corrupt confirmation)
        let cases: [(Vec<usize>, bool); 4] = [
            (vec![300; 9], false),             // confirmation only in a 9th record
            (vec![16000, 16000, 1500], false), // > 32 KiB before the confirmation
            (vec![3000], true),                // right size, wrong confirmation
            (vec![500; 8], true),              // 8 records, none opens
        ];
        for (records, corrupt) in cases {
            let (mut c, mut m) = tokio::io::duplex(128 * 1024);
            let psk2 = psk.clone();
            let recs = records.clone();
            let srv = tokio::spawn(async move {
                let ch = wire::read_record_raw(&mut m).await.unwrap();
                let hello = verify_client_hello(&psk2, &ch, current_epoch()).unwrap();
                let mut x = [0u8; 32];
                x.copy_from_slice(&hello.hybrid_share[1184..]);
                let (ss, resp) = kem::respond(&kem::InitiatorMessage {
                    x25519_pub: x,
                    mlkem_ek: hello.hybrid_share[..1184].to_vec(),
                })
                .unwrap();
                let mut share = resp.mlkem_ct.clone();
                share.extend_from_slice(&resp.x25519_pub);
                let sh = tls::build_server_hello(&mut OsRng, &hello.session_id, &share);
                let ks = KeySchedule::new(ss.expose(), &psk2, transcript_hash(&ch, &sh, &[]));
                let mut confirm = ks.server_confirm();
                if corrupt {
                    confirm[30] ^= 1;
                }
                let mut flight = sh;
                flight.extend_from_slice(&tls::CCS_RECORD);
                let n = recs.len();
                for (i, &l) in recs.iter().enumerate() {
                    flight.extend_from_slice(&wire::TLS_PREFIX);
                    flight.extend_from_slice(&(l as u16).to_be_bytes());
                    let mut body = vec![0x5a; l];
                    if i + 1 == n {
                        body[l - CONFIRM_LEN..].copy_from_slice(&confirm);
                    }
                    flight.extend_from_slice(&body);
                }
                let _ = m.write_all(&flight).await;
                let mut rest = Vec::new();
                let _ = tokio::time::timeout(Duration::from_millis(300), m.read_to_end(&mut rest))
                    .await;
                rest
            });
            let r = client_handshake(&mut c, &psk).await;
            assert!(r.is_err(), "{records:?} corrupt={corrupt}");
            drop(c);
            assert!(
                srv.await.unwrap().is_empty(),
                "nothing sent after the ClientHello"
            );
        }
    }

    #[test]
    fn default_profile_is_valid_and_v2_shaped() {
        for i in 0..64u8 {
            let psk = ObfsPsk::new([i; 32]);
            let p = psk.default_profile();
            assert!(p.validate());
            assert_eq!(p.records, psk.flight_shape());
            assert_eq!(p.server_hello, ServerHelloShape::default());
            assert!(p.ccs);
        }
    }

    #[test]
    fn gate_authenticates_whole_hello_with_psk() {
        let psk = ObfsPsk::new([5u8; 32]);
        let epoch = 1_000_000;
        let ch = build_gated_client_hello(&mut OsRng, &psk, epoch, &share(), "a.example");
        for now in [epoch - 1, epoch, epoch + 1] {
            assert_eq!(verify_client_hello(&psk, &ch, now).unwrap().epoch, epoch);
        }
        assert!(verify_client_hello(&psk, &ch, epoch + 2).is_none(), "stale");
        assert!(
            verify_client_hello(&psk, &ch, epoch - 2).is_none(),
            "future"
        );
        assert!(verify_client_hello(&ObfsPsk::new([6u8; 32]), &ch, epoch).is_none());
        // Flipping ANY byte outside the session_id (random, SNI, key_share, GREASE, …) breaks it.
        for pos in (0..ch.len()).step_by(7) {
            if (tls::SESSION_ID_OFFSET..tls::SESSION_ID_OFFSET + 32).contains(&pos) {
                continue;
            }
            let mut m = ch.clone();
            m[pos] ^= 0x01;
            assert!(verify_client_hello(&psk, &m, epoch).is_none(), "pos {pos}");
        }
    }

    #[test]
    fn replay_cache_is_bounded_and_windowed() {
        let mut c = ReplayCache::new(2);
        let t = |b: u8| [b; 32];
        assert!(c.check_and_insert(10, 10, &t(1)));
        assert!(!c.check_and_insert(10, 10, &t(1)), "replay");
        assert!(!c.check_and_insert(9, 10, &t(1)), "replay across buckets");
        assert!(c.check_and_insert(10, 10, &t(2)));
        assert!(
            !c.check_and_insert(10, 10, &t(3)),
            "bucket full ⇒ fail closed"
        );
        assert!(c.check_and_insert(11, 10, &t(3)));
        // Moving time forward prunes buckets that can no longer validate.
        assert!(c.check_and_insert(13, 13, &t(4)));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn flight_shape_is_plausible() {
        for i in 0..64u8 {
            let shape = ObfsPsk::new([i; 32]).flight_shape();
            let total: usize = shape.iter().sum();
            assert!((2500..=5000).contains(&total), "{shape:?}");
            assert!(*shape.last().unwrap() >= CONFIRM_LEN);
            assert!(shape.iter().all(|l| (40..=MAX_RECORD).contains(l)));
        }
    }

    #[test]
    fn psk_debug_is_redacted() {
        let s = format!("{:?}", ObfsPsk::new([0xAB; 32]));
        assert!(
            !s.contains("171") && !s.to_lowercase().contains("ab"),
            "{s}"
        );
    }

    #[test]
    fn deterministic_hello_kat() {
        // Same seed + inputs ⇒ byte-identical record (pins the template; see tests/ for the hash).
        let psk = ObfsPsk::new([7u8; 32]);
        let a = build_gated_client_hello(&mut StdRng::seed_from_u64(42), &psk, 7, &share(), "a.b");
        let b = build_gated_client_hello(&mut StdRng::seed_from_u64(42), &psk, 7, &share(), "a.b");
        assert_eq!(a, b);
    }
}
