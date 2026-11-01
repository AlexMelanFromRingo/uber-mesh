//! Obfuscated, probe-resistant, **mutually key-confirmed** handshake riding a Chrome-shaped TLS 1.3
//! handshake (wire format: `specs/001-uber-mesh-core/contracts/handshake-wire.md`, obfs wire v2).
//!
//! ```text
//! C → S  ClientHello (0x16)    Chrome template; X25519MLKEM768 share = ML-KEM-768 ek ‖ X25519;
//!                              session_id = MAC_gate(epoch, whole ClientHello with session_id = 0³²)
//! S → C  ServerHello (0x16)    echoes session_id; X25519MLKEM768 share = ML-KEM-768 ct ‖ X25519
//!        ChangeCipherSpec      14 03 03 00 01 01
//!        0x17 record(s)        "encrypted handshake", 1 or 4 records, 2500–5000 B in total (shape is
//!                              a public function of the PSK, so the client checks it exactly); the
//!                              final 53 bytes = AEAD(k_server_confirm, 0¹³, aad = label ‖ transcript)
//! C → S  ChangeCipherSpec, 0x17 record (53 B, Finished-sized)
//!                              = AEAD(k_client_confirm, 0¹³, aad = label ‖ transcript)
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
use std::sync::{LazyLock, Mutex};
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

use crate::error::{ObfsError, Result};
use crate::tls;
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

/// How the server treats a connection that fails the obfs gate (active-probe resistance).
#[derive(Clone, Debug, Default)]
pub enum ProbeResponse {
    /// Drain + randomized delay + close, sending no distinguishing reply (obfs4 model).
    #[default]
    Silence,
    /// Reverse-proxy the connection to a real upstream `host:port`, forwarding **every byte already
    /// received**, then relaying both directions until either side closes, so a prober transparently
    /// talks to a genuine site (REALITY/ShadowTLS model). On `:443` this is stronger than silence.
    Fallback(String),
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

/// Dial-side options: cover-SNI list and timeouts.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Cover SNIs; one is chosen uniformly per connection. Invalid entries are ignored.
    pub cover_snis: Vec<String>,
    /// TCP connect timeout (used by [`crate::ObfsTcp`]).
    pub connect_timeout: Duration,
    /// Bound on the whole client handshake (silent-freeze detection → rotation).
    pub handshake_timeout: Duration,
}

impl Default for ClientConfig {
    /// Cover SNIs from `UMESH_SNI` (comma-separated) if set, else [`DEFAULT_COVER_SNIS`];
    /// 10 s timeouts.
    fn default() -> Self {
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
            cover_snis,
            connect_timeout: CONNECT_TIMEOUT,
            handshake_timeout: HANDSHAKE_TIMEOUT,
        }
    }
}

impl ClientConfig {
    /// Pick this connection's cover SNI.
    fn pick_sni(&self) -> String {
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

/// `H(ClientHello ‖ ServerHello)` — both are self-delimiting TLS records.
fn transcript_hash(client_hello: &[u8], server_hello: &[u8]) -> Hash32 {
    let mut t = Vec::with_capacity(client_hello.len() + server_hello.len());
    t.extend_from_slice(client_hello);
    t.extend_from_slice(server_hello);
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
    let ks = KeySchedule::new(ss, psk, transcript_hash(client_hello, server_hello));
    let fp = |l: &str| umesh_crypto::hash::hash(&derive_key(l, &*ks.master));
    [
        fp(label::SERVER_CONFIRM),
        fp(label::CLIENT_CONFIRM),
        fp(label::TRAFFIC_C2S),
        fp(label::TRAFFIC_S2C),
    ]
}

/// The server's second-half flight: `CCS ‖ 0x17 records` sized per the PSK's flight shape, with the
/// sealed server confirmation as the last [`CONFIRM_LEN`] bytes of the last record.
fn server_encrypted_flight(psk: &ObfsPsk, ks: &KeySchedule) -> Vec<u8> {
    let shape = psk.flight_shape();
    let confirm = ks.server_confirm();
    let mut out = tls::CCS_RECORD.to_vec();
    for (i, &len) in shape.iter().enumerate() {
        let mut body = vec![0u8; len];
        rand::RngCore::fill_bytes(&mut OsRng, &mut body);
        if i + 1 == shape.len() {
            body[len - CONFIRM_LEN..].copy_from_slice(&confirm);
        }
        out.extend_from_slice(&wire::TLS_PREFIX);
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(&body);
    }
    out
}

/// Read one `0x17 03 03` record (bounded by `MAX_RECORD`), returning its payload.
async fn read_appdata_record<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut hdr = [0u8; HEADER_LEN];
    stream.read_exact(&mut hdr).await?;
    if hdr[..3] != wire::TLS_PREFIX {
        return Err(ObfsError::AuthFailed);
    }
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > MAX_RECORD {
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

    // ServerHello: strict parse, exact session_id echo, our only acceptable suite.
    let sh = wire::read_record_raw(stream).await?;
    let info = tls::parse_server_hello(&sh).ok_or(ObfsError::Malformed)?;
    let sid = &ch[tls::SESSION_ID_OFFSET..tls::SESSION_ID_OFFSET + tls::SESSION_ID_LEN];
    if info.session_id[..] != *sid || info.cipher_suite != tls::SELECTED_CIPHER {
        return Err(ObfsError::AuthFailed);
    }
    let split = kem::MLKEM768_CT_LEN;
    let mut x = [0u8; kem::X25519_LEN];
    x.copy_from_slice(&info.hybrid_share[split..]);
    let resp = kem::ResponderMessage {
        x25519_pub: x,
        mlkem_ct: info.hybrid_share[..split].to_vec(),
    };
    let ss = initiator.finish(&resp)?; // SharedSecret: zeroized on drop
    let ks = KeySchedule::new(ss.expose(), psk, transcript_hash(&ch, &sh));

    // Server flight: CCS, then exactly the PSK-determined "encrypted handshake" records; the last
    // CONFIRM_LEN bytes of the last record must open under the server confirmation key.
    expect_ccs(stream).await?;
    let shape = psk.flight_shape();
    let mut last = Vec::new();
    for &len in &shape {
        last = read_appdata_record(stream).await?;
        if last.len() != len {
            return Err(ObfsError::AuthFailed);
        }
    }
    if last.len() < CONFIRM_LEN || !ks.check_server_confirm(&last[last.len() - CONFIRM_LEN..]) {
        return Err(ObfsError::AuthFailed);
    }

    // Our CCS + Finished-sized confirmation, then the session is live.
    let confirm = ks.client_confirm();
    let mut out = Vec::with_capacity(6 + HEADER_LEN + CONFIRM_LEN);
    out.extend_from_slice(&tls::CCS_RECORD);
    out.extend_from_slice(&wire::TLS_PREFIX);
    out.extend_from_slice(&(CONFIRM_LEN as u16).to_be_bytes());
    out.extend_from_slice(&confirm);
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

/// Server handshake up to (but excluding) the probe response.
pub(crate) async fn server_handshake_core<S>(stream: &mut S, psk: &ObfsPsk) -> ServerOutcome
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

    let mut server_share = Vec::with_capacity(tls::HYBRID_SERVER_SHARE_LEN);
    server_share.extend_from_slice(&resp.mlkem_ct);
    server_share.extend_from_slice(&resp.x25519_pub);
    let sh = tls::build_server_hello(&mut OsRng, &hello.session_id, &server_share);
    let ks = KeySchedule::new(ss.expose(), psk, transcript_hash(&ch, &sh));

    let mut flight = sh;
    flight.extend_from_slice(&server_encrypted_flight(psk, &ks));
    let confirmed = async {
        stream.write_all(&flight).await?;
        stream.flush().await?;
        expect_ccs(stream).await?;
        let fin = read_appdata_record(stream).await?;
        if ks.check_client_confirm(&fin) {
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
    match probe {
        ProbeResponse::Silence => silence(stream).await,
        ProbeResponse::Fallback(upstream) => {
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
    match server_handshake_core(&mut stream, psk).await {
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
    match server_handshake_core(stream, psk).await {
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
            let ks = KeySchedule::new(ss.expose(), &wrong, transcript_hash(&ch, &sh));
            let mut flight = sh;
            flight.extend_from_slice(&server_encrypted_flight(&psk_shape, &ks));
            m.write_all(&flight).await.unwrap();
            let mut rest = Vec::new();
            let _ =
                tokio::time::timeout(Duration::from_millis(300), m.read_to_end(&mut rest)).await;
            rest
        });
        let r = client_handshake(&mut c, &psk).await;
        assert!(matches!(r, Err(ObfsError::AuthFailed)));
        drop(c);
        assert!(
            mitm.await.unwrap().is_empty(),
            "nothing sent after the ClientHello"
        );
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
