//! Chrome-exact TLS 1.3 ClientHello / cover-shaped ServerHello construction and **strict** parsing.
//!
//! # ClientHello template (pinned)
//!
//! The obfs handshake rides inside what is, on the wire, the default ClientHello of **desktop Chrome
//! stable 133 and later** (BoringSSL, x86-64 with AES-NI, first connection to an origin — no
//! resumption, so no `pre_shared_key`/`early_data`; the hello is > 512 B so BoringSSL emits no
//! `padding`). Source: BoringSSL `ssl/extensions.cc` / `handshake_client.cc` defaults as shipped
//! in Chrome (`X25519MLKEM768` default since Chrome 131, new ALPS codepoint `0x44cd` since
//! Chrome 133); the resulting JA4 is the public Chrome-133+ value [`CHROME_JA4`]
//! (`t13d1516h2_8daaf6152771_d8a2da3f94cd`), asserted for every generated hello by
//! `tests/fingerprint.rs`, which also recomputes JA3 (it varies per connection, as Chrome's does).
//!
//! ```text
//! record            16 0301 <len>                      (record-layer version 0x0301, one record)
//! handshake         01 <u24 len>
//! legacy_version    0303
//! random            32 B random
//! legacy_session_id 32 B                               (obfs gate tag; Chrome: 32 random bytes)
//! cipher_suites     GREASE, 1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035
//! compression       01 00
//! extensions        GREASE_1 (empty)                   — always first
//!                   ┌ shuffled uniformly per connection (Chrome's extension permutation) ┐
//!                   │ 0000 server_name        00 <len> 00 <len> host   (omitted for an IP / invalid) │
//!                   │ 0017 extended_ms        empty                                        │
//!                   │ ff01 renegotiation_info 00                                           │
//!                   │ 000a supported_groups   GREASE, 11ec, 001d, 0017, 0018               │
//!                   │ 000b ec_point_formats   01 00                                        │
//!                   │ 0023 session_ticket     empty                                        │
//!                   │ 0010 ALPN               "h2", "http/1.1"                             │
//!                   │ 0005 status_request     01 0000 0000 (OCSP, no responder ids/exts)   │
//!                   │ 000d signature_algs     0403 0804 0401 0503 0805 0501 0806 0601      │
//!                   │ 0012 SCT                empty                                        │
//!                   │ 0033 key_share          GREASE(1 B: 00), 11ec(1216 B), 001d(32 B)    │
//!                   │ 002d psk_kex_modes      01 01 (psk_dhe_ke)                           │
//!                   │ 002b supported_versions GREASE, 0304, 0303                           │
//!                   │ 001b compress_cert      02 0002 (brotli)                             │
//!                   │ 44cd application_settings (ALPS, Chrome 133+ codepoint) "h2"         │
//!                   │ fe0d encrypted_client_hello GREASE: outer, 0001/0001, random config_id,│
//!                   │      enc 32 B, payload 32·{4..7}+16 = 144|176|208|240 B random     │
//!                   └──────────────────────────────────────────────────────────────────────┘
//!                   GREASE_2 (body 00), ≠ GREASE_1      — always last
//! ```
//!
//! GREASE values (RFC 8701) are drawn per connection exactly where BoringSSL places them: cipher
//! (first suite), group (first `supported_groups` entry **and** the 1-byte key share), version (first
//! `supported_versions` entry), and the two extensions (first + last, distinct). The
//! `X25519MLKEM768` (`0x11EC`) share uses the IANA layout — client = ML-KEM-768 encapsulation key
//! (1184 B) ‖ X25519 (32 B) — and carries `umesh_crypto::kem`'s initiator message verbatim; the
//! separate `x25519` share is a random 32-byte string shaped like a public key.
//!
//! **Maintenance:** when Chrome stable changes its hello (new group/codepoint, ECH payload rule),
//! update this template, the [`CHROME_JA4`] constant, the KAT in `tests/handshake_security.rs`, and
//! the wire contract together.
//!
//! # ServerHello
//!
//! The ServerHello is built to a [`ServerHelloShape`] — cipher suite, selected group
//! (`X25519MLKEM768` carrying ML-KEM-768 ct ‖ X25519, or plain `x25519`) and extension order — so a
//! server can reproduce exactly what its real cover site answers to this ClientHello
//! (`crate::cover::CoverProfile`).
//!
//! Parsers are strict and bounds-checked: exact record/handshake length agreement, no duplicate
//! extensions, exact key_share sizes. They are fuzz targets (`fuzz/fuzz_targets/client_hello.rs`,
//! `server_hello.rs`).

use rand::seq::SliceRandom;
use rand::{Rng, RngCore};

/// IANA codepoint for the hybrid X25519 + ML-KEM-768 group.
pub const GROUP_X25519MLKEM768: u16 = 0x11EC;
/// IANA codepoint for x25519.
pub const GROUP_X25519: u16 = 0x001D;
const GROUP_SECP256R1: u16 = 0x0017;
const GROUP_SECP384R1: u16 = 0x0018;

/// Client `X25519MLKEM768` share length: ML-KEM-768 ek (1184) ‖ X25519 (32).
pub const HYBRID_CLIENT_SHARE_LEN: usize = 1184 + 32;
/// Server `X25519MLKEM768` share length: ML-KEM-768 ct (1088) ‖ X25519 (32).
pub const HYBRID_SERVER_SHARE_LEN: usize = 1088 + 32;
/// The TLS 1.3 suite the server selects by default (TLS_AES_128_GCM_SHA256, what most servers pick
/// for Chrome).
pub const SELECTED_CIPHER: u16 = 0x1301;
/// The TLS 1.3 suites Chrome offers; a ServerHello must select one of them.
pub const TLS13_SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];
/// The JA4 fingerprint of desktop Chrome stable 133+ — and of every ClientHello [`build_client_hello`]
/// emits with a valid SNI (`tests/fingerprint.rs`).
pub const CHROME_JA4: &str = "t13d1516h2_8daaf6152771_d8a2da3f94cd";

/// Byte offset of the 32-byte `legacy_session_id` inside a ClientHello/ServerHello **record**:
/// record header (5) + handshake header (4) + legacy_version (2) + random (32) + sid length (1).
pub const SESSION_ID_OFFSET: usize = 5 + 4 + 2 + 32 + 1;
/// Length of the `legacy_session_id` we send (middlebox-compatibility mode, like Chrome).
pub const SESSION_ID_LEN: usize = 32;

/// A TLS 1.3 middlebox-compatibility ChangeCipherSpec record (`14 03 03 00 01 01`).
pub const CCS_RECORD: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

const REC_HANDSHAKE: u8 = 0x16;
const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;
const TLS12: u16 = 0x0303;
const TLS13: u16 = 0x0304;

/// RFC 8446 §4.1.3: a ServerHello with this `random` is a HelloRetryRequest (unsupported → reject).
const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SCT: u16 = 0x0012;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEX_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
/// ALPS (`application_settings`), the codepoint current Chrome sends.
const EXT_APPLICATION_SETTINGS: u16 = 0x44cd;
const EXT_ECH: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// Chrome's cipher-suite list (after the leading GREASE value).
const CHROME_CIPHERS: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];
/// Chrome's `signature_algorithms` list.
const CHROME_SIGALGS: [u16; 8] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];
/// BoringSSL GREASE-ECH payload sizes (32·{4..7} + 16-byte AEAD tag).
const ECH_GREASE_PAYLOAD_LENS: [usize; 4] = [144, 176, 208, 240];
/// Maximum number of extensions a parser accepts (DoS bound for the duplicate check).
const MAX_EXTENSIONS: usize = 64;
/// Maximum DNS host-name length accepted in / emitted into `server_name`.
const MAX_SNI_LEN: usize = 253;

fn put_u16(v: &mut Vec<u8>, n: u16) {
    v.extend_from_slice(&n.to_be_bytes());
}

/// `n` as a big-endian u16 length prefix. Every caller passes a length bounded far below 2^16.
fn put_len16(v: &mut Vec<u8>, n: usize) {
    debug_assert!(n <= u16::MAX as usize);
    put_u16(v, n as u16);
}

/// A TLS extension: `type(2) | len(2) | body`.
fn ext(etype: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    put_u16(&mut v, etype);
    put_len16(&mut v, body.len());
    v.extend_from_slice(body);
    v
}

/// `u16 length ‖ items` for a list of u16 codepoints.
fn u16_list(items: &[u16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + 2 * items.len());
    put_len16(&mut v, 2 * items.len());
    for &i in items {
        put_u16(&mut v, i);
    }
    v
}

/// True if `v` is an RFC 8701 GREASE value (`0x?A?A` with equal nibbles).
pub fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 12) == ((v >> 4) & 0x0f)
}

fn grease<R: RngCore + ?Sized>(rng: &mut R) -> u16 {
    let n: u16 = rng.gen_range(0..16);
    (n << 12) | 0x0a00 | (n << 4) | 0x000a
}

/// A random 32-byte string shaped like an X25519 public key (top bit clear, as every canonical
/// u-coordinate below 2^255−19 is).
fn x25519_like<R: RngCore + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut k = [0u8; 32];
    rng.fill_bytes(&mut k);
    k[31] &= 0x7f;
    k
}

/// True if `sni` is something we are willing to put into `server_name` (non-empty ASCII host name,
/// not an IP literal — Chrome omits SNI for IPs).
pub fn sni_is_valid(sni: &str) -> bool {
    !sni.is_empty()
        && sni.len() <= MAX_SNI_LEN
        && sni
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && sni.parse::<std::net::IpAddr>().is_err()
}

/// Build a complete, Chrome-shaped ClientHello **record** whose 32-byte `legacy_session_id` is all
/// zero. The caller (the obfs handshake) computes the gate tag over this record and patches it in
/// at [`SESSION_ID_OFFSET`].
///
/// `hybrid_share` is the `X25519MLKEM768` client share (ML-KEM-768 ek ‖ X25519, 1216 B). All
/// per-connection randomness (client random, GREASE values, the decoy x25519 share, the GREASE-ECH
/// payload, and the extension permutation) is drawn from `rng`, so a seeded RNG yields a
/// deterministic record (used by the known-answer test).
pub fn build_client_hello<R: RngCore + ?Sized>(
    rng: &mut R,
    hybrid_share: &[u8],
    sni: &str,
) -> Vec<u8> {
    let g_cipher = grease(rng);
    let g_group = grease(rng);
    let g_version = grease(rng);
    let g_ext1 = grease(rng);
    let mut g_ext2 = grease(rng);
    if g_ext2 == g_ext1 {
        g_ext2 ^= 0x1010; // BoringSSL: the two GREASE extensions must differ
    }
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    let x25519_share = x25519_like(rng);

    let mut exts: Vec<Vec<u8>> = Vec::with_capacity(16);

    if sni_is_valid(sni) {
        let host = sni.as_bytes();
        let mut body = Vec::with_capacity(5 + host.len());
        put_len16(&mut body, 3 + host.len());
        body.push(0x00); // host_name
        put_len16(&mut body, host.len());
        body.extend_from_slice(host);
        exts.push(ext(EXT_SERVER_NAME, &body));
    }
    exts.push(ext(EXT_EXTENDED_MASTER_SECRET, &[]));
    exts.push(ext(EXT_RENEGOTIATION_INFO, &[0x00]));
    exts.push(ext(
        EXT_SUPPORTED_GROUPS,
        &u16_list(&[
            g_group,
            GROUP_X25519MLKEM768,
            GROUP_X25519,
            GROUP_SECP256R1,
            GROUP_SECP384R1,
        ]),
    ));
    exts.push(ext(EXT_EC_POINT_FORMATS, &[0x01, 0x00]));
    exts.push(ext(EXT_SESSION_TICKET, &[]));
    exts.push(ext(
        EXT_ALPN,
        &[
            0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ],
    ));
    exts.push(ext(EXT_STATUS_REQUEST, &[0x01, 0x00, 0x00, 0x00, 0x00]));
    exts.push(ext(EXT_SIGNATURE_ALGORITHMS, &u16_list(&CHROME_SIGALGS)));
    exts.push(ext(EXT_SCT, &[]));
    {
        // key_share: [GREASE(1 byte 0x00), X25519MLKEM768(1216), x25519(32)]
        let mut shares = Vec::with_capacity(5 + 4 + hybrid_share.len() + 4 + 32);
        put_u16(&mut shares, g_group);
        put_u16(&mut shares, 1);
        shares.push(0x00);
        put_u16(&mut shares, GROUP_X25519MLKEM768);
        put_len16(&mut shares, hybrid_share.len());
        shares.extend_from_slice(hybrid_share);
        put_u16(&mut shares, GROUP_X25519);
        put_u16(&mut shares, 32);
        shares.extend_from_slice(&x25519_share);
        let mut body = Vec::with_capacity(2 + shares.len());
        put_len16(&mut body, shares.len());
        body.extend_from_slice(&shares);
        exts.push(ext(EXT_KEY_SHARE, &body));
    }
    exts.push(ext(EXT_PSK_KEX_MODES, &[0x01, 0x01])); // psk_dhe_ke
    {
        let mut body = vec![6u8];
        for v in [g_version, TLS13, TLS12] {
            put_u16(&mut body, v);
        }
        exts.push(ext(EXT_SUPPORTED_VERSIONS, &body));
    }
    exts.push(ext(EXT_COMPRESS_CERTIFICATE, &[0x02, 0x00, 0x02])); // brotli
    exts.push(ext(
        EXT_APPLICATION_SETTINGS,
        &[0x00, 0x03, 0x02, b'h', b'2'],
    ));
    {
        // GREASE ECH (outer): type, HPKE suite (HKDF-SHA256, AES-128-GCM), config_id, enc, payload.
        let config_id: u8 = rng.r#gen();
        let enc = x25519_like(rng);
        let payload_len = ECH_GREASE_PAYLOAD_LENS[rng.gen_range(0..ECH_GREASE_PAYLOAD_LENS.len())];
        let mut payload = vec![0u8; payload_len];
        rng.fill_bytes(&mut payload);
        let mut body = Vec::with_capacity(10 + 32 + payload_len);
        body.push(0x00); // outer
        put_u16(&mut body, 0x0001);
        put_u16(&mut body, 0x0001);
        body.push(config_id);
        put_u16(&mut body, 32);
        body.extend_from_slice(&enc);
        put_len16(&mut body, payload_len);
        body.extend_from_slice(&payload);
        exts.push(ext(EXT_ECH, &body));
    }

    // Chrome's per-connection extension permutation; GREASE extensions pinned first and last.
    exts.shuffle(rng);
    let mut ext_bytes = ext(g_ext1, &[]);
    for e in &exts {
        ext_bytes.extend_from_slice(e);
    }
    ext_bytes.extend_from_slice(&ext(g_ext2, &[0x00]));

    let mut body = Vec::with_capacity(2 + 32 + 33 + 34 + 2 + 2 + ext_bytes.len());
    put_u16(&mut body, TLS12); // legacy_version
    body.extend_from_slice(&random);
    body.push(SESSION_ID_LEN as u8);
    body.extend_from_slice(&[0u8; SESSION_ID_LEN]);
    let mut suites = vec![g_cipher];
    suites.extend_from_slice(&CHROME_CIPHERS);
    body.extend_from_slice(&u16_list(&suites));
    body.extend_from_slice(&[0x01, 0x00]); // compression: null only
    put_len16(&mut body, ext_bytes.len());
    body.extend_from_slice(&ext_bytes);

    wrap_handshake(HS_CLIENT_HELLO, &body, 0x0301)
}

/// The key-share group a TLS 1.3 ServerHello selects (the two groups of the Chrome template a
/// server can pick without a HelloRetryRequest).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerGroup {
    /// `X25519MLKEM768` (`0x11EC`): share = ML-KEM-768 ciphertext (1088) ‖ X25519 (32).
    X25519MlKem768,
    /// `x25519` (`0x001D`): share = X25519 (32). The obfs server then carries the ML-KEM-768
    /// ciphertext, masked, inside the encrypted flight (see `handshake`).
    X25519,
}

impl ServerGroup {
    /// IANA codepoint.
    pub fn codepoint(self) -> u16 {
        match self {
            ServerGroup::X25519MlKem768 => GROUP_X25519MLKEM768,
            ServerGroup::X25519 => GROUP_X25519,
        }
    }

    /// Length of the server key share for this group.
    pub fn share_len(self) -> usize {
        match self {
            ServerGroup::X25519MlKem768 => HYBRID_SERVER_SHARE_LEN,
            ServerGroup::X25519 => 32,
        }
    }

    fn from_codepoint(g: u16) -> Option<Self> {
        match g {
            GROUP_X25519MLKEM768 => Some(ServerGroup::X25519MlKem768),
            GROUP_X25519 => Some(ServerGroup::X25519),
            _ => None,
        }
    }
}

/// The observable, non-random shape of a TLS 1.3 ServerHello answering the Chrome template: which
/// suite and group the server selects and in which order it writes its two extensions. Everything
/// else (random, echoed session_id, share bytes) is per connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerHelloShape {
    /// Selected cipher suite (one of [`TLS13_SUITES`]).
    pub cipher_suite: u16,
    /// Selected key-share group.
    pub group: ServerGroup,
    /// `key_share` before `supported_versions` (BoringSSL order) instead of after (OpenSSL / Go).
    pub key_share_first: bool,
}

impl Default for ServerHelloShape {
    /// `TLS_AES_128_GCM_SHA256`, `X25519MLKEM768`, `supported_versions` first (OpenSSL order).
    fn default() -> Self {
        ServerHelloShape {
            cipher_suite: SELECTED_CIPHER,
            group: ServerGroup::X25519MlKem768,
            key_share_first: false,
        }
    }
}

impl ServerHelloShape {
    /// Total record length (header included) of a ServerHello of this shape.
    pub fn record_len(&self) -> usize {
        // record hdr 5 + hs hdr 4 + version 2 + random 32 + sid 1+32 + suite 2 + comp 1 + ext len 2
        // + supported_versions (4 + 2) + key_share (4 + 2 + 2 + share).
        5 + 4 + 2 + 32 + 1 + SESSION_ID_LEN + 2 + 1 + 2 + 6 + 8 + self.group.share_len()
    }
}

/// Build a complete ServerHello record of the default [`ServerHelloShape`] echoing `session_id`
/// and carrying the `X25519MLKEM768` server share (ML-KEM-768 ct ‖ X25519, 1120 B).
pub fn build_server_hello<R: RngCore + ?Sized>(
    rng: &mut R,
    session_id: &[u8; 32],
    hybrid_share: &[u8],
) -> Vec<u8> {
    build_server_hello_shaped(rng, session_id, &ServerHelloShape::default(), hybrid_share)
}

/// Build a complete ServerHello record of `shape`, echoing `session_id` and carrying `share` for
/// `shape.group` (the caller passes exactly [`ServerGroup::share_len`] bytes). The server random is
/// drawn from `rng`.
pub fn build_server_hello_shaped<R: RngCore + ?Sized>(
    rng: &mut R,
    session_id: &[u8; 32],
    shape: &ServerHelloShape,
    share: &[u8],
) -> Vec<u8> {
    debug_assert_eq!(share.len(), shape.group.share_len());
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);

    let versions = ext(EXT_SUPPORTED_VERSIONS, &TLS13.to_be_bytes());
    let mut ks = Vec::with_capacity(4 + share.len());
    put_u16(&mut ks, shape.group.codepoint());
    put_len16(&mut ks, share.len());
    ks.extend_from_slice(share);
    let key_share = ext(EXT_KEY_SHARE, &ks);
    let exts = if shape.key_share_first {
        [key_share, versions].concat()
    } else {
        [versions, key_share].concat()
    };

    let mut body = Vec::with_capacity(2 + 32 + 33 + 3 + 2 + exts.len());
    put_u16(&mut body, TLS12);
    body.extend_from_slice(&random);
    body.push(SESSION_ID_LEN as u8);
    body.extend_from_slice(session_id);
    put_u16(&mut body, shape.cipher_suite);
    body.push(0); // compression
    put_len16(&mut body, exts.len());
    body.extend_from_slice(&exts);

    wrap_handshake(HS_SERVER_HELLO, &body, TLS12)
}

fn wrap_handshake(msg_type: u8, body: &[u8], rec_version: u16) -> Vec<u8> {
    let l = body.len();
    let mut rec = Vec::with_capacity(9 + l);
    rec.push(REC_HANDSHAKE);
    put_u16(&mut rec, rec_version);
    put_len16(&mut rec, l + 4);
    rec.push(msg_type);
    rec.push((l >> 16) as u8);
    rec.push((l >> 8) as u8);
    rec.push(l as u8);
    rec.extend_from_slice(body);
    rec
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, p: 0 }
    }
    fn remaining(&self) -> usize {
        self.b.len() - self.p
    }
    fn is_empty(&self) -> bool {
        self.p == self.b.len()
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.p.checked_add(n)?;
        let s = self.b.get(self.p..end)?;
        self.p = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        let s = self.take(3)?;
        Some(((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
    }
    /// A `u16`-length-prefixed vector, returned as a sub-reader.
    fn vec16(&mut self) -> Option<Reader<'a>> {
        let n = self.u16()? as usize;
        Some(Reader::new(self.take(n)?))
    }
}

/// Strictly walk one handshake record of type `expect_type`: the record length must equal the rest
/// of `rec` exactly and the handshake length must equal the record length − 4. Returns a reader over
/// the handshake body.
fn handshake_body(rec: &[u8], expect_type: u8, client: bool) -> Option<Reader<'_>> {
    let mut r = Reader::new(rec);
    if r.u8()? != REC_HANDSHAKE {
        return None;
    }
    let rec_version = r.u16()?;
    let version_ok = if client {
        rec_version == 0x0301 || rec_version == TLS12
    } else {
        rec_version == TLS12
    };
    if !version_ok {
        return None;
    }
    let rec_len = r.u16()? as usize;
    if rec_len != r.remaining() {
        return None;
    }
    if r.u8()? != expect_type {
        return None;
    }
    let hs_len = r.u24()?;
    if hs_len != r.remaining() {
        return None;
    }
    Some(r)
}

/// Iterate a strict extension block: each extension well-formed, no duplicates, bounded count.
fn extensions<'a>(mut r: Reader<'a>) -> Option<Vec<(u16, &'a [u8])>> {
    let mut out: Vec<(u16, &'a [u8])> = Vec::new();
    while !r.is_empty() {
        let etype = r.u16()?;
        let n = r.u16()? as usize;
        let body = r.take(n)?;
        if out.len() >= MAX_EXTENSIONS || out.iter().any(|(t, _)| *t == etype) {
            return None;
        }
        out.push((etype, body));
    }
    Some(out)
}

/// The fields of a parsed ClientHello that the obfs gate needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// The 32-byte `legacy_session_id` (the obfs gate tag for a uber-mesh client).
    pub session_id: [u8; 32],
    /// The `X25519MLKEM768` client share (exactly [`HYBRID_CLIENT_SHARE_LEN`] bytes).
    pub hybrid_share: Vec<u8>,
    /// The `server_name` host, if present.
    pub sni: Option<String>,
}

fn parse_sni(body: &[u8]) -> Option<String> {
    let mut r = Reader::new(body);
    let mut list = r.vec16()?;
    if !r.is_empty() {
        return None;
    }
    if list.u8()? != 0x00 {
        return None;
    }
    let host = list.vec16()?;
    if !list.is_empty() {
        return None;
    }
    let host = std::str::from_utf8(host.b).ok()?;
    sni_is_valid(host).then(|| host.to_string())
}

/// Strictly parse a single ClientHello **record** (exactly one record, nothing trailing). Returns
/// `None` for anything that is not a well-formed TLS 1.3 ClientHello with a 32-byte session_id and
/// exactly one `X25519MLKEM768` share of the right size. Never panics.
pub fn parse_client_hello(rec: &[u8]) -> Option<ClientHelloInfo> {
    let mut r = handshake_body(rec, HS_CLIENT_HELLO, true)?;
    if r.u16()? != TLS12 {
        return None;
    }
    r.take(32)?; // random
    if r.u8()? as usize != SESSION_ID_LEN {
        return None;
    }
    let session_id: [u8; 32] = r.take(SESSION_ID_LEN)?.try_into().ok()?;
    let suites = r.vec16()?;
    if suites.b.is_empty() || suites.b.len() % 2 != 0 {
        return None;
    }
    let mut comp = Reader::new({
        let n = r.u8()? as usize;
        r.take(n)?
    });
    if comp.u8()? != 0x00 || !comp.is_empty() {
        return None;
    }
    let ext_block = r.vec16()?;
    if !r.is_empty() {
        return None;
    }

    let mut hybrid_share = None;
    let mut sni = None;
    for (etype, body) in extensions(ext_block)? {
        match etype {
            EXT_KEY_SHARE => {
                let mut kr = Reader::new(body);
                let mut shares = kr.vec16()?;
                if !kr.is_empty() {
                    return None;
                }
                let mut groups: Vec<u16> = Vec::new();
                while !shares.is_empty() {
                    let group = shares.u16()?;
                    let ke = shares.vec16()?;
                    if groups.len() >= MAX_EXTENSIONS || groups.contains(&group) {
                        return None;
                    }
                    groups.push(group);
                    if group == GROUP_X25519MLKEM768 {
                        if ke.b.len() != HYBRID_CLIENT_SHARE_LEN {
                            return None;
                        }
                        hybrid_share = Some(ke.b.to_vec());
                    }
                }
            }
            EXT_SERVER_NAME => sni = Some(parse_sni(body)?),
            _ => {}
        }
    }
    Some(ClientHelloInfo {
        session_id,
        hybrid_share: hybrid_share?,
        sni,
    })
}

/// The fields of a parsed ServerHello.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerHelloInfo {
    /// The echoed `legacy_session_id`.
    pub session_id: [u8; 32],
    /// Suite, group and extension order (the reproducible shape).
    pub shape: ServerHelloShape,
    /// The server key share for `shape.group` (exactly [`ServerGroup::share_len`] bytes).
    pub key_share: Vec<u8>,
}

/// Strictly parse a single ServerHello **record**. Requires TLS 1.3 (`supported_versions` =
/// 0x0304), exactly the two extensions `supported_versions` and `key_share` (in either order), a
/// TLS 1.3 suite Chrome offers ([`TLS13_SUITES`]), an `X25519MLKEM768` share of exactly
/// [`HYBRID_SERVER_SHARE_LEN`] bytes or an `x25519` share of 32 bytes, null compression and a 32-byte
/// session_id; rejects HelloRetryRequest. Never panics.
pub fn parse_server_hello(rec: &[u8]) -> Option<ServerHelloInfo> {
    let mut r = handshake_body(rec, HS_SERVER_HELLO, false)?;
    if r.u16()? != TLS12 {
        return None;
    }
    if r.take(32)? == HRR_RANDOM {
        return None;
    }
    if r.u8()? as usize != SESSION_ID_LEN {
        return None;
    }
    let session_id: [u8; 32] = r.take(SESSION_ID_LEN)?.try_into().ok()?;
    let cipher_suite = r.u16()?;
    if !TLS13_SUITES.contains(&cipher_suite) {
        return None;
    }
    if r.u8()? != 0 {
        return None;
    }
    let ext_block = r.vec16()?;
    if !r.is_empty() {
        return None;
    }

    let exts = extensions(ext_block)?;
    if exts.len() != 2 {
        return None;
    }
    let mut version_ok = false;
    let mut share = None;
    for (etype, body) in &exts {
        match *etype {
            EXT_SUPPORTED_VERSIONS => version_ok = *body == TLS13.to_be_bytes(),
            EXT_KEY_SHARE => {
                let mut kr = Reader::new(body);
                let group = ServerGroup::from_codepoint(kr.u16()?)?;
                let ke = kr.vec16()?;
                if !kr.is_empty() || ke.b.len() != group.share_len() {
                    return None;
                }
                share = Some((group, ke.b.to_vec()));
            }
            _ => return None,
        }
    }
    let (group, key_share) = share?;
    if !version_ok {
        return None;
    }
    Some(ServerHelloInfo {
        session_id,
        shape: ServerHelloShape {
            cipher_suite,
            group,
            key_share_first: exts[0].0 == EXT_KEY_SHARE,
        },
        key_share,
    })
}

/// Payload length of the TLS 1.3 client `Finished` record for `cipher_suite`: verify_data (32 for
/// SHA-256 suites, 48 for `TLS_AES_256_GCM_SHA384`) + handshake header 4 + content type 1 + AEAD tag
/// 16.
pub fn finished_record_len(cipher_suite: u16) -> usize {
    let verify_data = if cipher_suite == 0x1302 { 48 } else { 32 };
    verify_data + 4 + 1 + 16
}

/// The extension types of a ClientHello record, in wire order (diagnostics / fingerprint tests).
pub fn client_hello_extension_order(rec: &[u8]) -> Option<Vec<u16>> {
    let mut r = handshake_body(rec, HS_CLIENT_HELLO, true)?;
    r.take(2 + 32)?;
    let n = r.u8()? as usize;
    r.take(n)?;
    r.vec16()?;
    let n = r.u8()? as usize;
    r.take(n)?;
    let ext_block = r.vec16()?;
    Some(extensions(ext_block)?.into_iter().map(|(t, _)| t).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn share(n: usize, salt: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8) ^ salt).collect()
    }

    #[test]
    fn client_hello_roundtrip() {
        let ks = share(HYBRID_CLIENT_SHARE_LEN, 0);
        let mut rng = StdRng::seed_from_u64(1);
        let rec = build_client_hello(&mut rng, &ks, "www.example.com");
        assert_eq!(rec[0], REC_HANDSHAKE);
        assert_eq!(&rec[1..3], &[0x03, 0x01]);
        assert_eq!(rec[SESSION_ID_OFFSET - 1], 32);
        let info = parse_client_hello(&rec).unwrap();
        assert_eq!(info.session_id, [0u8; 32]);
        assert_eq!(info.hybrid_share, ks);
        assert_eq!(info.sni.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn client_hello_has_chrome_shape() {
        let ks = share(HYBRID_CLIENT_SHARE_LEN, 3);
        let rec = build_client_hello(&mut StdRng::seed_from_u64(7), &ks, "a.example");
        let order = client_hello_extension_order(&rec).unwrap();
        assert!(is_grease(order[0]), "first extension must be GREASE");
        assert!(
            is_grease(*order.last().unwrap()),
            "last extension must be GREASE"
        );
        assert_ne!(order[0], *order.last().unwrap());
        for want in [
            EXT_SERVER_NAME,
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_SUPPORTED_GROUPS,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
            EXT_ALPN,
            EXT_STATUS_REQUEST,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_SCT,
            EXT_KEY_SHARE,
            EXT_PSK_KEX_MODES,
            EXT_SUPPORTED_VERSIONS,
            EXT_COMPRESS_CERTIFICATE,
            EXT_APPLICATION_SETTINGS,
            EXT_ECH,
        ] {
            assert!(order.contains(&want), "missing extension {want:#06x}");
        }
        assert_eq!(order.len(), 18);
        // cipher list: GREASE + Chrome's 15 suites.
        let cs_off = SESSION_ID_OFFSET + 32;
        assert_eq!(&rec[cs_off..cs_off + 2], &[0x00, 32]);
        assert!(is_grease(u16::from_be_bytes([
            rec[cs_off + 2],
            rec[cs_off + 3]
        ])));
    }

    #[test]
    fn grease_values_are_grease() {
        let mut rng = StdRng::seed_from_u64(9);
        for _ in 0..200 {
            assert!(is_grease(grease(&mut rng)));
        }
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0a1a));
    }

    #[test]
    fn server_hello_roundtrip() {
        let sid = [9u8; 32];
        let ks = share(HYBRID_SERVER_SHARE_LEN, 0x5a);
        let rec = build_server_hello(&mut StdRng::seed_from_u64(2), &sid, &ks);
        assert_eq!(rec[0], REC_HANDSHAKE);
        let info = parse_server_hello(&rec).unwrap();
        assert_eq!(info.session_id, sid);
        assert_eq!(info.shape, ServerHelloShape::default());
        assert_eq!(info.key_share, ks);
        assert_eq!(rec.len(), ServerHelloShape::default().record_len());
    }

    #[test]
    fn server_hello_shapes_roundtrip() {
        let sid = [3u8; 32];
        for cipher_suite in TLS13_SUITES {
            for group in [ServerGroup::X25519MlKem768, ServerGroup::X25519] {
                for key_share_first in [false, true] {
                    let shape = ServerHelloShape {
                        cipher_suite,
                        group,
                        key_share_first,
                    };
                    let ks = share(group.share_len(), 0x11);
                    let rec =
                        build_server_hello_shaped(&mut StdRng::seed_from_u64(8), &sid, &shape, &ks);
                    assert_eq!(rec.len(), shape.record_len());
                    let info = parse_server_hello(&rec).unwrap();
                    assert_eq!(info.shape, shape);
                    assert_eq!(info.key_share, ks);
                }
            }
        }
        // x25519 ServerHello is the classic 127-byte record (0x7a body).
        let x = ServerHelloShape {
            group: ServerGroup::X25519,
            ..ServerHelloShape::default()
        };
        assert_eq!(x.record_len(), 127);
        assert_eq!(ServerHelloShape::default().record_len(), 1215);
        // A TLS 1.2 suite or an unknown group is rejected.
        let mut bad = build_server_hello(&mut StdRng::seed_from_u64(9), &sid, &share(1120, 0));
        bad[SESSION_ID_OFFSET + 32..SESSION_ID_OFFSET + 34].copy_from_slice(&[0xc0, 0x2f]);
        assert!(parse_server_hello(&bad).is_none());
        assert_eq!(finished_record_len(0x1301), 53);
        assert_eq!(finished_record_len(0x1303), 53);
        assert_eq!(finished_record_len(0x1302), 69);
    }

    #[test]
    fn parsers_are_strict() {
        let ks = share(HYBRID_CLIENT_SHARE_LEN, 1);
        let ch = build_client_hello(&mut StdRng::seed_from_u64(3), &ks, "x.example");
        // Trailing byte ⇒ record length mismatch.
        let mut t = ch.clone();
        t.push(0);
        assert!(parse_client_hello(&t).is_none());
        // Truncation at every length is rejected without panic.
        for n in 0..ch.len() {
            assert!(parse_client_hello(&ch[..n]).is_none());
        }
        // Wrong hybrid share size.
        let short = build_client_hello(&mut StdRng::seed_from_u64(3), &ks[..1000], "x.example");
        assert!(parse_client_hello(&short).is_none());

        let sh = build_server_hello(
            &mut StdRng::seed_from_u64(4),
            &[1; 32],
            &share(HYBRID_SERVER_SHARE_LEN, 2),
        );
        for n in 0..sh.len() {
            assert!(parse_server_hello(&sh[..n]).is_none());
        }
        // HelloRetryRequest random ⇒ rejected.
        let mut hrr = sh.clone();
        hrr[11..43].copy_from_slice(&HRR_RANDOM);
        assert!(parse_server_hello(&hrr).is_none());
        // A ServerHello is not a ClientHello and vice versa.
        assert!(parse_client_hello(&sh).is_none());
        assert!(parse_server_hello(&ch).is_none());
    }

    #[test]
    fn rejects_garbage_without_panic() {
        assert!(parse_client_hello(&[]).is_none());
        assert!(parse_client_hello(&[0x17, 0x03, 0x03, 0, 0]).is_none());
        assert!(parse_server_hello(&[0x16, 0x03, 0x03, 0xff, 0xff]).is_none());
        for n in 0..64 {
            let junk: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
            let _ = parse_client_hello(&junk);
            let _ = parse_server_hello(&junk);
        }
    }

    #[test]
    fn sni_validation() {
        assert!(sni_is_valid("www.example.com"));
        assert!(!sni_is_valid(""));
        assert!(!sni_is_valid("1.2.3.4"));
        assert!(!sni_is_valid("bad host"));
        // An invalid SNI is omitted rather than emitted.
        let ks = share(HYBRID_CLIENT_SHARE_LEN, 1);
        let rec = build_client_hello(&mut StdRng::seed_from_u64(5), &ks, "10.0.0.1");
        assert_eq!(parse_client_hello(&rec).unwrap().sni, None);
    }
}
