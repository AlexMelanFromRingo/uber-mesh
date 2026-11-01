//! Chrome-shaped TLS 1.3 ClientHello / ServerHello construction and **strict** parsing.
//!
//! The obfs handshake rides inside what looks, on the wire, like a modern Chrome (stable, 2025-26)
//! TLS 1.3 handshake with post-quantum key agreement (constitution Principle II — no static
//! fingerprint):
//!
//! - **ClientHello** follows Chrome's template: GREASE (RFC 8701) cipher / group / version /
//!   extension values chosen per connection, Chrome's 15-suite cipher list, Chrome's extension set
//!   (`server_name`, `extended_master_secret`, `renegotiation_info`, `supported_groups`
//!   `[GREASE, X25519MLKEM768, x25519, secp256r1, secp384r1]`, `ec_point_formats`, `session_ticket`,
//!   ALPN `[h2, http/1.1]`, `status_request`, `signature_algorithms`, `signed_certificate_timestamp`,
//!   `key_share [GREASE, X25519MLKEM768, x25519]`, `psk_key_exchange_modes`, `supported_versions`,
//!   `compress_certificate` (brotli), `application_settings`, GREASE `encrypted_client_hello`), and
//!   Chrome's **per-connection extension-order permutation** (GREASE extensions pinned first/last).
//!   The size therefore varies per connection (SNI, ECH GREASE payload) and the order is never
//!   static.
//! - The `X25519MLKEM768` (`0x11EC`) share uses the real IANA layout: client = ML-KEM-768
//!   encapsulation key (1184 B) ‖ X25519 (32 B); server = ML-KEM-768 ciphertext (1088 B) ‖ X25519
//!   (32 B). This carries the hybrid KEM material of `umesh_crypto::kem` verbatim.
//! - **ServerHello** carries `supported_versions` + the hybrid `key_share` (OpenSSL order).
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
/// The TLS 1.3 suite the server "selects" (TLS_AES_128_GCM_SHA256, what servers pick for Chrome).
pub const SELECTED_CIPHER: u16 = 0x1301;

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

/// Build a complete ServerHello record echoing `session_id` and carrying the `X25519MLKEM768`
/// server share (ML-KEM-768 ct ‖ X25519, 1120 B). The server random is drawn from `rng`.
pub fn build_server_hello<R: RngCore + ?Sized>(
    rng: &mut R,
    session_id: &[u8; 32],
    hybrid_share: &[u8],
) -> Vec<u8> {
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);

    let mut exts = ext(EXT_SUPPORTED_VERSIONS, &TLS13.to_be_bytes());
    let mut share = Vec::with_capacity(4 + hybrid_share.len());
    put_u16(&mut share, GROUP_X25519MLKEM768);
    put_len16(&mut share, hybrid_share.len());
    share.extend_from_slice(hybrid_share);
    exts.extend(ext(EXT_KEY_SHARE, &share));

    let mut body = Vec::with_capacity(2 + 32 + 33 + 3 + 2 + exts.len());
    put_u16(&mut body, TLS12);
    body.extend_from_slice(&random);
    body.push(SESSION_ID_LEN as u8);
    body.extend_from_slice(session_id);
    put_u16(&mut body, SELECTED_CIPHER);
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
    /// The selected cipher suite.
    pub cipher_suite: u16,
    /// The `X25519MLKEM768` server share (exactly [`HYBRID_SERVER_SHARE_LEN`] bytes).
    pub hybrid_share: Vec<u8>,
}

/// Strictly parse a single ServerHello **record**. Requires TLS 1.3 (`supported_versions` = 0x0304),
/// an `X25519MLKEM768` share of exactly [`HYBRID_SERVER_SHARE_LEN`] bytes, null compression, a
/// 32-byte session_id, and no other extensions; rejects HelloRetryRequest. Never panics.
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
    if r.u8()? != 0 {
        return None;
    }
    let ext_block = r.vec16()?;
    if !r.is_empty() {
        return None;
    }

    let mut version_ok = false;
    let mut hybrid_share = None;
    for (etype, body) in extensions(ext_block)? {
        match etype {
            EXT_SUPPORTED_VERSIONS => version_ok = body == TLS13.to_be_bytes(),
            EXT_KEY_SHARE => {
                let mut kr = Reader::new(body);
                if kr.u16()? != GROUP_X25519MLKEM768 {
                    return None;
                }
                let ke = kr.vec16()?;
                if !kr.is_empty() || ke.b.len() != HYBRID_SERVER_SHARE_LEN {
                    return None;
                }
                hybrid_share = Some(ke.b.to_vec());
            }
            _ => return None,
        }
    }
    if !version_ok {
        return None;
    }
    Some(ServerHelloInfo {
        session_id,
        cipher_suite,
        hybrid_share: hybrid_share?,
    })
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
        assert_eq!(info.cipher_suite, SELECTED_CIPHER);
        assert_eq!(info.hybrid_share, ks);
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
