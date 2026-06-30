//! Minimal, structurally-valid TLS 1.3 ClientHello / ServerHello construction & parsing.
//!
//! The obfs handshake rides inside a real TLS 1.3 handshake record (`0x16`) with a **PQ-hybrid
//! `X25519MLKEM768` key_share** carrying the KEM material — exactly the shape modern browsers send.
//! This defeats TLS-state-machine DPI (the flow opens with a ClientHello, not application data) and
//! blends with real PQ-TLS traffic. The obfs auth gate rides in the 32-byte `session_id`.
//!
//! Scope: structurally valid (passes record-type + ClientHello parsing). It is NOT byte-exact uTLS
//! fingerprint mimicry of a specific browser (JA3/JA4) nor full TLS-1.3-transcript validity (no
//! EncryptedExtensions/Certificate/Finished) — those need a real TLS stack (native REALITY, deferred,
//! see docs/security-and-deferred.md).

use rand::RngCore;
use rand::rngs::OsRng;

/// IANA codepoint for the hybrid X25519 + ML-KEM-768 group.
pub const GROUP_X25519MLKEM768: u16 = 0x11EC;
const REC_HANDSHAKE: u8 = 0x16;
const HS_CLIENT_HELLO: u8 = 0x01;
const HS_SERVER_HELLO: u8 = 0x02;

fn be16(n: usize) -> [u8; 2] {
    (n as u16).to_be_bytes()
}

/// A TLS extension: `type(2) | len(2) | body`.
fn ext(etype: u16, body: &[u8]) -> Vec<u8> {
    let mut v = etype.to_be_bytes().to_vec();
    v.extend_from_slice(&be16(body.len()));
    v.extend_from_slice(body);
    v
}

fn random32() -> [u8; 32] {
    let mut r = [0u8; 32];
    OsRng.fill_bytes(&mut r);
    r
}

/// Build a complete ClientHello TLS record carrying `session_id` (obfs gate) and `key_share`
/// (the X25519MLKEM768 client share = ml-kem ek ‖ x25519 pub).
pub fn build_client_hello(session_id: &[u8; 32], key_share: &[u8], sni: &str) -> Vec<u8> {
    let mut exts = Vec::new();

    // server_name
    let host = sni.as_bytes();
    let mut entry = vec![0x00];
    entry.extend_from_slice(&be16(host.len()));
    entry.extend_from_slice(host);
    let mut sn = be16(entry.len()).to_vec();
    sn.extend_from_slice(&entry);
    exts.extend(ext(0x0000, &sn));

    // supported_groups
    let mut groups = Vec::new();
    for g in [GROUP_X25519MLKEM768, 0x001D] {
        groups.extend_from_slice(&g.to_be_bytes());
    }
    let mut sg = be16(groups.len()).to_vec();
    sg.extend_from_slice(&groups);
    exts.extend(ext(0x000a, &sg));

    // signature_algorithms
    let mut sa = Vec::new();
    for a in [0x0403u16, 0x0804, 0x0807] {
        sa.extend_from_slice(&a.to_be_bytes());
    }
    let mut sab = be16(sa.len()).to_vec();
    sab.extend_from_slice(&sa);
    exts.extend(ext(0x000d, &sab));

    // supported_versions (ClientHello form: list)
    let mut sv = vec![2u8];
    sv.extend_from_slice(&0x0304u16.to_be_bytes());
    exts.extend(ext(0x002b, &sv));

    // key_share (ClientHello form: client_shares list)
    let mut share = GROUP_X25519MLKEM768.to_be_bytes().to_vec();
    share.extend_from_slice(&be16(key_share.len()));
    share.extend_from_slice(key_share);
    let mut ks = be16(share.len()).to_vec();
    ks.extend_from_slice(&share);
    exts.extend(ext(0x0033, &ks));

    // ClientHello body
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
    body.extend_from_slice(&random32());
    body.push(32);
    body.extend_from_slice(session_id);
    let mut cs = Vec::new();
    for c in [0x1301u16, 0x1302, 0x1303] {
        cs.extend_from_slice(&c.to_be_bytes());
    }
    body.extend_from_slice(&be16(cs.len()));
    body.extend_from_slice(&cs);
    body.push(1); // compression methods len
    body.push(0); // null compression
    body.extend_from_slice(&be16(exts.len()));
    body.extend_from_slice(&exts);

    wrap_handshake(HS_CLIENT_HELLO, &body, 0x0301)
}

/// Build a complete ServerHello TLS record carrying the echoed `session_id` and the server
/// `key_share` (X25519MLKEM768 server share = ml-kem ct ‖ x25519 pub).
pub fn build_server_hello(session_id: &[u8; 32], key_share: &[u8]) -> Vec<u8> {
    let mut exts = Vec::new();
    // supported_versions (ServerHello form: selected version)
    exts.extend(ext(0x002b, &0x0304u16.to_be_bytes()));
    // key_share (ServerHello form: single server_share)
    let mut share = GROUP_X25519MLKEM768.to_be_bytes().to_vec();
    share.extend_from_slice(&be16(key_share.len()));
    share.extend_from_slice(key_share);
    exts.extend(ext(0x0033, &share));

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
    body.extend_from_slice(&random32());
    body.push(32);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&0x1301u16.to_be_bytes()); // chosen cipher suite
    body.push(0); // compression
    body.extend_from_slice(&be16(exts.len()));
    body.extend_from_slice(&exts);

    wrap_handshake(HS_SERVER_HELLO, &body, 0x0303)
}

fn wrap_handshake(msg_type: u8, body: &[u8], rec_version: u16) -> Vec<u8> {
    let mut hs = vec![msg_type];
    let l = body.len();
    hs.push((l >> 16) as u8);
    hs.push((l >> 8) as u8);
    hs.push(l as u8);
    hs.extend_from_slice(body);

    let mut rec = vec![REC_HANDSHAKE];
    rec.extend_from_slice(&rec_version.to_be_bytes());
    rec.extend_from_slice(&be16(hs.len()));
    rec.extend_from_slice(&hs);
    rec
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.p.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<usize> {
        let s = self.take(2)?;
        Some(((s[0] as usize) << 8) | s[1] as usize)
    }
    fn u24(&mut self) -> Option<usize> {
        let s = self.take(3)?;
        Some(((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
    }
}

/// Walk a handshake record, returning the post-(version+random+session_id) reader positioned at
/// cipher-suites (client) or cipher-suite (server), plus the session_id. `expect_type` is the
/// handshake message type (ClientHello/ServerHello).
fn into_hello<'a>(rec: &'a [u8], expect_type: u8) -> Option<(Reader<'a>, [u8; 32])> {
    let mut r = Reader { b: rec, p: 0 };
    if r.u8()? != REC_HANDSHAKE {
        return None;
    }
    r.take(2)?; // record version
    r.u16()?; // record length
    if r.u8()? != expect_type {
        return None;
    }
    r.u24()?; // handshake length
    r.take(2)?; // legacy_version
    r.take(32)?; // random
    if r.u8()? as usize != 32 {
        return None;
    }
    let sid: [u8; 32] = r.take(32)?.try_into().ok()?;
    Some((r, sid))
}

fn find_key_share(exts: &[u8], is_client: bool) -> Option<Vec<u8>> {
    let mut r = Reader { b: exts, p: 0 };
    while r.p < exts.len() {
        let etype = r.u16()?;
        let elen = r.u16()?;
        let ebody = r.take(elen)?;
        if etype == 0x0033 {
            let mut er = Reader { b: ebody, p: 0 };
            if is_client {
                er.u16()?; // client_shares list length
            }
            while er.p < ebody.len() {
                let group = er.u16()?;
                let kelen = er.u16()?;
                let ke = er.take(kelen)?;
                if group == GROUP_X25519MLKEM768 as usize {
                    return Some(ke.to_vec());
                }
            }
        }
    }
    None
}

/// Parse a ClientHello record → `(session_id, X25519MLKEM768 key_share)`.
pub fn parse_client_hello(rec: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    let (mut r, sid) = into_hello(rec, HS_CLIENT_HELLO)?;
    let cs_len = r.u16()?;
    r.take(cs_len)?;
    let comp_len = r.u8()? as usize;
    r.take(comp_len)?;
    let ext_total = r.u16()?;
    let exts = r.take(ext_total)?;
    let ks = find_key_share(exts, true)?;
    Some((sid, ks))
}

/// Parse a ServerHello record → the X25519MLKEM768 server key_share.
pub fn parse_server_hello(rec: &[u8]) -> Option<Vec<u8>> {
    let (mut r, _sid) = into_hello(rec, HS_SERVER_HELLO)?;
    r.take(2)?; // cipher_suite
    r.u8()?; // compression
    let ext_total = r.u16()?;
    let exts = r.take(ext_total)?;
    find_key_share(exts, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_roundtrip() {
        let sid = [7u8; 32];
        let ks: Vec<u8> = (0..1216u32).map(|i| i as u8).collect();
        let rec = build_client_hello(&sid, &ks, "www.example.com");
        assert_eq!(rec[0], REC_HANDSHAKE);
        assert_eq!(&rec[1..3], &[0x03, 0x01]);
        let (psid, pks) = parse_client_hello(&rec).unwrap();
        assert_eq!(psid, sid);
        assert_eq!(pks, ks);
    }

    #[test]
    fn server_hello_roundtrip() {
        let sid = [9u8; 32];
        let ks: Vec<u8> = (0..1120u32).map(|i| (i ^ 0x5a) as u8).collect();
        let rec = build_server_hello(&sid, &ks);
        assert_eq!(rec[0], REC_HANDSHAKE);
        assert_eq!(parse_server_hello(&rec).unwrap(), ks);
    }

    #[test]
    fn rejects_garbage_without_panic() {
        assert!(parse_client_hello(&[]).is_none());
        assert!(parse_client_hello(&[0x17, 0x03, 0x03, 0, 0]).is_none()); // app-data, not handshake
        assert!(parse_server_hello(&[0x16, 0x03, 0x03, 0xff, 0xff]).is_none());
        for n in 0..64 {
            let junk: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
            let _ = parse_client_hello(&junk); // must not panic
        }
    }
}
