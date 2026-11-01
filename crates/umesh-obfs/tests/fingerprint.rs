//! ClientHello fingerprint conformance: every hello the obfs client (and the cover-profile learner)
//! sends must be **Chrome 133+ stable** at the JA4 level and field-for-field otherwise.
//!
//! - JA4 (FoxIO spec) is computed here independently of `umesh_obfs::tls` and must equal
//!   `t13d1516h2_8daaf6152771_d8a2da3f94cd` for every generated hello (`t13i1515h2_…` when the SNI
//!   is omitted, as Chrome does for IP literals).
//! - JA3 is computed for documentation: like real Chrome's it changes per connection (extension
//!   permutation), while its order-normalised form is constant.
//! - Each extension body is checked byte-for-byte against the Chrome template, including GREASE
//!   placement and the GREASE-ECH payload sizes.
//!
//! SHA-256 / MD5 below are **test oracles only** (fingerprint hashing, never security): no hash
//! crate is a dependency of this crate, and adding one is not worth a lockfile change. Both are
//! checked against their standard test vectors.

use std::collections::HashSet;

use rand::SeedableRng;
use rand::rngs::StdRng;
use umesh_obfs::ObfsPsk;
use umesh_obfs::handshake::build_gated_client_hello;
use umesh_obfs::tls::{self, CHROME_JA4};

// ── Test-oracle hashes ───────────────────────────────────────────────────────────────────────────
// Standard RustCrypto implementations (constitution Principle I: no hand-rolled primitives, even in
// tests). MD5 is used only because JA3 is defined over it.

fn sha256(msg: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(msg).into()
}

fn md5(msg: &[u8]) -> [u8; 16] {
    use md5::Digest;
    md5::Md5::digest(msg).into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn oracle_hashes_match_standard_vectors() {
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        hex(&md5(b"The quick brown fox jumps over the lazy dog")),
        "9e107d9d372bb6826bd81d3542a419d6"
    );
}

// ── Independent ClientHello walker ───────────────────────────────────────────────────────────────

fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 12 == (v >> 4) & 0xf
}

fn u16_at(b: &[u8], p: usize) -> u16 {
    u16::from_be_bytes([b[p], b[p + 1]])
}

fn u16s(b: &[u8]) -> Vec<u16> {
    b.chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

struct Hello {
    record_version: u16,
    legacy_version: u16,
    session_id_len: usize,
    ciphers: Vec<u16>,
    compression: Vec<u8>,
    exts: Vec<(u16, Vec<u8>)>,
}

fn walk(rec: &[u8]) -> Hello {
    assert_eq!(rec[0], 0x16);
    assert_eq!(u16_at(rec, 3) as usize, rec.len() - 5);
    assert_eq!(rec[5], 0x01);
    let mut p = 9;
    let legacy_version = u16_at(rec, p);
    p += 2 + 32;
    let session_id_len = rec[p] as usize;
    p += 1 + session_id_len;
    let n = u16_at(rec, p) as usize;
    let ciphers = u16s(&rec[p + 2..p + 2 + n]);
    p += 2 + n;
    let n = rec[p] as usize;
    let compression = rec[p + 1..p + 1 + n].to_vec();
    p += 1 + n;
    let end = p + 2 + u16_at(rec, p) as usize;
    assert_eq!(end, rec.len());
    p += 2;
    let mut exts = Vec::new();
    while p < end {
        let t = u16_at(rec, p);
        let l = u16_at(rec, p + 2) as usize;
        exts.push((t, rec[p + 4..p + 4 + l].to_vec()));
        p += 4 + l;
    }
    Hello {
        record_version: u16_at(rec, 1),
        legacy_version,
        session_id_len,
        ciphers,
        compression,
        exts,
    }
}

fn ext(h: &Hello, t: u16) -> Option<&[u8]> {
    h.exts.iter().find(|(x, _)| *x == t).map(|(_, b)| &b[..])
}

fn sig_algs(h: &Hello) -> Vec<u16> {
    let b = ext(h, 0x000d).expect("signature_algorithms");
    u16s(&b[2..])
}

/// JA4 (FoxIO, TCP): `t{ver}{d|i}{nc:02}{ne:02}{alpn}_{sha12(sorted ciphers)}_{sha12(sorted exts w/o
/// SNI+ALPN "_" sigalgs in order)}`; GREASE ignored everywhere.
fn ja4(h: &Hello) -> String {
    let versions = ext(h, 0x002b)
        .map(|b| u16s(&b[1..]))
        .unwrap_or_else(|| vec![h.legacy_version]);
    let max = versions.iter().filter(|v| !is_grease(**v)).max().unwrap();
    let ver = match *max {
        0x0304 => "13",
        0x0303 => "12",
        _ => "00",
    };
    let sni = if ext(h, 0x0000).is_some() { 'd' } else { 'i' };
    let ciphers: Vec<u16> = h
        .ciphers
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let exts: Vec<u16> = h
        .exts
        .iter()
        .map(|(t, _)| *t)
        .filter(|t| !is_grease(*t))
        .collect();
    let alpn = ext(h, 0x0010)
        .map(|b| {
            let first = &b[3..3 + b[2] as usize];
            format!("{}{}", first[0] as char, *first.last().unwrap() as char)
        })
        .unwrap_or_else(|| "00".into());
    let a = format!("t{ver}{sni}{:02}{:02}{alpn}", ciphers.len(), exts.len());

    let mut cs: Vec<String> = ciphers.iter().map(|c| format!("{c:04x}")).collect();
    cs.sort();
    let b = &hex(&sha256(cs.join(",").as_bytes()))[..12];

    let mut es: Vec<String> = exts
        .iter()
        .filter(|t| **t != 0x0000 && **t != 0x0010)
        .map(|t| format!("{t:04x}"))
        .collect();
    es.sort();
    let sa: Vec<String> = sig_algs(h).iter().map(|s| format!("{s:04x}")).collect();
    let c_in = format!("{}_{}", es.join(","), sa.join(","));
    let c = &hex(&sha256(c_in.as_bytes()))[..12];
    format!("{a}_{b}_{c}")
}

/// JA3 string: `version,ciphers,extensions,groups,point_formats` (decimal, '-'-joined, GREASE
/// removed, wire order). `sorted = true` gives the order-normalised variant.
fn ja3_string(h: &Hello, sorted: bool) -> String {
    let j = |v: Vec<u16>| {
        v.iter()
            .filter(|x| !is_grease(**x))
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    let mut exts: Vec<u16> = h.exts.iter().map(|(t, _)| *t).collect();
    if sorted {
        exts.sort();
    }
    let groups = ext(h, 0x000a).map(|b| u16s(&b[2..])).unwrap_or_default();
    let pf = ext(h, 0x000b)
        .map(|b| b[1..].iter().map(|x| *x as u16).collect())
        .unwrap_or_default();
    format!(
        "{},{},{},{},{}",
        h.legacy_version,
        j(h.ciphers.clone()),
        j(exts),
        j(groups),
        j(pf)
    )
}

fn hellos(n: u64, sni: &str) -> Vec<Vec<u8>> {
    let psk = ObfsPsk::new([0x3a; 32]);
    let share: Vec<u8> = (0..tls::HYBRID_CLIENT_SHARE_LEN)
        .map(|i| (i * 7) as u8)
        .collect();
    (0..n)
        .map(|seed| {
            build_gated_client_hello(
                &mut StdRng::seed_from_u64(seed),
                &psk,
                29_000_000,
                &share,
                sni,
            )
        })
        .collect()
}

// ── Tests ────────────────────────────────────────────────────────────────────────────────────────

/// The pre-images the JA4 b/c hashes are taken over — the exact Chrome 133+ lists.
#[test]
fn ja4_preimages_are_chromes() {
    let h = walk(&hellos(1, "www.example.com")[0]);
    let mut cs: Vec<String> = h
        .ciphers
        .iter()
        .filter(|c| !is_grease(**c))
        .map(|c| format!("{c:04x}"))
        .collect();
    cs.sort();
    assert_eq!(
        cs.join(","),
        "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
    );
    assert_eq!(&hex(&sha256(cs.join(",").as_bytes()))[..12], "8daaf6152771");
    let c_in = "0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_\
                0403,0804,0401,0503,0805,0501,0806,0601";
    assert_eq!(&hex(&sha256(c_in.as_bytes()))[..12], "d8a2da3f94cd");
}

/// JA4 equals Chrome 133+'s for every generated hello (many seeds, several SNIs).
#[test]
fn ja4_is_chrome_133_for_every_hello() {
    for sni in [
        "www.example.com",
        "a.b",
        "cdn-17.static.cover-site.example.org",
    ] {
        for rec in hellos(300, sni) {
            assert_eq!(ja4(&walk(&rec)), CHROME_JA4, "sni={sni}");
        }
    }
    // Chrome omits SNI for IP literals → `i`, 15 extensions; the hashes are unchanged.
    for rec in hellos(20, "192.0.2.7") {
        assert_eq!(ja4(&walk(&rec)), "t13i1515h2_8daaf6152771_d8a2da3f94cd");
    }
}

/// JA3 varies per connection (Chrome's extension permutation), its normalised form does not.
#[test]
fn ja3_varies_like_chrome_but_normalised_ja3_is_constant() {
    let hs: Vec<Hello> = hellos(64, "www.example.com")
        .iter()
        .map(|r| walk(r))
        .collect();
    let ja3: HashSet<String> = hs
        .iter()
        .map(|h| hex(&md5(ja3_string(h, false).as_bytes())))
        .collect();
    let ja3n: HashSet<String> = hs.iter().map(|h| ja3_string(h, true)).collect();
    assert!(
        ja3.len() >= 60,
        "JA3 should be per-connection: {} distinct",
        ja3.len()
    );
    assert_eq!(ja3n.len(), 1);
    assert_eq!(
        ja3n.into_iter().next().unwrap(),
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,\
         0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281,4588-29-23-24,0"
    );
}

/// Every field byte-for-byte against the Chrome template.
#[test]
fn every_field_matches_chrome_template() {
    let mut first_exts = HashSet::new();
    let mut ech_lens = HashSet::new();
    for rec in hellos(400, "www.example.com") {
        let h = walk(&rec);
        assert_eq!(h.record_version, 0x0301);
        assert_eq!(h.legacy_version, 0x0303);
        assert_eq!(h.session_id_len, 32);
        assert_eq!(h.compression, vec![0]);
        // Ciphers: GREASE first, then Chrome's 15 in order.
        assert!(is_grease(h.ciphers[0]));
        assert_eq!(
            h.ciphers[1..],
            [
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035
            ]
        );
        // GREASE extensions: first (empty) and last (one 0 byte), distinct; none in between.
        let (g1, b1) = &h.exts[0];
        let (g2, b2) = h.exts.last().unwrap();
        assert!(is_grease(*g1) && b1.is_empty());
        assert!(is_grease(*g2) && b2 == &[0u8]);
        assert_ne!(g1, g2);
        let mid = &h.exts[1..h.exts.len() - 1];
        assert!(mid.iter().all(|(t, _)| !is_grease(*t)));
        assert_eq!(mid.len(), 16);
        first_exts.insert(mid[0].0);
        // No padding, no pre_shared_key / early_data, no record_size_limit, no delegated creds.
        for absent in [0x0015, 0x0029, 0x002a, 0x001c, 0x0022] {
            assert!(ext(&h, absent).is_none(), "{absent:#06x}");
        }
        let e = |t: u16| ext(&h, t).unwrap_or_else(|| panic!("missing {t:#06x}"));
        let mut sni = vec![0x00, 0x12, 0x00, 0x00, 0x0f];
        sni.extend_from_slice(b"www.example.com");
        assert_eq!(e(0x0000), sni);
        assert_eq!(e(0x0017), b"");
        assert_eq!(e(0xff01), [0x00]);
        let groups = u16s(&e(0x000a)[2..]);
        assert_eq!(u16_at(e(0x000a), 0), 10);
        assert!(is_grease(groups[0]));
        assert_eq!(groups[1..], [0x11ec, 0x001d, 0x0017, 0x0018]);
        assert_eq!(e(0x000b), [0x01, 0x00]);
        assert_eq!(e(0x0023), b"");
        assert_eq!(e(0x0010), b"\x00\x0c\x02h2\x08http/1.1");
        assert_eq!(e(0x0005), [0x01, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(u16_at(e(0x000d), 0), 16);
        assert_eq!(
            sig_algs(&h),
            [
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601
            ]
        );
        assert_eq!(e(0x0012), b"");
        // key_share: [GREASE (same as the group GREASE) 1 B 00, 11ec 1216 B, 001d 32 B].
        let ks = e(0x0033);
        assert_eq!(u16_at(ks, 0) as usize, ks.len() - 2);
        assert_eq!(u16_at(ks, 2), groups[0]);
        assert_eq!(&ks[4..7], &[0x00, 0x01, 0x00]);
        assert_eq!(u16_at(ks, 7), 0x11ec);
        assert_eq!(u16_at(ks, 9), 1216);
        let x = 11 + 1216;
        assert_eq!(u16_at(ks, x), 0x001d);
        assert_eq!(u16_at(ks, x + 2), 32);
        assert_eq!(ks.len(), x + 4 + 32);
        assert_eq!(
            ks[x + 4 + 31] & 0x80,
            0,
            "x25519 share is a canonical u-coordinate"
        );
        assert_eq!(e(0x002d), [0x01, 0x01]);
        let sv = e(0x002b);
        assert_eq!(sv[0], 6);
        assert!(is_grease(u16_at(sv, 1)));
        assert_eq!(&sv[3..], &[0x03, 0x04, 0x03, 0x03]);
        assert_eq!(e(0x001b), [0x02, 0x00, 0x02]);
        assert_eq!(e(0x44cd), b"\x00\x03\x02h2");
        // GREASE ECH: outer, HKDF-SHA256 / AES-128-GCM, config_id, 32-B enc, 144|176|208|240 B.
        let ech = e(0xfe0d);
        assert_eq!(&ech[..5], &[0x00, 0x00, 0x01, 0x00, 0x01]);
        assert_eq!(u16_at(ech, 6), 32);
        let pl = u16_at(ech, 40) as usize;
        assert_eq!(ech.len(), 42 + pl);
        assert!([144, 176, 208, 240].contains(&pl), "{pl}");
        ech_lens.insert(pl);
    }
    assert!(
        first_exts.len() >= 12,
        "extension order is permuted per connection"
    );
    assert_eq!(ech_lens.len(), 4, "all four GREASE-ECH payload sizes occur");
}
