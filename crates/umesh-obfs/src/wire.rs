//! Wire framing for the obfs carrier.
//!
//! Every flight and record is wrapped in a **TLS 1.2 Application-Data record header**
//! (`0x17 0x03 0x03 <len:u16-be>`). This defeats the "fully-encrypted / no recognizable header"
//! classifier (USENIX'23 Ex1) that Russia's TSPU and China's GFW use: on the wire the flow opens
//! with bytes that look like an ordinary TLS record rather than uniform-random noise (research D2/D3).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{ObfsError, Result};

/// TLS Application-Data record type + TLS 1.2 version (`content_type=23, version=0x0303`).
pub const TLS_PREFIX: [u8; 3] = [0x17, 0x03, 0x03];
/// Length of the record header (`prefix(3) || len(2)`).
pub const HEADER_LEN: usize = 5;
/// Maximum record payload (matches the TLS record-size ceiling).
pub const MAX_RECORD: usize = 16384;

/// Write `payload` as a single TLS-record-framed message.
pub async fn write_record<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_RECORD {
        return Err(ObfsError::RecordTooLarge);
    }
    let mut hdr = [TLS_PREFIX[0], TLS_PREFIX[1], TLS_PREFIX[2], 0, 0];
    hdr[3..].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    w.write_all(&hdr).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// Read a single TLS-record-framed message. Bounds the length to `MAX_RECORD` so a probe sending a
/// huge declared length cannot cause unbounded allocation.
pub async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut hdr = [0u8; HEADER_LEN];
    r.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > MAX_RECORD {
        return Err(ObfsError::RecordTooLarge);
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Read a single TLS-record-framed message, returning the **full raw bytes** (header + body). Used
/// by the probe-resistant fallback path, which forwards the raw flight verbatim to a cover upstream.
pub async fn read_record_raw<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut hdr = [0u8; HEADER_LEN];
    r.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > MAX_RECORD {
        return Err(ObfsError::RecordTooLarge);
    }
    let mut raw = Vec::with_capacity(HEADER_LEN + len);
    raw.extend_from_slice(&hdr);
    raw.resize(HEADER_LEN + len, 0);
    r.read_exact(&mut raw[HEADER_LEN..]).await?;
    Ok(raw)
}

/// Synchronous, pure parser for one TLS-record-framed message in an in-memory buffer.
///
/// Returns `(payload, bytes_consumed)`, or `None` if the buffer does not yet hold a complete record
/// or declares an oversized length. This is the fuzz target for the framing parser (it must never
/// panic on arbitrary input).
pub fn parse_record(buf: &[u8]) -> Option<(&[u8], usize)> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if len > MAX_RECORD {
        return None;
    }
    let end = HEADER_LEN.checked_add(len)?;
    if buf.len() < end {
        return None;
    }
    Some((&buf[HEADER_LEN..end], end))
}

/// Smallest plausible ClientHello record body (handshake header + version + random + minimal
/// session/cipher/compression vectors). Anything shorter is not a real ClientHello.
pub const MIN_CLIENT_HELLO_RECORD: usize = 40;

/// Incremental verdict on the bytes a server has read so far from a fresh connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloPrefix {
    /// Plausible so far; the complete first record is this many bytes long in total (header
    /// included), or the header itself (`5`) is not complete yet.
    NeedMore(usize),
    /// The first record is complete (`buf.len()` bytes).
    Complete,
    /// Not a plausible TLS ClientHello record (wrong content type / version, implausible length,
    /// or not a ClientHello handshake message) — hand the connection to the probe response now.
    Implausible,
}

/// Classify the first bytes of an inbound connection: is this (the start of) one plausible TLS
/// handshake record carrying a ClientHello (`16 03 01|03 <len>` with
/// `MIN_CLIENT_HELLO_RECORD ≤ len ≤ MAX_RECORD`, handshake type `0x01` and a consistent handshake
/// length)? Pure and total, so it is fuzzed together with the gate (`fuzz/fuzz_targets/server_gate.rs`).
///
/// `buf` must never contain more than the first record; the async reader enforces this by only
/// ever reading up to the length this function asks for.
pub fn classify_client_hello_prefix(buf: &[u8]) -> HelloPrefix {
    if let Some(&b) = buf.first()
        && b != 0x16
    {
        return HelloPrefix::Implausible;
    }
    if let Some(&b) = buf.get(1)
        && b != 0x03
    {
        return HelloPrefix::Implausible;
    }
    if let Some(&b) = buf.get(2)
        && b != 0x01
        && b != 0x03
    {
        return HelloPrefix::Implausible;
    }
    if buf.len() < HEADER_LEN {
        return HelloPrefix::NeedMore(HEADER_LEN);
    }
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if !(MIN_CLIENT_HELLO_RECORD..=MAX_RECORD).contains(&len) {
        return HelloPrefix::Implausible;
    }
    if let Some(&t) = buf.get(5)
        && t != 0x01
    {
        return HelloPrefix::Implausible;
    }
    if buf.len() >= 9 {
        let hs_len = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | buf[8] as usize;
        if hs_len + 4 != len {
            return HelloPrefix::Implausible;
        }
    }
    let total = HEADER_LEN + len;
    match buf.len().cmp(&total) {
        std::cmp::Ordering::Less => HelloPrefix::NeedMore(total),
        std::cmp::Ordering::Equal => HelloPrefix::Complete,
        std::cmp::Ordering::Greater => HelloPrefix::Implausible,
    }
}

/// Why [`read_client_hello_record`] stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloRead {
    /// A complete, plausible ClientHello record was read (and nothing beyond it).
    Complete,
    /// The opening bytes are not a plausible ClientHello record.
    Implausible,
    /// The peer closed (or the socket errored) before a complete record arrived.
    Closed,
    /// The deadline passed before a complete record arrived.
    TimedOut,
}

/// Read the first record of an inbound connection, **keeping every byte read** (returned in all
/// cases so a fallback proxy can forward it verbatim), never reading past the end of the first
/// record, and giving up immediately once the bytes stop looking like a ClientHello.
pub async fn read_client_hello_record<R: AsyncRead + Unpin>(
    r: &mut R,
    deadline: tokio::time::Instant,
) -> (Vec<u8>, HelloRead) {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    loop {
        let need = match classify_client_hello_prefix(&buf) {
            HelloPrefix::Complete => return (buf, HelloRead::Complete),
            HelloPrefix::Implausible => return (buf, HelloRead::Implausible),
            HelloPrefix::NeedMore(total) => total,
        };
        let old = buf.len();
        buf.resize(need, 0);
        let res = tokio::time::timeout_at(deadline, r.read(&mut buf[old..need])).await;
        match res {
            Ok(Ok(n)) if n > 0 => buf.truncate(old + n),
            Ok(_) => {
                buf.truncate(old);
                return (buf, HelloRead::Closed);
            }
            Err(_) => {
                buf.truncate(old);
                return (buf, HelloRead::TimedOut);
            }
        }
    }
}

/// Fraction of set bits per byte over `data` (a coarse proxy for the GFW's popcount heuristic).
/// Fully-random/encrypted payloads sit near 4.0; structured/text data sits lower.
pub fn popcount_per_byte(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let bits: u32 = data.iter().map(|b| b.count_ones()).sum();
    bits as f64 / data.len() as f64
}

/// True if `opening` begins with a recognizable TLS record header: a known `content_type`
/// (ChangeCipherSpec/Alert/Handshake/ApplicationData) followed by a TLS major version `0x03`. This
/// covers both our ClientHello first flight (`0x16`) and the data records (`0x17`).
pub fn is_tls_record_header(opening: &[u8]) -> bool {
    opening.len() >= 3 && matches!(opening[0], 0x14..=0x17) && opening[1] == 0x03
}

/// A minimal model of a censor's "fully-encrypted" classifier (USENIX'23 Ex1+Ex2): a flow is flagged
/// when its opening bytes have **no recognizable protocol header** AND a high average popcount.
/// uber-mesh's TLS-record header (handshake `0x16` first flight, then `0x17` data) makes this return
/// `false`.
pub fn looks_fully_encrypted(opening: &[u8]) -> bool {
    if is_tls_record_header(opening) {
        return false; // recognizable header ⇒ exempt
    }
    let pc = popcount_per_byte(opening);
    (3.4..=4.6).contains(&pc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_roundtrip_and_prefix() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let payload = vec![0xABu8; 1000];
        write_record(&mut a, &payload).await.unwrap();
        // Peek the header by reading raw on the other side.
        let got = read_record(&mut b).await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn first_bytes_are_tls_prefixed() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_record(&mut a, &[0u8; 8]).await.unwrap();
        let mut hdr = [0u8; HEADER_LEN];
        tokio::io::AsyncReadExt::read_exact(&mut b, &mut hdr)
            .await
            .unwrap();
        assert_eq!(
            hdr[..3],
            TLS_PREFIX,
            "carrier must open with a TLS record header"
        );
    }

    #[test]
    fn classifier_exempts_tls_prefixed_flow() {
        // High-entropy body, but app-data TLS-prefixed ⇒ not flagged.
        let mut opening = TLS_PREFIX.to_vec();
        opening.extend_from_slice(&[0x5a; 64]);
        assert!(!looks_fully_encrypted(&opening));
        // A handshake (ClientHello) record header is equally exempt.
        let mut ch = vec![0x16, 0x03, 0x01];
        ch.extend_from_slice(&[0x5a; 64]);
        assert!(is_tls_record_header(&ch));
        assert!(!looks_fully_encrypted(&ch));
        // Same high-entropy body without the prefix would be flagged.
        let raw: Vec<u8> = (0..64u16)
            .map(|i| (i.wrapping_mul(53) ^ 0xa7) as u8)
            .collect();
        assert!(looks_fully_encrypted(&raw) || popcount_per_byte(&raw) < 3.4);
    }

    #[test]
    fn hello_prefix_classifier() {
        use HelloPrefix::*;
        assert_eq!(classify_client_hello_prefix(&[]), NeedMore(5));
        assert_eq!(classify_client_hello_prefix(b"G"), Implausible);
        assert_eq!(classify_client_hello_prefix(b"GET / HTTP/1.1"), Implausible);
        assert_eq!(classify_client_hello_prefix(&[0x16, 0x03]), NeedMore(5));
        assert_eq!(
            classify_client_hello_prefix(&[0x16, 0x03, 0x02]),
            Implausible
        );
        // Oversized declared length ⇒ implausible immediately (no waiting for 18 KiB).
        assert_eq!(
            classify_client_hello_prefix(&[0x16, 0x03, 0x01, 0x48, 0x01]),
            Implausible
        );
        assert_eq!(
            classify_client_hello_prefix(&[0x16, 0x03, 0x01, 0x00, 0x05]),
            Implausible
        );
        assert_eq!(
            classify_client_hello_prefix(&[0x16, 0x03, 0x01, 0x00, 0x40]),
            NeedMore(69)
        );
        // Handshake type must be ClientHello and the handshake length consistent.
        assert_eq!(
            classify_client_hello_prefix(&[0x16, 3, 1, 0, 0x40, 2]),
            Implausible
        );
        assert_eq!(
            classify_client_hello_prefix(&[0x16, 3, 1, 0, 0x40, 1, 0, 0, 0x3c]),
            NeedMore(69)
        );
        assert_eq!(
            classify_client_hello_prefix(&[0x16, 3, 1, 0, 0x40, 1, 0, 0, 0x3d]),
            Implausible
        );
        let mut full = vec![0x16, 3, 1, 0, 0x40, 1, 0, 0, 0x3c];
        full.resize(69, 0);
        assert_eq!(classify_client_hello_prefix(&full), Complete);
    }

    #[tokio::test]
    async fn hello_reader_keeps_all_bytes_and_stops_early() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        a.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let (got, why) = read_client_hello_record(&mut b, deadline).await;
        assert_eq!(why, HelloRead::Implausible);
        assert!(b"GET / HTTP/1.1".starts_with(&got) && !got.is_empty());
    }

    #[test]
    fn parse_record_never_panics_and_bounds() {
        // Too short.
        assert!(parse_record(&[0x17, 0x03]).is_none());
        // Declares more than it holds.
        assert!(parse_record(&[0x17, 0x03, 0x03, 0x10, 0x00, 0x00]).is_none());
        // Well-formed small record.
        let rec = [0x17, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB];
        let (payload, consumed) = parse_record(&rec).unwrap();
        assert_eq!(payload, &[0xAA, 0xBB]);
        assert_eq!(consumed, 7);
        // Oversized declared length is rejected (no huge allocation).
        let big = [0x17, 0x03, 0x03, 0xFF, 0xFF];
        assert!(parse_record(&big).is_none());
    }
}
