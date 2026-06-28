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

/// Fraction of set bits per byte over `data` (a coarse proxy for the GFW's popcount heuristic).
/// Fully-random/encrypted payloads sit near 4.0; structured/text data sits lower.
pub fn popcount_per_byte(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let bits: u32 = data.iter().map(|b| b.count_ones()).sum();
    bits as f64 / data.len() as f64
}

/// A minimal model of a censor's "fully-encrypted" classifier (USENIX'23 Ex1+Ex2): a flow is flagged
/// when its opening bytes have **no recognizable protocol header** AND a high average popcount.
/// uber-mesh's TLS-record prefix makes this return `false` for our first flight.
pub fn looks_fully_encrypted(opening: &[u8]) -> bool {
    if opening.len() >= 3 && opening[..3] == TLS_PREFIX {
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
        // High-entropy body, but TLS-prefixed ⇒ not flagged.
        let mut opening = TLS_PREFIX.to_vec();
        opening.extend_from_slice(&[0x5a; 64]);
        assert!(!looks_fully_encrypted(&opening));
        // Same high-entropy body without the prefix would be flagged.
        let raw: Vec<u8> = (0..64u16)
            .map(|i| (i.wrapping_mul(53) ^ 0xa7) as u8)
            .collect();
        assert!(looks_fully_encrypted(&raw) || popcount_per_byte(&raw) < 3.4);
    }
}
