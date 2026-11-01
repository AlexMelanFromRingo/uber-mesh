//! Post-handshake secure record stream: AEAD-protected, length-hidden, shaped.
//!
//! Each application message becomes one record: `AEAD(seal)( u32 real_len || data || padding )`,
//! itself TLS-record-framed on the wire. The AEAD **AAD binds the direction tag and a per-direction
//! monotonic record counter**, so reordering, replay, injection, or truncation of records within a
//! session is detected (TCP delivers in order; a mismatch ⇒ decrypt failure). Padding (from the
//! [`ShapingPolicy`]) hides the true length; the receiver recovers `data` via the inner length
//! prefix and ignores the padding.

use tokio::io::{AsyncRead, AsyncWrite};
use umesh_crypto::aead::{self, AeadKey};

use crate::error::{ObfsError, Result};
use crate::handshake::SessionKeys;
use crate::shaping::ShapingPolicy;
use crate::wire::{MAX_RECORD, read_record, write_record};

const INNER_HEADER: usize = 4; // u32 real length
const AEAD_OVERHEAD: usize = 24 + 16; // nonce + tag
/// Maximum application payload per [`SecureStream::send`] call.
pub const MAX_MESSAGE: usize = MAX_RECORD - AEAD_OVERHEAD - INNER_HEADER - 512;

/// AAD = direction(1) || record-counter(8, little-endian).
fn record_aad(dir: u8, ctr: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[0] = dir;
    aad[1..].copy_from_slice(&ctr.to_le_bytes());
    aad
}

/// An authenticated, length-hidden, shaped message stream over an obfuscated carrier.
pub struct SecureStream<S> {
    inner: S,
    send: AeadKey,
    recv: AeadKey,
    send_dir: u8,
    recv_dir: u8,
    send_ctr: u64,
    recv_ctr: u64,
    shaping: ShapingPolicy,
    channel_binding: [u8; 32],
}

impl<S> SecureStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap a handshaked carrier with directional keys and a shaping policy.
    pub fn new(inner: S, keys: SessionKeys, shaping: ShapingPolicy) -> Self {
        SecureStream {
            inner,
            send: keys.send,
            recv: keys.recv,
            send_dir: keys.send_dir,
            recv_dir: keys.recv_dir,
            send_ctr: 0,
            recv_ctr: 0,
            shaping,
            channel_binding: keys.channel_binding,
        }
    }

    /// This session's channel binding (see [`SessionKeys::channel_binding`]).
    pub fn channel_binding(&self) -> &[u8; 32] {
        &self.channel_binding
    }

    /// Send one application message (≤ [`MAX_MESSAGE`] bytes) as a padded, encrypted record.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_MESSAGE {
            return Err(ObfsError::RecordTooLarge);
        }
        let real_len = u32::try_from(data.len()).map_err(|_| ObfsError::RecordTooLarge)?;
        let framed = INNER_HEADER + data.len();
        // Pad per policy, but never overflow the record ceiling.
        let max_pad = MAX_RECORD - AEAD_OVERHEAD - framed;
        let pad = self.shaping.pad_len(framed).min(max_pad);

        let mut inner = Vec::with_capacity(framed + pad);
        inner.extend_from_slice(&real_len.to_le_bytes());
        inner.extend_from_slice(data);
        inner.resize(framed + pad, 0);

        let aad = record_aad(self.send_dir, self.send_ctr);
        let wire = aead::seal(&self.send, &inner, &aad);
        self.send_ctr = self.send_ctr.wrapping_add(1);
        self.shaping.jitter().await;
        write_record(&mut self.inner, &wire).await
    }

    /// Receive one application message, stripping padding.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let wire = read_record(&mut self.inner).await?;
        let aad = record_aad(self.recv_dir, self.recv_ctr);
        let inner = aead::open(&self.recv, &wire, &aad)?;
        self.recv_ctr = self.recv_ctr.wrapping_add(1);
        if inner.len() < INNER_HEADER {
            return Err(ObfsError::Malformed);
        }
        let real = u32::from_le_bytes(
            inner[..INNER_HEADER]
                .try_into()
                .map_err(|_| ObfsError::Malformed)?,
        ) as usize;
        // checked_add guards against integer overflow on 32-bit usize targets.
        match INNER_HEADER.checked_add(real) {
            Some(end) if end <= inner.len() => Ok(inner[INNER_HEADER..end].to_vec()),
            _ => Err(ObfsError::Malformed),
        }
    }

    /// Borrow the underlying carrier (e.g. to inspect the peer address).
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{DIR_C2S, DIR_S2C};

    fn client_keys() -> SessionKeys {
        SessionKeys {
            send: AeadKey::from_bytes([1; 32]),
            recv: AeadKey::from_bytes([2; 32]),
            send_dir: DIR_C2S,
            recv_dir: DIR_S2C,
            channel_binding: [7; 32],
        }
    }

    fn server_keys() -> SessionKeys {
        SessionKeys {
            send: AeadKey::from_bytes([2; 32]),
            recv: AeadKey::from_bytes([1; 32]),
            send_dir: DIR_S2C,
            recv_dir: DIR_C2S,
            channel_binding: [7; 32],
        }
    }

    #[tokio::test]
    async fn message_roundtrip_with_padding() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = SecureStream::new(a, client_keys(), ShapingPolicy::aggressive());
        let mut server = SecureStream::new(b, server_keys(), ShapingPolicy::aggressive());

        let server = tokio::spawn(async move {
            let m1 = server.recv().await.unwrap();
            let m2 = server.recv().await.unwrap();
            (m1, m2)
        });
        client.send(b"first message").await.unwrap();
        client.send(b"second message").await.unwrap();
        let (m1, m2) = server.await.unwrap();
        assert_eq!(m1, b"first message");
        assert_eq!(m2, b"second message");
    }

    #[tokio::test]
    async fn counter_mismatch_breaks_decrypt() {
        // If the receiver's counter is out of step (simulating a dropped/injected record), the AAD
        // won't match and decryption fails.
        let (a, b) = tokio::io::duplex(8192);
        let mut client = SecureStream::new(a, client_keys(), ShapingPolicy::none());
        let mut server = SecureStream::new(b, server_keys(), ShapingPolicy::none());
        server.recv_ctr = 5; // desynchronized
        let srv = tokio::spawn(async move { server.recv().await });
        client.send(b"x").await.unwrap();
        assert!(srv.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn tampering_breaks_decrypt() {
        let (a, b) = tokio::io::duplex(8192);
        let mut client = SecureStream::new(a, client_keys(), ShapingPolicy::none());
        // Wrong recv key.
        let bad = SessionKeys {
            send: AeadKey::from_bytes([9; 32]),
            recv: AeadKey::from_bytes([9; 32]),
            send_dir: DIR_S2C,
            recv_dir: DIR_C2S,
            channel_binding: [7; 32],
        };
        let mut server = SecureStream::new(b, bad, ShapingPolicy::none());
        let srv = tokio::spawn(async move { server.recv().await });
        client.send(b"x").await.unwrap();
        assert!(srv.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn oversized_message_rejected() {
        let (a, _b) = tokio::io::duplex(1024);
        let mut s = SecureStream::new(a, client_keys(), ShapingPolicy::none());
        assert!(matches!(
            s.send(&vec![0u8; MAX_MESSAGE + 1]).await,
            Err(ObfsError::RecordTooLarge)
        ));
    }

    /// Audit F6 regression: aggressive shaping produced records whose length was always
    /// ≡ 5 + 40 + 16 (mod 512) — a static length signature. Random padding now rides on top of the
    /// bucket, so the residue varies.
    #[tokio::test]
    async fn aggressive_padding_is_not_a_constant_bucket_residue() {
        let (a, mut b) = tokio::io::duplex(1024 * 1024);
        let mut s = SecureStream::new(
            a,
            client_keys(),
            ShapingPolicy {
                iat_jitter_ms: 0,
                ..ShapingPolicy::aggressive()
            },
        );
        let mut residues = std::collections::HashSet::new();
        for n in [1usize, 50, 600, 3000, 9999] {
            for _ in 0..8 {
                s.send(&vec![0u8; n]).await.unwrap();
                let r = crate::wire::read_record_raw(&mut b).await.unwrap();
                residues.insert(r.len() % 512);
            }
        }
        assert!(residues.len() > 4, "residues {residues:?}");
    }
}
