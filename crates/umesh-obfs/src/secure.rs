//! Post-handshake secure record stream: AEAD-protected, length-hidden, shaped.
//!
//! Each application message becomes one record: `AEAD(seal)( u32 real_len || data || padding )`,
//! itself TLS-record-framed on the wire. Padding (from the [`ShapingPolicy`]) hides the true length;
//! the receiver recovers `data` via the inner length prefix and ignores the padding.

use tokio::io::{AsyncRead, AsyncWrite};
use umesh_crypto::aead::{self, AeadKey};

use crate::error::{ObfsError, Result};
use crate::handshake::SessionKeys;
use crate::shaping::ShapingPolicy;
use crate::wire::{MAX_RECORD, read_record, write_record};

const REC_AAD: &[u8] = b"uber-mesh-rec-v1";
const INNER_HEADER: usize = 4; // u32 real length
const AEAD_OVERHEAD: usize = 24 + 16; // nonce + tag
/// Maximum application payload per [`SecureStream::send`] call.
pub const MAX_MESSAGE: usize = MAX_RECORD - AEAD_OVERHEAD - INNER_HEADER - 512;

/// An authenticated, length-hidden, shaped message stream over an obfuscated carrier.
pub struct SecureStream<S> {
    inner: S,
    send: AeadKey,
    recv: AeadKey,
    shaping: ShapingPolicy,
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
            shaping,
        }
    }

    /// Send one application message (≤ [`MAX_MESSAGE`] bytes) as a padded, encrypted record.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_MESSAGE {
            return Err(ObfsError::RecordTooLarge);
        }
        let framed = INNER_HEADER + data.len();
        // Pad per policy, but never overflow the record ceiling.
        let max_pad = MAX_RECORD - AEAD_OVERHEAD - framed;
        let pad = self.shaping.pad_len(framed).min(max_pad);

        let mut inner = Vec::with_capacity(framed + pad);
        inner.extend_from_slice(&(data.len() as u32).to_le_bytes());
        inner.extend_from_slice(data);
        inner.resize(framed + pad, 0);

        let wire = aead::seal(&self.send, &inner, REC_AAD);
        self.shaping.jitter().await;
        write_record(&mut self.inner, &wire).await
    }

    /// Receive one application message, stripping padding.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let wire = read_record(&mut self.inner).await?;
        let inner = aead::open(&self.recv, &wire, REC_AAD)?;
        if inner.len() < INNER_HEADER {
            return Err(ObfsError::Malformed);
        }
        let real = u32::from_le_bytes(inner[..INNER_HEADER].try_into().unwrap()) as usize;
        if INNER_HEADER + real > inner.len() {
            return Err(ObfsError::Malformed);
        }
        Ok(inner[INNER_HEADER..INNER_HEADER + real].to_vec())
    }

    /// Borrow the underlying carrier (e.g. to inspect the peer address).
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(send: u8, recv: u8) -> SessionKeys {
        SessionKeys {
            send: AeadKey::from_bytes([send; 32]),
            recv: AeadKey::from_bytes([recv; 32]),
        }
    }

    #[tokio::test]
    async fn message_roundtrip_with_padding() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = SecureStream::new(a, keys(1, 2), ShapingPolicy::aggressive());
        let mut server = SecureStream::new(b, keys(2, 1), ShapingPolicy::aggressive());

        let msg = b"hello over a censored link".to_vec();
        let cmsg = msg.clone();
        let srv = tokio::spawn(async move { server.recv().await.unwrap() });
        client.send(&cmsg).await.unwrap();
        assert_eq!(srv.await.unwrap(), msg);
    }

    #[tokio::test]
    async fn tampering_breaks_decrypt() {
        // Mismatched keys (as a stand-in for tampering) must fail to decrypt.
        let (a, b) = tokio::io::duplex(8192);
        let mut client = SecureStream::new(a, keys(1, 2), ShapingPolicy::none());
        let mut server = SecureStream::new(b, keys(9, 9), ShapingPolicy::none());
        let srv = tokio::spawn(async move { server.recv().await });
        client.send(b"x").await.unwrap();
        assert!(srv.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn oversized_message_rejected() {
        let (a, _b) = tokio::io::duplex(1024);
        let mut s = SecureStream::new(a, keys(1, 2), ShapingPolicy::none());
        assert!(matches!(
            s.send(&vec![0u8; MAX_MESSAGE + 1]).await,
            Err(ObfsError::RecordTooLarge)
        ));
    }
}
