//! A poll-based byte stream (`AsyncRead + AsyncWrite`) over the obfs AEAD record framing.
//!
//! Where [`crate::secure::SecureStream`] is message-oriented (`send`/`recv`), `ObfsByteStream`
//! presents a plain byte stream so it can carry an arbitrary protocol — specifically libp2p's
//! Noise+Yamux upgrade. Every chunk written becomes one TLS-record-framed AEAD record (AAD binds
//! direction + a monotonic counter); reads reassemble records and yield the decrypted bytes. This is
//! the adapter that lets the obfuscated, probe-resistant carrier sit **below** libp2p Noise (T032).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use umesh_crypto::aead::{self, AeadKey};

use crate::handshake::SessionKeys;
use crate::wire::{HEADER_LEN, MAX_RECORD, TLS_PREFIX};

const INNER_HEADER: usize = 4;
const AEAD_OVERHEAD: usize = 24 + 16;
const MAX_CHUNK: usize = MAX_RECORD - AEAD_OVERHEAD - INNER_HEADER;

fn record_aad(dir: u8, ctr: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[0] = dir;
    aad[1..].copy_from_slice(&ctr.to_le_bytes());
    aad
}

#[derive(PartialEq)]
enum RState {
    Header,
    Body,
}

/// Byte-stream adapter over the obfs secure record channel.
pub struct ObfsByteStream<S> {
    inner: S,
    send: AeadKey,
    recv: AeadKey,
    send_dir: u8,
    recv_dir: u8,
    send_ctr: u64,
    recv_ctr: u64,

    // read state
    rstate: RState,
    hdr: [u8; HEADER_LEN],
    hdr_filled: usize,
    body: Vec<u8>,
    body_filled: usize,
    plain: Vec<u8>,
    plain_pos: usize,

    // write state
    wbuf: Vec<u8>,
    wpos: usize,
}

impl<S> ObfsByteStream<S> {
    /// Wrap a handshaked carrier with the session's directional keys.
    pub fn new(inner: S, keys: SessionKeys) -> Self {
        ObfsByteStream {
            inner,
            send: keys.send,
            recv: keys.recv,
            send_dir: keys.send_dir,
            recv_dir: keys.recv_dir,
            send_ctr: 0,
            recv_ctr: 0,
            rstate: RState::Header,
            hdr: [0u8; HEADER_LEN],
            hdr_filled: 0,
            body: Vec::new(),
            body_filled: 0,
            plain: Vec::new(),
            plain_pos: 0,
            wbuf: Vec::new(),
            wpos: 0,
        }
    }
}

impl<S: AsyncWrite + Unpin> ObfsByteStream<S> {
    /// Flush any buffered (already-framed) outgoing bytes to the underlying writer.
    fn flush_wbuf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")));
            }
            self.wpos += n;
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObfsByteStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            // 1. Drain already-decrypted plaintext.
            if me.plain_pos < me.plain.len() {
                let n = (out.remaining()).min(me.plain.len() - me.plain_pos);
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                out.put_slice(&me.plain[me.plain_pos..me.plain_pos + n]);
                me.plain_pos += n;
                return Poll::Ready(Ok(()));
            }

            // 2. Pull the next record.
            match me.rstate {
                RState::Header => {
                    let mut rb = ReadBuf::new(&mut me.hdr[me.hdr_filled..]);
                    ready!(Pin::new(&mut me.inner).poll_read(cx, &mut rb))?;
                    let got = rb.filled().len();
                    if got == 0 {
                        // EOF: clean only at a record boundary.
                        if me.hdr_filled == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    me.hdr_filled += got;
                    if me.hdr_filled == HEADER_LEN {
                        let len = u16::from_be_bytes([me.hdr[3], me.hdr[4]]) as usize;
                        if len == 0 || len > MAX_RECORD {
                            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                        }
                        me.body = vec![0u8; len];
                        me.body_filled = 0;
                        me.rstate = RState::Body;
                    }
                }
                RState::Body => {
                    let mut rb = ReadBuf::new(&mut me.body[me.body_filled..]);
                    ready!(Pin::new(&mut me.inner).poll_read(cx, &mut rb))?;
                    let got = rb.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    me.body_filled += got;
                    if me.body_filled == me.body.len() {
                        let aad = record_aad(me.recv_dir, me.recv_ctr);
                        let inner = aead::open(&me.recv, &me.body, &aad)
                            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aead"))?;
                        me.recv_ctr = me.recv_ctr.wrapping_add(1);
                        if inner.len() < INNER_HEADER {
                            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                        }
                        let real =
                            u32::from_le_bytes(inner[..INNER_HEADER].try_into().unwrap()) as usize;
                        match INNER_HEADER.checked_add(real) {
                            Some(end) if end <= inner.len() => {
                                me.plain = inner[INNER_HEADER..end].to_vec();
                                me.plain_pos = 0;
                            }
                            _ => return Poll::Ready(Err(io::ErrorKind::InvalidData.into())),
                        }
                        me.hdr_filled = 0;
                        me.body = Vec::new();
                        me.rstate = RState::Header;
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObfsByteStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // Finish flushing any in-flight record before framing a new one.
        ready!(me.flush_wbuf(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_CHUNK);

        let mut inner = Vec::with_capacity(INNER_HEADER + n);
        inner.extend_from_slice(&(n as u32).to_le_bytes());
        inner.extend_from_slice(&buf[..n]);
        let aad = record_aad(me.send_dir, me.send_ctr);
        me.send_ctr = me.send_ctr.wrapping_add(1);
        let ct = aead::seal(&me.send, &inner, &aad);

        let mut rec = Vec::with_capacity(HEADER_LEN + ct.len());
        rec.extend_from_slice(&TLS_PREFIX);
        rec.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        rec.extend_from_slice(&ct);
        me.wbuf = rec;
        me.wpos = 0;

        // Best-effort flush; remaining bytes flush on the next poll_write/poll_flush.
        let _ = me.flush_wbuf(cx)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.flush_wbuf(cx))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.flush_wbuf(cx))?;
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{DIR_C2S, DIR_S2C};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn client_keys() -> SessionKeys {
        SessionKeys {
            send: AeadKey::from_bytes([1; 32]),
            recv: AeadKey::from_bytes([2; 32]),
            send_dir: DIR_C2S,
            recv_dir: DIR_S2C,
        }
    }
    fn server_keys() -> SessionKeys {
        SessionKeys {
            send: AeadKey::from_bytes([2; 32]),
            recv: AeadKey::from_bytes([1; 32]),
            send_dir: DIR_S2C,
            recv_dir: DIR_C2S,
        }
    }

    #[tokio::test]
    async fn byte_stream_roundtrip() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = ObfsByteStream::new(a, client_keys());
        let mut server = ObfsByteStream::new(b, server_keys());

        let payload = vec![0xABu8; 5000]; // spans multiple records
        let p2 = payload.clone();
        let srv = tokio::spawn(async move {
            let mut got = vec![0u8; 5000];
            server.read_exact(&mut got).await.unwrap();
            got
        });
        client.write_all(&p2).await.unwrap();
        client.flush().await.unwrap();
        assert_eq!(srv.await.unwrap(), payload);
    }

    #[tokio::test]
    async fn bidirectional_and_partial_reads() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = ObfsByteStream::new(a, client_keys());
        let mut server = ObfsByteStream::new(b, server_keys());

        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 5];
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            server.write_all(b"world!!").await.unwrap();
            server.flush().await.unwrap();
        });
        client.write_all(b"hello").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0u8; 7];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world!!");
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn tampered_record_fails() {
        // Mismatched recv key ⇒ AEAD open fails ⇒ read error.
        let (a, b) = tokio::io::duplex(8192);
        let mut client = ObfsByteStream::new(a, client_keys());
        let bad = SessionKeys {
            send: AeadKey::from_bytes([9; 32]),
            recv: AeadKey::from_bytes([9; 32]),
            send_dir: DIR_S2C,
            recv_dir: DIR_C2S,
        };
        let mut server = ObfsByteStream::new(b, bad);
        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            server.read_exact(&mut buf).await
        });
        client.write_all(b"data").await.unwrap();
        client.flush().await.unwrap();
        assert!(srv.await.unwrap().is_err());
    }
}
