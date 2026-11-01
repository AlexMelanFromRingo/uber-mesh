//! A poll-based byte stream (`AsyncRead + AsyncWrite`) over the obfs AEAD record framing.
//!
//! Where [`crate::secure::SecureStream`] is message-oriented (`send`/`recv`), `ObfsByteStream`
//! presents a plain byte stream so it can carry an arbitrary protocol — specifically libp2p's
//! Noise+Yamux upgrade. Every chunk written becomes one TLS-record-framed AEAD record (AAD binds
//! direction + a monotonic counter); reads reassemble records and yield the decrypted bytes. This is
//! the adapter that lets the obfuscated, probe-resistant carrier sit **below** libp2p Noise (T032).
//!
//! Two write modes:
//! - [`ObfsByteStream::new`] — unshaped: one record per `poll_write` (record = plaintext + 49
//!   bytes). Kept for compatibility; it leaks the inner protocol's write sizes.
//! - [`ObfsByteStream::with_shaping`] — shaped: writes are **coalesced** into a bounded plaintext
//!   buffer (≤ one record) and emitted as one record when the buffer fills or on
//!   `poll_flush`/`poll_shutdown`; every record is padded per the [`ShapingPolicy`] (bucket
//!   round-up + random tail). This hides inner Noise/multistream record boundaries and sizes
//!   (the TLS-in-TLS length signal). The `iat_jitter_ms` field is not applied here.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use umesh_crypto::aead::{self, AeadKey};

use crate::handshake::SessionKeys;
use crate::shaping::ShapingPolicy;
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
    /// One fully framed record in flight (bounded: ≤ `HEADER_LEN + MAX_RECORD`).
    wbuf: Vec<u8>,
    wpos: usize,
    /// Shaping policy; `None` = legacy one-record-per-write mode.
    shaping: Option<ShapingPolicy>,
    /// Coalesced plaintext not yet framed (shaped mode only; bounded: ≤ `MAX_CHUNK`).
    pending: Vec<u8>,
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
            shaping: None,
            pending: Vec::new(),
        }
    }

    /// Wrap a handshaked carrier with the session's directional keys, padding every record per
    /// `policy` and coalescing small writes (flushed on `poll_flush`/`poll_shutdown` or when a
    /// full record's worth of plaintext is buffered). The peer may use either constructor: the
    /// record format is identical, the receiver strips padding via the inner length prefix.
    pub fn with_shaping(inner: S, keys: SessionKeys, policy: ShapingPolicy) -> Self {
        let mut s = Self::new(inner, keys);
        s.pending = Vec::with_capacity(MAX_CHUNK);
        s.shaping = Some(policy);
        s
    }

    /// Seal `data` (+ policy padding, clamped to the record ceiling) into `wbuf` as one record.
    /// Precondition: `wbuf` is fully flushed.
    fn frame_record(&mut self, data: &[u8]) {
        debug_assert!(self.wbuf.is_empty() && data.len() <= MAX_CHUNK);
        let framed = INNER_HEADER + data.len();
        let pad = match &self.shaping {
            Some(p) => p.pad_len(framed).min(MAX_RECORD - AEAD_OVERHEAD - framed),
            None => 0,
        };
        let mut inner = Vec::with_capacity(framed + pad);
        inner.extend_from_slice(&(data.len() as u32).to_le_bytes());
        inner.extend_from_slice(data);
        inner.resize(framed + pad, 0);
        let aad = record_aad(self.send_dir, self.send_ctr);
        self.send_ctr = self.send_ctr.wrapping_add(1);
        let ct = aead::seal(&self.send, &inner, &aad);

        self.wbuf.reserve(HEADER_LEN + ct.len());
        self.wbuf.extend_from_slice(&TLS_PREFIX);
        self.wbuf
            .extend_from_slice(&(ct.len() as u16).to_be_bytes());
        self.wbuf.extend_from_slice(&ct);
        self.wpos = 0;
    }

    /// Move the coalesced plaintext into a framed record (shaped mode). Precondition: `wbuf` empty.
    fn frame_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let data = std::mem::take(&mut self.pending);
        self.frame_record(&data);
        self.pending = data;
        self.pending.clear();
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

impl<S: AsyncWrite + Unpin> ObfsByteStream<S> {
    /// Frame any coalesced plaintext and push every buffered byte to the inner writer.
    fn drain_all(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.flush_wbuf(cx))?;
        if !self.pending.is_empty() {
            self.frame_pending();
            ready!(self.flush_wbuf(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_write_shaped(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.pending.len() >= MAX_CHUNK {
            // Coalescing buffer is full: it can only be emptied once the in-flight record is out.
            // `Pending` here is returned with the inner writer's waker registered.
            ready!(self.flush_wbuf(cx))?;
            self.frame_pending();
        }
        let n = buf.len().min(MAX_CHUNK - self.pending.len());
        self.pending.extend_from_slice(&buf[..n]);
        // A full record's worth is buffered: frame it now (if the slot is free) and push it
        // opportunistically, so bulk transfers stream without waiting for poll_flush.
        if self.pending.len() >= MAX_CHUNK && self.wbuf.is_empty() {
            self.frame_pending();
        }
        if !self.wbuf.is_empty() {
            // Best effort; a `Pending` result just leaves bytes for the next write/flush (the
            // waker it registered causes at most a spurious wake-up). Errors are surfaced now.
            if let Poll::Ready(Err(e)) = self.flush_wbuf(cx) {
                return Poll::Ready(Err(e));
            }
        }
        Poll::Ready(Ok(n))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObfsByteStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if me.shaping.is_some() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            return me.poll_write_shaped(cx, buf);
        }
        // Unshaped: finish flushing any in-flight record before framing a new one.
        ready!(me.flush_wbuf(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_CHUNK);
        me.frame_record(&buf[..n]);

        // Best-effort flush; remaining bytes flush on the next poll_write/poll_flush.
        let _ = me.flush_wbuf(cx)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.drain_all(cx))?;
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        ready!(me.drain_all(cx))?;
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
            channel_binding: [7; 32],
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

    fn raw_overhead() -> usize {
        HEADER_LEN + AEAD_OVERHEAD + INNER_HEADER
    }

    /// Audit F5 regression: on the libp2p path every record was exactly plaintext + 49 bytes. With
    /// shaping, records are padded (bucket + random tail) and the overhead varies.
    #[tokio::test]
    async fn shaped_records_hide_plaintext_length() {
        let (a, mut b) = tokio::io::duplex(256 * 1024);
        let policy = ShapingPolicy::light();
        let mut s = ObfsByteStream::with_shaping(a, client_keys(), policy.clone());
        let mut overheads = std::collections::HashSet::new();
        for n in [1usize, 20, 28, 100, 1000, 3000] {
            for _ in 0..16 {
                s.write_all(&vec![0u8; n]).await.unwrap();
                s.flush().await.unwrap();
                let r = crate::wire::read_record_raw(&mut b).await.unwrap();
                assert_ne!(r.len(), n + raw_overhead(), "unpadded record for n={n}");
                let framed = INNER_HEADER + n;
                let bucketed = framed.div_ceil(256) * 256;
                let body = r.len() - HEADER_LEN - AEAD_OVERHEAD;
                assert!(
                    (bucketed..=bucketed + 64).contains(&body),
                    "n={n} body={body}"
                );
                overheads.insert(r.len() - n);
            }
        }
        assert!(overheads.len() > 8, "padding must vary: {overheads:?}");
    }

    /// Small writes are coalesced into one record until flush (no per-write record boundaries).
    #[tokio::test]
    async fn shaped_small_writes_are_coalesced() {
        let (a, mut b) = tokio::io::duplex(256 * 1024);
        let mut s = ObfsByteStream::with_shaping(a, client_keys(), ShapingPolicy::none());
        for _ in 0..100 {
            s.write_all(&[7u8; 10]).await.unwrap();
        }
        // Nothing on the wire before flush.
        let mut probe = [0u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                b.read_exact(&mut probe)
            )
            .await
            .is_err()
        );
        s.flush().await.unwrap();
        let r = crate::wire::read_record_raw(&mut b).await.unwrap();
        assert_eq!(
            r.len(),
            1000 + raw_overhead(),
            "one record carrying all 100 writes"
        );
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                b.read_exact(&mut probe)
            )
            .await
            .is_err(),
            "no second record"
        );
    }

    /// Bulk transfer through a tiny pipe (constant partial writes / Pending) in both directions of
    /// compatibility: shaped writer → unshaped reader and vice versa.
    #[tokio::test]
    async fn shaped_bulk_through_tiny_pipe_roundtrips() {
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i * 31 % 251) as u8).collect();
        for shaped_writer in [true, false] {
            let (a, b) = tokio::io::duplex(61);
            let mut w = if shaped_writer {
                ObfsByteStream::with_shaping(a, client_keys(), ShapingPolicy::aggressive())
            } else {
                ObfsByteStream::new(a, client_keys())
            };
            let mut r = if shaped_writer {
                ObfsByteStream::new(b, server_keys())
            } else {
                ObfsByteStream::with_shaping(b, server_keys(), ShapingPolicy::aggressive())
            };
            let p2 = payload.clone();
            let wr = tokio::spawn(async move {
                for chunk in p2.chunks(777) {
                    w.write_all(chunk).await.unwrap();
                }
                w.shutdown().await.unwrap();
            });
            let mut got = Vec::new();
            r.read_to_end(&mut got).await.unwrap();
            wr.await.unwrap();
            assert_eq!(got.len(), payload.len());
            assert!(got == payload, "shaped_writer={shaped_writer}");
        }
    }

    /// Shutdown flushes coalesced bytes and the reader sees a clean EOF at a record boundary.
    #[tokio::test]
    async fn shaped_shutdown_flushes_pending_then_eof() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut w = ObfsByteStream::with_shaping(a, client_keys(), ShapingPolicy::light());
        let mut r = ObfsByteStream::new(b, server_keys());
        w.write_all(b"abc").await.unwrap();
        w.write_all(b"def").await.unwrap();
        w.shutdown().await.unwrap();
        drop(w);
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"abcdef");
    }

    /// Buffering is bounded: a single huge write is accepted at most one record's worth at a time.
    #[tokio::test]
    async fn shaped_write_is_bounded() {
        let (a, _b) = tokio::io::duplex(1024 * 1024);
        let mut w = ObfsByteStream::with_shaping(a, client_keys(), ShapingPolicy::none());
        let n = w.write(&vec![1u8; 100_000]).await.unwrap();
        assert!(n <= MAX_CHUNK);
        assert!(w.pending.len() <= MAX_CHUNK && w.wbuf.len() <= HEADER_LEN + MAX_RECORD);
    }
}
