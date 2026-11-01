//! libp2p wiring for set reconciliation: a request-response protocol `/uber-mesh/reconcile/1.0.0`
//! that carries [`crate::reconcile`] messages (bincode). The initiator sends rounds as requests; the
//! responder answers; the exchange repeats until convergence (driven in [`crate::node`]).

use std::io;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;
use libp2p::request_response;

use crate::reconcile::{self, Segment};

/// The reconciliation protocol name.
pub const RECONCILE_PROTOCOL: StreamProtocol = StreamProtocol::new("/uber-mesh/reconcile/1.0.0");
/// Maximum reconciliation frame size. A maximal valid message (`MAX_SEGMENTS` segments, each with
/// a 32-byte upper and a `THRESHOLD`-id list) encodes to ~1.3 MiB.
pub const MAX_RECONCILE: usize = 2 * 1024 * 1024;
/// bincode decode budget (wire bytes + claimed heap). Bincode checks every container length claim
/// against it **before** allocating, so a tiny frame claiming 2^40 elements fails cleanly instead
/// of aborting the process on allocation failure.
const DECODE_LIMIT: usize = 2 * MAX_RECONCILE;

/// One round's reconciliation message (request and response use the same type).
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct ReconcileMsg(pub Vec<Segment>);

fn cfg() -> bincode::config::Configuration {
    bincode::config::standard()
}

fn decode_cfg() -> bincode::config::Configuration<
    bincode::config::LittleEndian,
    bincode::config::Varint,
    bincode::config::Limit<DECODE_LIMIT>,
> {
    bincode::config::standard().with_limit::<DECODE_LIMIT>()
}

/// Decode and structurally validate one reconciliation frame body. Bounded allocation, never
/// panics; used by the codec and the fuzz harness.
pub fn decode_msg(buf: &[u8]) -> io::Result<ReconcileMsg> {
    if buf.len() > MAX_RECONCILE {
        return Err(bin_err("reconcile frame too large"));
    }
    let (m, used): (ReconcileMsg, usize) =
        bincode::decode_from_slice(buf, decode_cfg()).map_err(bin_err)?;
    if used != buf.len() {
        return Err(bin_err("trailing bytes in reconcile frame"));
    }
    reconcile::validate(&m.0).map_err(bin_err)?;
    Ok(m)
}

/// Encode one reconciliation frame body.
pub fn encode_msg(m: &ReconcileMsg) -> io::Result<Vec<u8>> {
    let bytes = bincode::encode_to_vec(m, cfg()).map_err(bin_err)?;
    if bytes.len() > MAX_RECONCILE {
        return Err(bin_err("reconcile frame too large"));
    }
    Ok(bytes)
}

fn bin_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

async fn read_lp<T: AsyncRead + Unpin + Send>(io: &mut T) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await?;
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_RECONCILE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reconcile frame too large",
        ));
    }
    let mut buf = vec![0u8; n];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_lp<T: AsyncWrite + Unpin + Send>(io: &mut T, bytes: &[u8]) -> io::Result<()> {
    io.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    io.write_all(bytes).await?;
    Ok(())
}

/// bincode codec for the reconciliation protocol.
#[derive(Clone, Default)]
pub struct ReconcileCodec;

#[async_trait::async_trait]
impl request_response::Codec for ReconcileCodec {
    type Protocol = StreamProtocol;
    type Request = ReconcileMsg;
    type Response = ReconcileMsg;

    async fn read_request<T>(&mut self, _p: &StreamProtocol, io: &mut T) -> io::Result<ReconcileMsg>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_lp(io).await?;
        decode_msg(&buf)
    }

    async fn read_response<T>(
        &mut self,
        _p: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<ReconcileMsg>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_lp(io).await?;
        decode_msg(&buf)
    }

    async fn write_request<T>(
        &mut self,
        _p: &StreamProtocol,
        io: &mut T,
        req: ReconcileMsg,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = encode_msg(&req)?;
        write_lp(io, &bytes).await
    }

    async fn write_response<T>(
        &mut self,
        _p: &StreamProtocol,
        io: &mut T,
        resp: ReconcileMsg,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = encode_msg(&resp)?;
        write_lp(io, &bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcile::{MAX_SEGMENTS, Mode, THRESHOLD, respond};
    use libp2p::request_response::Codec;

    fn varint_u64(v: u64) -> Vec<u8> {
        let mut o = vec![253u8];
        o.extend_from_slice(&v.to_le_bytes());
        o
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut f = (body.len() as u32).to_le_bytes().to_vec();
        f.extend_from_slice(body);
        f
    }

    /// Audit regression (CRITICAL): a 13-byte request claiming 2^40 segments aborted the process
    /// (unbounded bincode allocation). Must now be a clean `InvalidData` error.
    #[test]
    fn huge_length_claim_is_rejected_without_allocating() {
        for claim in [1u64 << 40, u64::MAX, (DECODE_LIMIT as u64) / 8] {
            let mut io = futures::io::Cursor::new(frame(&varint_u64(claim)));
            let r = futures::executor::block_on(
                ReconcileCodec.read_request(&RECONCILE_PROTOCOL, &mut io),
            );
            assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
            let mut io = futures::io::Cursor::new(frame(&varint_u64(claim)));
            let r = futures::executor::block_on(
                ReconcileCodec.read_response(&RECONCILE_PROTOCOL, &mut io),
            );
            assert!(r.is_err());
        }
        // Nested claim: one segment whose id list claims 2^40 ids.
        let mut body = vec![1u8, 0, 2]; // len=1, upper=None, mode=IdList
        body.extend(varint_u64(1 << 40));
        assert!(decode_msg(&body).is_err());
    }

    #[test]
    fn invalid_structure_rejected_at_codec() {
        let bad = ReconcileMsg(vec![
            Segment {
                upper: None,
                mode: Mode::Skip,
            },
            Segment {
                upper: None,
                mode: Mode::Skip,
            },
        ]);
        let bytes = bincode::encode_to_vec(&bad, cfg()).unwrap();
        assert!(decode_msg(&bytes).is_err());
        let mut ok = encode_msg(&ReconcileMsg(vec![Segment {
            upper: None,
            mode: Mode::IdList(vec![[3; 32]]),
        }]))
        .unwrap();
        assert!(decode_msg(&ok).is_ok());
        ok.push(0);
        assert!(decode_msg(&ok).is_err(), "trailing bytes");
    }

    /// The largest valid message fits in a frame (so honest peers never hit the cap).
    #[test]
    fn maximal_valid_message_fits_frame() {
        let mut ids: Vec<[u8; 32]> = (0..MAX_SEGMENTS as u64 * (THRESHOLD as u64 + 1))
            .map(|i| umesh_crypto::hash::hash(&i.to_le_bytes()))
            .collect();
        ids.sort_unstable();
        let mut segs: Vec<Segment> = ids
            .chunks(THRESHOLD + 1)
            .map(|c| Segment {
                upper: Some(c[THRESHOLD]),
                mode: Mode::IdList(c[..THRESHOLD].to_vec()),
            })
            .collect();
        segs.last_mut().unwrap().upper = None;
        let m = ReconcileMsg(segs);
        let bytes = encode_msg(&m).expect("fits");
        assert!(bytes.len() <= MAX_RECONCILE);
        assert_eq!(decode_msg(&bytes).unwrap().0.len(), MAX_SEGMENTS);
    }

    /// Audit regression (HIGH amplification): a 4 MiB request of alternating segments produced a
    /// ~172 MiB response against a 50-id store. Now refused outright; any valid request yields a
    /// response bounded by the frame cap.
    #[test]
    fn reconcile_amplification_bounded() {
        let mut local: Vec<[u8; 32]> = (0..50u64)
            .map(|i| umesh_crypto::hash::hash(&i.to_le_bytes()))
            .collect();
        local.sort_unstable();
        let pair = [
            Segment {
                upper: Some([0u8; 32]),
                mode: Mode::Skip,
            },
            Segment {
                upper: None,
                mode: Mode::IdList(vec![]),
            },
        ];
        let req: Vec<Segment> = pair.iter().cycle().take(100_000).cloned().collect();
        let bytes = bincode::encode_to_vec(ReconcileMsg(req.clone()), cfg()).unwrap();
        assert!(decode_msg(&bytes).is_err(), "codec refuses it");
        assert!(respond(&local, &req).is_err(), "responder refuses it");

        // Worst valid request against a big store: response still fits one frame.
        let mut big: Vec<[u8; 32]> = (0..50_000u64)
            .map(|i| umesh_crypto::hash::hash(&i.to_le_bytes()))
            .collect();
        big.sort_unstable();
        let mut bounds: Vec<[u8; 32]> = (0..MAX_SEGMENTS as u64 - 1)
            .map(|i| umesh_crypto::hash::hash(&(i + 1_000_000).to_le_bytes()))
            .collect();
        bounds.sort_unstable();
        let mut req: Vec<Segment> = bounds
            .into_iter()
            .map(|u| Segment {
                upper: Some(u),
                mode: Mode::IdList(vec![]),
            })
            .collect();
        req.push(Segment {
            upper: None,
            mode: Mode::IdList(vec![]),
        });
        let resp = respond(&big, &req).unwrap();
        let out = encode_msg(&ReconcileMsg(resp)).expect("response fits a frame");
        assert!(out.len() <= MAX_RECONCILE);
    }
}
