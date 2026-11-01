//! Blob exchange: request/response wire types + a **bincode** codec for the libp2p
//! request-response protocol `/uber-mesh/blobs/1.0.0`.
//!
//! A peer requests content by `Cid` and receives the bytes (or `None`). bincode is used only here,
//! inside the libp2p-encrypted (and obfs-wrapped) stream — never in cleartext on the wire (research
//! D7 / constitution). The receiver verifies `BLAKE3(bytes) == cid` before trusting the content.

use std::io;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;
use libp2p::request_response;

/// The blob exchange protocol name.
pub const BLOB_PROTOCOL: StreamProtocol = StreamProtocol::new("/uber-mesh/blobs/1.0.0");
const MAX_REQUEST: usize = 64; // a request is just a 32-byte cid
/// Maximum blob size served/accepted (8 MiB).
pub const MAX_BLOB: usize = 8 * 1024 * 1024;

/// A request for the content with the given `Cid` bytes.
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct BlobRequest {
    /// `Cid` (BLAKE3 of the wanted content).
    pub cid: [u8; 32],
}

/// A response carrying the content if the responder has it.
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct BlobResponse {
    /// The content bytes, or `None` if not held.
    pub data: Option<Vec<u8>>,
}

fn cfg() -> bincode::config::Configuration {
    bincode::config::standard()
}

/// Largest blob-response frame: `Some` tag + varint length + `MAX_BLOB` bytes.
const MAX_RESPONSE_FRAME: usize = MAX_BLOB + 16;
/// bincode decode budgets: bincode checks every container length claim against these **before**
/// allocating, so a frame claiming a 2^46-byte blob fails cleanly instead of aborting the process.
const REQUEST_DECODE_LIMIT: usize = 2 * MAX_REQUEST;
const RESPONSE_DECODE_LIMIT: usize = 2 * MAX_RESPONSE_FRAME;

type LimitedCfg<const N: usize> = bincode::config::Configuration<
    bincode::config::LittleEndian,
    bincode::config::Varint,
    bincode::config::Limit<N>,
>;

fn request_cfg() -> LimitedCfg<REQUEST_DECODE_LIMIT> {
    bincode::config::standard().with_limit::<REQUEST_DECODE_LIMIT>()
}

fn response_cfg() -> LimitedCfg<RESPONSE_DECODE_LIMIT> {
    bincode::config::standard().with_limit::<RESPONSE_DECODE_LIMIT>()
}

/// Decode a blob request frame body (bounded, never panics; used by the codec and fuzzing).
pub fn decode_request(buf: &[u8]) -> io::Result<BlobRequest> {
    if buf.len() > MAX_REQUEST {
        return Err(bin_err("blob request too large"));
    }
    let (req, used): (BlobRequest, usize) =
        bincode::decode_from_slice(buf, request_cfg()).map_err(bin_err)?;
    if used != buf.len() {
        return Err(bin_err("trailing bytes in blob request"));
    }
    Ok(req)
}

/// Decode a blob response frame body (bounded, never panics; used by the codec and fuzzing).
pub fn decode_response(buf: &[u8]) -> io::Result<BlobResponse> {
    if buf.len() > MAX_RESPONSE_FRAME {
        return Err(bin_err("blob response too large"));
    }
    let (resp, used): (BlobResponse, usize) =
        bincode::decode_from_slice(buf, response_cfg()).map_err(bin_err)?;
    if used != buf.len() {
        return Err(bin_err("trailing bytes in blob response"));
    }
    if resp.data.as_ref().is_some_and(|d| d.len() > MAX_BLOB) {
        return Err(bin_err("blob too large"));
    }
    Ok(resp)
}

fn bin_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

async fn read_lp<T: AsyncRead + Unpin + Send>(io: &mut T, max: usize) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await?;
    let n = u32::from_le_bytes(len) as usize;
    if n > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
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

/// bincode codec for the blob protocol.
#[derive(Clone, Default)]
pub struct BlobCodec;

#[async_trait::async_trait]
impl request_response::Codec for BlobCodec {
    type Protocol = StreamProtocol;
    type Request = BlobRequest;
    type Response = BlobResponse;

    async fn read_request<T>(&mut self, _p: &StreamProtocol, io: &mut T) -> io::Result<BlobRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_lp(io, MAX_REQUEST).await?;
        decode_request(&buf)
    }

    async fn read_response<T>(
        &mut self,
        _p: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<BlobResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_lp(io, MAX_RESPONSE_FRAME).await?;
        decode_response(&buf)
    }

    async fn write_request<T>(
        &mut self,
        _p: &StreamProtocol,
        io: &mut T,
        req: BlobRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = bincode::encode_to_vec(&req, cfg()).map_err(bin_err)?;
        write_lp(io, &bytes).await
    }

    async fn write_response<T>(
        &mut self,
        _p: &StreamProtocol,
        io: &mut T,
        resp: BlobResponse,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if resp.data.as_ref().is_some_and(|d| d.len() > MAX_BLOB) {
            return Err(bin_err("blob too large to serve"));
        }
        let bytes = bincode::encode_to_vec(&resp, cfg()).map_err(bin_err)?;
        write_lp(io, &bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bincode_roundtrip() {
        let req = BlobRequest { cid: [7u8; 32] };
        let bytes = bincode::encode_to_vec(&req, cfg()).unwrap();
        let (back, _): (BlobRequest, usize) = bincode::decode_from_slice(&bytes, cfg()).unwrap();
        assert_eq!(back.cid, req.cid);

        let resp = BlobResponse {
            data: Some(vec![1, 2, 3]),
        };
        let rb = bincode::encode_to_vec(&resp, cfg()).unwrap();
        let (rback, _): (BlobResponse, usize) = bincode::decode_from_slice(&rb, cfg()).unwrap();
        assert_eq!(rback.data, resp.data);
        assert_eq!(decode_response(&rb).unwrap().data, resp.data);
        assert_eq!(decode_request(&bytes).unwrap().cid, req.cid);
    }

    fn varint_u64(v: u64) -> Vec<u8> {
        let mut o = vec![253u8];
        o.extend_from_slice(&v.to_le_bytes());
        o
    }

    /// Audit regression (CRITICAL): a malicious responder's `Some(Vec)` claiming 2^46 bytes
    /// aborted the requesting process. Must now be a clean `InvalidData` error.
    #[test]
    fn huge_blob_length_claim_rejected() {
        use libp2p::request_response::Codec;
        for claim in [1u64 << 46, u64::MAX, MAX_BLOB as u64 + 1] {
            let mut body = vec![1u8]; // Some
            body.extend(varint_u64(claim));
            let mut f = (body.len() as u32).to_le_bytes().to_vec();
            f.extend_from_slice(&body);
            let mut io = futures::io::Cursor::new(f);
            let r = futures::executor::block_on(BlobCodec.read_response(&BLOB_PROTOCOL, &mut io));
            assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn max_blob_roundtrips_and_oversize_rejected() {
        let resp = BlobResponse {
            data: Some(vec![0x5a; MAX_BLOB]),
        };
        let b = bincode::encode_to_vec(&resp, cfg()).unwrap();
        assert!(b.len() <= MAX_RESPONSE_FRAME);
        assert_eq!(decode_response(&b).unwrap().data.unwrap().len(), MAX_BLOB);
        let over = bincode::encode_to_vec(
            BlobResponse {
                data: Some(vec![0; MAX_BLOB + 1]),
            },
            cfg(),
        )
        .unwrap();
        assert!(decode_response(&over).is_err());
        assert!(decode_request(&[0u8; 33]).is_err(), "trailing byte");
    }
}
