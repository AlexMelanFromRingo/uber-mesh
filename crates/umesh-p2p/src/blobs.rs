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
        let (req, _): (BlobRequest, usize) =
            bincode::decode_from_slice(&buf, cfg()).map_err(bin_err)?;
        Ok(req)
    }

    async fn read_response<T>(
        &mut self,
        _p: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<BlobResponse>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_lp(io, MAX_BLOB + 16).await?;
        let (resp, _): (BlobResponse, usize) =
            bincode::decode_from_slice(&buf, cfg()).map_err(bin_err)?;
        Ok(resp)
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
    }
}
