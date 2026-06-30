//! libp2p wiring for set reconciliation: a request-response protocol `/uber-mesh/reconcile/1.0.0`
//! that carries [`crate::reconcile`] messages (bincode). The initiator sends rounds as requests; the
//! responder answers; the exchange repeats until convergence (driven in [`crate::node`]).

use std::io;

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;
use libp2p::request_response;

use crate::reconcile::Segment;

/// The reconciliation protocol name.
pub const RECONCILE_PROTOCOL: StreamProtocol = StreamProtocol::new("/uber-mesh/reconcile/1.0.0");
/// Maximum reconciliation message size (messages stay small — log-depth — but bound for safety).
pub const MAX_RECONCILE: usize = 4 * 1024 * 1024;

/// One round's reconciliation message (request and response use the same type).
#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct ReconcileMsg(pub Vec<Segment>);

fn cfg() -> bincode::config::Configuration {
    bincode::config::standard()
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
        let (m, _): (ReconcileMsg, usize) =
            bincode::decode_from_slice(&buf, cfg()).map_err(bin_err)?;
        Ok(m)
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
        let (m, _): (ReconcileMsg, usize) =
            bincode::decode_from_slice(&buf, cfg()).map_err(bin_err)?;
        Ok(m)
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
        let bytes = bincode::encode_to_vec(&req, cfg()).map_err(bin_err)?;
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
        let bytes = bincode::encode_to_vec(&resp, cfg()).map_err(bin_err)?;
        write_lp(io, &bytes).await
    }
}
