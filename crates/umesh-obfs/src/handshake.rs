//! Obfuscated, probe-resistant handshake.
//!
//! Both flights are **AEAD-sealed under a key derived from the per-listener PSK** and TLS-record
//! framed. This means:
//! - On the wire each flight is indistinguishable from uniform-random TLS application data — the
//!   ML-KEM-768 encapsulation key / ciphertext and the X25519 keys carry no plaintext structure for
//!   DPI to fingerprint (research D2/D3; addresses the plaintext-PQ-key tell).
//! - The AEAD tag **is** the probe-resistance gate: a peer without the PSK cannot produce a flight
//!   that decrypts, so the server replies with **silence** (bounded drain + randomized delay + close)
//!   and an active prober cannot distinguish a uber-mesh node from any other service.
//! - Both flights (including the responder's) are authenticated to anyone holding the PSK. *Peer
//!   identity* (which specific node) is still established by the signed-hello / future Noise layer
//!   above this transport — the obfs layer authenticates the carrier, not the peer.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use umesh_crypto::aead::{self, AeadKey};
use umesh_crypto::hash::labels;
use umesh_crypto::kem;

use crate::error::{ObfsError, Result};
use crate::wire::{read_record, read_record_raw, write_record};

/// How the server treats a connection that fails the obfs gate (active-probe resistance).
#[derive(Clone, Debug)]
pub enum ProbeResponse {
    /// Drain + randomized delay + close, sending no distinguishing reply (obfs4 model).
    Silence,
    /// Reverse-proxy the connection to a real upstream `host:port`, forwarding the bytes already
    /// received, so a prober transparently talks to a genuine site (REALITY/ShadowTLS model,
    /// research D3). On `:443` this is stronger than silence — silence is itself anomalous there.
    Fallback(String),
}

impl Default for ProbeResponse {
    fn default() -> Self {
        ProbeResponse::Silence
    }
}

const EPOCH_LEN: usize = 8;
/// Flight-1 plaintext: x25519_pub(32) || mlkem_ek(1184) || epoch(8).
const FLIGHT1_PT_LEN: usize = kem::X25519_LEN + kem::MLKEM768_EK_LEN + EPOCH_LEN;
/// Flight-2 plaintext: x25519_pub(32) || mlkem_ct(1088).
const FLIGHT2_PT_LEN: usize = kem::X25519_LEN + kem::MLKEM768_CT_LEN;

const HS1_AAD: &[u8] = b"uber-mesh-hs1-v1";
const HS2_AAD: &[u8] = b"uber-mesh-hs2-v1";

/// Direction tags bound into record AAD (also pick the directional traffic key).
pub(crate) const DIR_C2S: u8 = 0;
pub(crate) const DIR_S2C: u8 = 1;

/// Maximum time to wait for a peer's handshake flight before treating it as a probe.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Hard cap on bytes drained from a rejected/probing connection (DoS bound).
const MAX_DRAIN_BYTES: usize = 64 * 1024;

/// A per-listener pre-shared key (the "bridge secret") that gates the obfs handshake.
#[derive(Clone)]
pub struct ObfsPsk(pub [u8; 32]);

impl ObfsPsk {
    /// AEAD key that seals/opens handshake flights (the probe-resistance gate).
    fn frame_key(&self) -> AeadKey {
        AeadKey::derive(labels::OBFS_FRAME, &self.0)
    }
}

/// Directional AEAD keys + direction tags established by the handshake.
pub struct SessionKeys {
    /// Key for data this side sends.
    pub send: AeadKey,
    /// Key for data this side receives.
    pub recv: AeadKey,
    /// Direction tag for sent records (bound into AAD).
    pub send_dir: u8,
    /// Direction tag for received records (bound into AAD).
    pub recv_dir: u8,
}

fn current_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0)
}

/// Drain and discard input (bounded by time and byte count), sending no distinguishing reply. Used
/// when the gate fails; the caller drops the stream afterwards.
async fn silence<S>(stream: &mut S)
where
    S: AsyncRead + Unpin,
{
    let delay_ms = rand::random::<u64>() % 350 + 50;
    let _ = tokio::time::timeout(Duration::from_millis(delay_ms), async {
        let mut buf = [0u8; 1024];
        let mut drained = 0usize;
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    drained += n;
                    if drained >= MAX_DRAIN_BYTES {
                        break;
                    }
                }
            }
        }
    })
    .await;
}

/// Client side of the handshake. Returns directional session keys.
pub async fn client_handshake<S>(stream: &mut S, psk: &ObfsPsk) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = psk.frame_key();
    let (initiator, init) = kem::Initiator::start();
    let epoch = current_epoch();

    let mut pt = Vec::with_capacity(FLIGHT1_PT_LEN);
    pt.extend_from_slice(&init.x25519_pub);
    pt.extend_from_slice(&init.mlkem_ek);
    pt.extend_from_slice(&epoch.to_le_bytes());
    write_record(stream, &aead::seal(&key, &pt, HS1_AAD)).await?;

    let resp_wire = read_record(stream).await?;
    let resp_pt = aead::open(&key, &resp_wire, HS2_AAD)?;
    if resp_pt.len() != FLIGHT2_PT_LEN {
        return Err(ObfsError::Malformed);
    }
    let mut x = [0u8; kem::X25519_LEN];
    x.copy_from_slice(&resp_pt[..kem::X25519_LEN]);
    let resp_msg = kem::ResponderMessage {
        x25519_pub: x,
        mlkem_ct: resp_pt[kem::X25519_LEN..].to_vec(),
    };
    let ss = initiator.finish(&resp_msg)?;

    Ok(SessionKeys {
        send: AeadKey::derive(labels::TRAFFIC_C2S, &ss),
        recv: AeadKey::derive(labels::TRAFFIC_S2C, &ss),
        send_dir: DIR_C2S,
        recv_dir: DIR_S2C,
    })
}

/// On gate failure, run the configured probe response over `stream`, forwarding any bytes already
/// read (`prefix`) to a cover upstream for the fallback model.
async fn handle_probe<S>(stream: &mut S, prefix: &[u8], probe: &ProbeResponse)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match probe {
        ProbeResponse::Silence => silence(stream).await,
        ProbeResponse::Fallback(upstream) => match TcpStream::connect(upstream).await {
            Ok(mut up) => {
                // Replay the bytes we already consumed, then splice the prober ↔ real site.
                if up.write_all(prefix).await.is_ok() {
                    let _ = tokio::io::copy_bidirectional(stream, &mut up).await;
                }
            }
            // Upstream unreachable ⇒ fall back to silence rather than a distinguishing error.
            Err(_) => silence(stream).await,
        },
    }
}

/// Server side of the handshake, defaulting to silent probe rejection.
pub async fn server_handshake<S>(stream: &mut S, psk: &ObfsPsk) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    server_handshake_probe(stream, psk, &ProbeResponse::Silence).await
}

/// Server side of the handshake with an explicit probe-response policy. A peer whose flight fails the
/// AEAD gate (no PSK, tampering, or a stale epoch) is handled per `probe` (silence or fallback-proxy).
pub async fn server_handshake_probe<S>(
    stream: &mut S,
    psk: &ObfsPsk,
    probe: &ProbeResponse,
) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = psk.frame_key();

    // Read the raw first flight under a timeout, keeping the bytes for the fallback path.
    let raw = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_record_raw(stream)).await {
        Ok(Ok(raw)) => raw,
        _ => {
            handle_probe(stream, &[], probe).await;
            return Err(ObfsError::AuthFailed);
        }
    };
    let body = &raw[crate::wire::HEADER_LEN..];

    let pt = match aead::open(&key, body, HS1_AAD) {
        Ok(pt) if pt.len() == FLIGHT1_PT_LEN => pt,
        _ => {
            handle_probe(stream, &raw, probe).await;
            return Err(ObfsError::AuthFailed);
        }
    };

    // Replay window: the (authenticated) epoch must be within ±1 of ours (clock-skew tolerant;
    // bounds reuse of a captured valid flight to ~3 minutes — accepted for a stateless gate).
    let epoch_off = kem::X25519_LEN + kem::MLKEM768_EK_LEN;
    let epoch_bytes: [u8; EPOCH_LEN] = pt[epoch_off..epoch_off + EPOCH_LEN]
        .try_into()
        .map_err(|_| ObfsError::Malformed)?;
    let client_epoch = u64::from_le_bytes(epoch_bytes);
    if client_epoch.abs_diff(current_epoch()) > 1 {
        handle_probe(stream, &raw, probe).await;
        return Err(ObfsError::AuthFailed);
    }

    let mut x = [0u8; kem::X25519_LEN];
    x.copy_from_slice(&pt[..kem::X25519_LEN]);
    let init = kem::InitiatorMessage {
        x25519_pub: x,
        mlkem_ek: pt[kem::X25519_LEN..epoch_off].to_vec(),
    };

    let (ss, resp) = kem::respond(&init)?;
    let mut rpt = Vec::with_capacity(FLIGHT2_PT_LEN);
    rpt.extend_from_slice(&resp.x25519_pub);
    rpt.extend_from_slice(&resp.mlkem_ct);
    write_record(stream, &aead::seal(&key, &rpt, HS2_AAD)).await?;

    Ok(SessionKeys {
        send: AeadKey::derive(labels::TRAFFIC_S2C, &ss),
        recv: AeadKey::derive(labels::TRAFFIC_C2S, &ss),
        send_dir: DIR_S2C,
        recv_dir: DIR_C2S,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handshake_agrees_over_duplex() {
        let psk = ObfsPsk([9u8; 32]);
        let (mut c, mut s) = tokio::io::duplex(8192);
        let psk2 = psk.clone();
        let server = tokio::spawn(async move { server_handshake(&mut s, &psk2).await.map(|_| ()) });
        let _ck = client_handshake(&mut c, &psk).await.unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn wrong_psk_fails_auth() {
        let (mut c, mut s) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            server_handshake(&mut s, &ObfsPsk([1u8; 32]))
                .await
                .map(|_| ())
        });
        let client = client_handshake(&mut c, &ObfsPsk([2u8; 32])).await;
        assert!(matches!(server.await.unwrap(), Err(ObfsError::AuthFailed)));
        assert!(client.is_err());
    }
}
