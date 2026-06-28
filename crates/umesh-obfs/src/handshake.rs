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

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use umesh_crypto::aead::{self, AeadKey};
use umesh_crypto::hash::labels;
use umesh_crypto::kem;

use crate::error::{ObfsError, Result};
use crate::wire::{read_record, write_record};

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

/// Server side of the handshake. Probe-resistant: a peer whose flight fails the AEAD gate (no PSK,
/// tampering, or a stale epoch) gets silence + close.
pub async fn server_handshake<S>(stream: &mut S, psk: &ObfsPsk) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = psk.frame_key();

    // Read + open flight 1 under a timeout. Any failure ⇒ treat as a probe (silence).
    let pt = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_record(stream)).await {
        Ok(Ok(wire)) => match aead::open(&key, &wire, HS1_AAD) {
            Ok(pt) if pt.len() == FLIGHT1_PT_LEN => pt,
            _ => {
                silence(stream).await;
                return Err(ObfsError::AuthFailed);
            }
        },
        _ => {
            silence(stream).await;
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
        silence(stream).await;
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
