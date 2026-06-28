//! Obfuscated, probe-resistant handshake.
//!
//! Flight 1 (client→server) carries a keyed-MAC **gate** (proves PSK knowledge → probe resistance,
//! research D3) *and* the hybrid-KEM initiator message. Flight 2 (server→client) carries the KEM
//! response. Both flights are TLS-record-framed (see [`crate::wire`]). On gate failure the server
//! emits **cryptographic silence** (drain + randomized delay + close) so an active prober cannot
//! distinguish a uber-mesh node from any other service.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use umesh_crypto::aead::AeadKey;
use umesh_crypto::hash::{self, labels};
use umesh_crypto::kem;

use crate::error::{ObfsError, Result};
use crate::wire::{read_record, write_record};

const SALT_LEN: usize = 16;
const MAC_LEN: usize = 16; // truncated BLAKE3-keyed MAC (128-bit tag)
const EPOCH_LEN: usize = 8;

const FLIGHT1_LEN: usize = SALT_LEN + kem::X25519_LEN + kem::MLKEM768_EK_LEN + EPOCH_LEN + MAC_LEN;
const FLIGHT2_LEN: usize = kem::X25519_LEN + kem::MLKEM768_CT_LEN;

/// Maximum time to wait for a peer's handshake flight before treating it as a probe.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A per-listener pre-shared key (the "bridge secret") that gates the obfs handshake.
#[derive(Clone)]
pub struct ObfsPsk(pub [u8; 32]);

impl ObfsPsk {
    fn mac_key(&self) -> [u8; 32] {
        hash::derive_key(labels::OBFS_MAC, &self.0)
    }
}

/// Directional AEAD keys established by the handshake.
pub struct SessionKeys {
    /// Key for data this side sends.
    pub send: AeadKey,
    /// Key for data this side receives.
    pub recv: AeadKey,
}

fn current_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / 60)
        .unwrap_or(0)
}

/// Constant-time equality over equal-length, public-length byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn mac16(mac_key: &[u8; 32], data: &[u8]) -> [u8; MAC_LEN] {
    let full = hash::keyed_mac(mac_key, data);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&full[..MAC_LEN]);
    out
}

/// Drain and discard input for a randomized interval, then return — sending no distinguishing
/// reply. Used when probe-resistance auth fails (the caller drops the stream afterwards).
async fn silence<S>(stream: &mut S)
where
    S: AsyncRead + Unpin,
{
    let delay_ms = rand::random::<u64>() % 350 + 50;
    let _ = tokio::time::timeout(Duration::from_millis(delay_ms), async {
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
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
    let (initiator, init) = kem::Initiator::start();
    let epoch = current_epoch();

    // Build flight 1: salt || x25519 || mlkem_ek || epoch || mac(gate).
    let mut body = Vec::with_capacity(FLIGHT1_LEN);
    let salt: [u8; SALT_LEN] = rand::random();
    body.extend_from_slice(&salt);
    body.extend_from_slice(&init.x25519_pub);
    body.extend_from_slice(&init.mlkem_ek);
    body.extend_from_slice(&epoch.to_le_bytes());
    let mac = mac16(&psk.mac_key(), &body);
    body.extend_from_slice(&mac);
    debug_assert_eq!(body.len(), FLIGHT1_LEN);
    write_record(stream, &body).await?;

    // Flight 2: x25519 || mlkem_ct.
    let resp = read_record(stream).await?;
    if resp.len() != FLIGHT2_LEN {
        return Err(ObfsError::Malformed);
    }
    let mut x = [0u8; kem::X25519_LEN];
    x.copy_from_slice(&resp[..kem::X25519_LEN]);
    let resp_msg = kem::ResponderMessage {
        x25519_pub: x,
        mlkem_ct: resp[kem::X25519_LEN..].to_vec(),
    };
    let ss = initiator.finish(&resp_msg)?;

    Ok(SessionKeys {
        send: AeadKey::derive(labels::TRAFFIC_C2S, &ss),
        recv: AeadKey::derive(labels::TRAFFIC_S2C, &ss),
    })
}

/// Server side of the handshake. Probe-resistant: a non-authenticating peer gets silence + close.
pub async fn server_handshake<S>(stream: &mut S, psk: &ObfsPsk) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read flight 1 under a timeout; any failure ⇒ treat as a probe.
    let body = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_record(stream)).await {
        Ok(Ok(b)) if b.len() == FLIGHT1_LEN => b,
        _ => {
            silence(stream).await;
            return Err(ObfsError::AuthFailed);
        }
    };

    let (signed, mac) = body.split_at(FLIGHT1_LEN - MAC_LEN);
    let expected = mac16(&psk.mac_key(), signed);
    let epoch_off = SALT_LEN + kem::X25519_LEN + kem::MLKEM768_EK_LEN;
    let client_epoch =
        u64::from_le_bytes(signed[epoch_off..epoch_off + EPOCH_LEN].try_into().unwrap());
    let server_epoch = current_epoch();

    // Gate: MAC must match AND the epoch must be within ±1 (clock-skew tolerant replay window).
    let epoch_ok = client_epoch.abs_diff(server_epoch) <= 1;
    if !epoch_ok || !ct_eq(&expected, mac) {
        silence(stream).await;
        return Err(ObfsError::AuthFailed);
    }

    let mut x = [0u8; kem::X25519_LEN];
    x.copy_from_slice(&signed[SALT_LEN..SALT_LEN + kem::X25519_LEN]);
    let ek = signed[SALT_LEN + kem::X25519_LEN..epoch_off].to_vec();
    let init = kem::InitiatorMessage {
        x25519_pub: x,
        mlkem_ek: ek,
    };

    let (ss, resp) = kem::respond(&init)?;
    let mut flight2 = Vec::with_capacity(FLIGHT2_LEN);
    flight2.extend_from_slice(&resp.x25519_pub);
    flight2.extend_from_slice(&resp.mlkem_ct);
    write_record(stream, &flight2).await?;

    Ok(SessionKeys {
        send: AeadKey::derive(labels::TRAFFIC_S2C, &ss),
        recv: AeadKey::derive(labels::TRAFFIC_C2S, &ss),
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
        let ck = client_handshake(&mut c, &psk).await.unwrap();
        server.await.unwrap().unwrap();
        // Keys exist (directional); a deeper data-path test lives in secure.rs / dpi_sim.
        let _ = ck;
    }

    #[tokio::test]
    async fn wrong_psk_fails_auth() {
        let (mut c, mut s) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            server_handshake(&mut s, &ObfsPsk([1u8; 32]))
                .await
                .map(|_| ())
        });
        // Client uses a different PSK; its flight1 MAC won't validate ⇒ server returns AuthFailed.
        let client = client_handshake(&mut c, &ObfsPsk([2u8; 32])).await;
        let server_res = server.await.unwrap();
        assert!(matches!(server_res, Err(ObfsError::AuthFailed)));
        // Client will then fail to read flight 2 (server closed).
        assert!(client.is_err());
    }
}
