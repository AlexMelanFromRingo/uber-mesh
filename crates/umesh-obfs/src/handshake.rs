//! Obfuscated, probe-resistant handshake — riding a real TLS 1.3 handshake.
//!
//! The first flight is a structurally-valid **TLS 1.3 ClientHello** ([`crate::tls`]) and the reply a
//! **ServerHello**. The hybrid X25519 + ML-KEM-768 key agreement is carried in the
//! `X25519MLKEM768` `key_share` — exactly the shape a modern PQ-TLS browser sends, so:
//! - On the wire the flow **opens with a ClientHello (record type `0x16`), then a ServerHello, then
//!   application-data records** — a valid TLS *state-machine* opening. This defeats the strict
//!   "handshake-must-precede-app-data" DPI heuristic that flagged the old app-data-first carrier, and
//!   the 1216-byte PQ key_share blends with real X25519MLKEM768 traffic (Chrome/Cloudflare default).
//! - The **probe-resistance gate is a PSK-keyed MAC carried in the 32-byte `session_id`**: a peer
//!   without the PSK cannot produce a ClientHello whose `session_id` authenticates, so the server
//!   replies with **silence** or **proxies a real cover site** (REALITY model) and an active prober
//!   cannot distinguish a uber-mesh node from a genuine TLS server.
//! - The KEM material is public (as in any TLS key_share); session confidentiality comes from the KEM
//!   shared secret and the AEAD record layer above — no payload secrecy is lost by exposing it.
//!
//! *Peer identity* (which specific node) is still established by the signed-hello / Noise layer above
//! this transport — the obfs layer authenticates the carrier, not the peer.
//!
//! Residual gap (deferred native REALITY, see `docs/security-and-deferred.md`): this is structurally
//! valid, not a **byte-exact uTLS fingerprint** of a specific browser (JA3/JA4) and the transcript is
//! not a full TLS 1.3 handshake (no EncryptedExtensions/Certificate/Finished) — a DPI doing full
//! transcript validation would still distinguish it. Closing that needs a real TLS stack.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use umesh_crypto::aead::AeadKey;
use umesh_crypto::hash::{Hash32, derive_key, keyed_mac, labels};
use umesh_crypto::kem;

use crate::error::{ObfsError, Result};
use crate::tls;
use crate::wire::read_record_raw;

/// How the server treats a connection that fails the obfs gate (active-probe resistance).
#[derive(Clone, Debug, Default)]
pub enum ProbeResponse {
    /// Drain + randomized delay + close, sending no distinguishing reply (obfs4 model).
    #[default]
    Silence,
    /// Reverse-proxy the connection to a real upstream `host:port`, forwarding the bytes already
    /// received, so a prober transparently talks to a genuine site (REALITY/ShadowTLS model,
    /// research D3). On `:443` this is stronger than silence — silence is itself anomalous there.
    Fallback(String),
}

/// Domain-separation tag for the session_id gate MAC.
const GATE_CTX: &[u8] = b"uber-mesh ch-gate v1";
/// Client key_share = ml-kem-768 ek(1184) ‖ x25519 pub(32).
const CLIENT_KS_LEN: usize = kem::MLKEM768_EK_LEN + kem::X25519_LEN;
/// Server key_share = ml-kem-768 ct(1088) ‖ x25519 pub(32).
const SERVER_KS_LEN: usize = kem::MLKEM768_CT_LEN + kem::X25519_LEN;

/// Direction tags bound into record AAD (also pick the directional traffic key).
pub(crate) const DIR_C2S: u8 = 0;
pub(crate) const DIR_S2C: u8 = 1;

/// Maximum time to wait for a peer's handshake flight before treating it as a probe.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Hard cap on bytes drained from a rejected/probing connection (DoS bound).
const MAX_DRAIN_BYTES: usize = 64 * 1024;

/// SNI presented in the cover ClientHello. Overridable so an operator can match a chosen cover
/// domain (`UMESH_SNI`). A single fixed default is itself a fingerprint — per-connection cover-domain
/// selection is part of the deferred native-REALITY work.
fn cover_sni() -> String {
    std::env::var("UMESH_SNI").unwrap_or_else(|_| "www.cloudflare.com".to_string())
}

/// A per-listener pre-shared key (the "bridge secret") that gates the obfs handshake.
#[derive(Clone)]
pub struct ObfsPsk(pub [u8; 32]);

impl ObfsPsk {
    /// PSK-derived key for the session_id gate MAC (the probe-resistance gate).
    fn mac_key(&self) -> Hash32 {
        derive_key(labels::OBFS_MAC, &self.0)
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

/// Constant-time equality (length is fixed/public here; only contents are secret-dependent).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

/// MAC over the (public) key_share + epoch under the PSK — the gate authenticator.
fn gate_tag(psk: &ObfsPsk, key_share: &[u8], epoch: u64) -> Hash32 {
    let mut data = Vec::with_capacity(GATE_CTX.len() + key_share.len() + 8);
    data.extend_from_slice(GATE_CTX);
    data.extend_from_slice(key_share);
    data.extend_from_slice(&epoch.to_le_bytes());
    keyed_mac(&psk.mac_key(), &data)
}

/// The 32-byte TLS `session_id` doubling as the obfs gate: `epoch_le(8) ‖ MAC(key_share, epoch)[..24]`.
fn gate_session_id(psk: &ObfsPsk, key_share: &[u8], epoch: u64) -> [u8; 32] {
    let tag = gate_tag(psk, key_share, epoch);
    let mut sid = [0u8; 32];
    sid[..8].copy_from_slice(&epoch.to_le_bytes());
    sid[8..32].copy_from_slice(&tag[..24]);
    sid
}

/// Verify a `session_id` gate against `key_share`. Returns the (authenticated) epoch on success.
fn verify_gate(psk: &ObfsPsk, session_id: &[u8; 32], key_share: &[u8]) -> Option<u64> {
    let epoch = u64::from_le_bytes(session_id[..8].try_into().ok()?);
    let expect = gate_tag(psk, key_share, epoch);
    ct_eq(&session_id[8..32], &expect[..24]).then_some(epoch)
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
    let (initiator, init) = kem::Initiator::start();
    let epoch = current_epoch();

    // Client key_share = ml-kem ek ‖ x25519 pub, carried in an X25519MLKEM768 ClientHello.
    let mut ks = Vec::with_capacity(CLIENT_KS_LEN);
    ks.extend_from_slice(&init.mlkem_ek);
    ks.extend_from_slice(&init.x25519_pub);
    let session_id = gate_session_id(psk, &ks, epoch);
    let ch = tls::build_client_hello(&session_id, &ks, &cover_sni());
    stream.write_all(&ch).await?;
    stream.flush().await?;

    // Reply: a ServerHello whose key_share is ml-kem ct ‖ x25519 pub.
    let raw = read_record_raw(stream).await?;
    let server_ks = tls::parse_server_hello(&raw).ok_or(ObfsError::Malformed)?;
    if server_ks.len() != SERVER_KS_LEN {
        return Err(ObfsError::Malformed);
    }
    let mut x = [0u8; kem::X25519_LEN];
    x.copy_from_slice(&server_ks[kem::MLKEM768_CT_LEN..]);
    let resp_msg = kem::ResponderMessage {
        x25519_pub: x,
        mlkem_ct: server_ks[..kem::MLKEM768_CT_LEN].to_vec(),
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

/// Server side of the handshake with an explicit probe-response policy. A ClientHello whose
/// `session_id` fails the PSK gate (no PSK, tampering, a stale epoch, or a foreign/real TLS client)
/// is handled per `probe` (silence or fallback-proxy).
pub async fn server_handshake_probe<S>(
    stream: &mut S,
    psk: &ObfsPsk,
    probe: &ProbeResponse,
) -> Result<SessionKeys>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read the raw ClientHello under a timeout, keeping the bytes for the fallback path.
    let raw = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_record_raw(stream)).await {
        Ok(Ok(raw)) => raw,
        _ => {
            handle_probe(stream, &[], probe).await;
            return Err(ObfsError::AuthFailed);
        }
    };

    // Parse + gate. Any failure (unparseable, wrong key_share size, bad MAC, stale epoch) is treated
    // uniformly as a probe — a foreign/real ClientHello transparently reaches the cover site.
    let gated = match tls::parse_client_hello(&raw) {
        Some((session_id, ks)) if ks.len() == CLIENT_KS_LEN => {
            match verify_gate(psk, &session_id, &ks) {
                Some(epoch) if epoch.abs_diff(current_epoch()) <= 1 => Some((session_id, ks)),
                _ => None,
            }
        }
        _ => None,
    };
    let Some((session_id, ks)) = gated else {
        handle_probe(stream, &raw, probe).await;
        return Err(ObfsError::AuthFailed);
    };

    // Split the client key_share, run the KEM, answer with a ServerHello carrying our key_share.
    let mut x = [0u8; kem::X25519_LEN];
    x.copy_from_slice(&ks[kem::MLKEM768_EK_LEN..]);
    let init = kem::InitiatorMessage {
        x25519_pub: x,
        mlkem_ek: ks[..kem::MLKEM768_EK_LEN].to_vec(),
    };
    let (ss, resp) = kem::respond(&init)?;

    let mut server_ks = Vec::with_capacity(SERVER_KS_LEN);
    server_ks.extend_from_slice(&resp.mlkem_ct);
    server_ks.extend_from_slice(&resp.x25519_pub);
    // Echo the client's session_id verbatim, as a TLS 1.3 server echoes legacy_session_id.
    let sh = tls::build_server_hello(&session_id, &server_ks);
    stream.write_all(&sh).await?;
    stream.flush().await?;

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

    #[test]
    fn gate_authenticates_only_with_psk() {
        let psk = ObfsPsk([5u8; 32]);
        let ks = vec![0xABu8; CLIENT_KS_LEN];
        let epoch = current_epoch();
        let sid = gate_session_id(&psk, &ks, epoch);
        assert_eq!(verify_gate(&psk, &sid, &ks), Some(epoch));
        // Wrong PSK rejects.
        assert_eq!(verify_gate(&ObfsPsk([6u8; 32]), &sid, &ks), None);
        // Tampered key_share rejects (MAC binds it).
        let mut ks2 = ks.clone();
        ks2[0] ^= 1;
        assert_eq!(verify_gate(&psk, &sid, &ks2), None);
    }
}
