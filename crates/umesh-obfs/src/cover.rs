//! **Cover-site profile** — REALITY-style "know your cover" for the server's fake TLS flight.
//!
//! A listener with a cover site (`host:port` = its fallback upstream, SNI = the cover domain)
//! periodically connects to that site **with the exact Chrome ClientHello our clients send**
//! (SNI = cover domain, a real `X25519MLKEM768` share, random session_id) and records the record
//! layout of the genuine server flight:
//!
//! - the ServerHello shape (selected suite, selected group, extension order — hence its exact length),
//! - whether a middlebox-compatibility ChangeCipherSpec follows,
//! - the payload size of every encrypted (`0x17`) record up to the point where the server stops and
//!   waits for the client's Finished (bounded: ≤ [`MAX_FLIGHT_RECORDS`] records,
//!   ≤ [`MAX_FLIGHT_BYTES`] in total).
//!
//! The authenticated obfs server flight then reproduces exactly that layout (random record bodies;
//! the key confirmation hidden in the tail of the final record — `handshake`), so a censor that
//! knows or re-fetches the cover site sees the same ServerHello length, CCS presence and record
//! sizes from the bridge as from the real site, and a replayed ClientHello (proxied to the real
//! site) gets the same layout as the genuine session did.
//!
//! **Refresh**: [`CoverSite::start`] learns at startup and then every [`CoverRefresh::interval`]
//! (± jitter); on failure it keeps the last good profile and retries sooner. Until a first profile
//! has been learned the server uses a PSK-derived default layout (the v2 shape).
//!
//! **Trust**: learning is unauthenticated (we do not complete the TLS handshake or validate the
//! certificate). An adversary on the bridge's own uplink can therefore feed a crafted layout; the
//! parser bounds it ([`CoverProfile::validate`]) and the worst outcome is a distinctive layout on
//! that bridge's flights (a confirmation attack against an already-suspected bridge, which needs
//! targeted MITM of the bridge's outbound traffic). See `contracts/handshake-wire.md`.

use std::fmt;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use umesh_crypto::kem;

use crate::error::{ObfsError, Result};
use crate::tls::{self, ServerGroup, ServerHelloShape};
use crate::wire::{HEADER_LEN, MAX_RECORD};

/// Maximum number of encrypted records in a server flight (learned, emitted, and accepted by the
/// client).
pub const MAX_FLIGHT_RECORDS: usize = 8;
/// Maximum total payload of the encrypted records of a server flight.
pub const MAX_FLIGHT_BYTES: usize = 32 * 1024;
/// Maximum payload of one TLS 1.3 ciphertext record (RFC 8446 §5.2: 2^14 + 256).
pub const MAX_CIPHERTEXT_RECORD: usize = MAX_RECORD + 256;
/// Smallest final record that can carry the key confirmation (= a TLS 1.3 SHA-256 Finished record).
pub(crate) const MIN_LAST_RECORD: usize = 53;
/// Encrypted-flight bytes needed ahead of the confirmation when the server selects plain `x25519`
/// (the ML-KEM-768 ciphertext then rides, masked, at the start of the encrypted flight).
pub(crate) const CT_IN_FLIGHT_LEN: usize = kem::MLKEM768_CT_LEN;

/// How long the learner waits for the next record once the encrypted flight has begun; a real
/// server stops after its Finished and waits for ours.
const LEARN_IDLE: Duration = Duration::from_millis(1500);

/// Record layout of a cover site's TLS 1.3 server flight (what a passive observer sees of it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverProfile {
    /// ServerHello suite / group / extension order (determines its exact length).
    pub server_hello: ServerHelloShape,
    /// A ChangeCipherSpec record (`14 03 03 00 01 01`) follows the ServerHello.
    pub ccs: bool,
    /// Payload sizes of the encrypted (`0x17`) records, in order.
    pub records: Vec<usize>,
}

impl CoverProfile {
    /// Total length of the ServerHello record.
    pub fn server_hello_len(&self) -> usize {
        self.server_hello.record_len()
    }

    /// Sum of the encrypted-record payload sizes.
    pub fn flight_bytes(&self) -> usize {
        self.records.iter().sum()
    }

    /// True if an obfs server can reproduce this layout and an obfs client will accept it:
    /// 1..=[`MAX_FLIGHT_RECORDS`] records, each ≤ [`MAX_CIPHERTEXT_RECORD`], ≤ [`MAX_FLIGHT_BYTES`] in
    /// total, a final record that holds the 53-byte confirmation, a Chrome TLS 1.3 suite, and — when
    /// the group is plain `x25519` — room for the 1088-byte ML-KEM ciphertext ahead of the
    /// confirmation.
    pub fn validate(&self) -> bool {
        let n = self.records.len();
        let total = self.flight_bytes();
        (1..=MAX_FLIGHT_RECORDS).contains(&n)
            && self
                .records
                .iter()
                .all(|&l| (1..=MAX_CIPHERTEXT_RECORD).contains(&l))
            && total <= MAX_FLIGHT_BYTES
            && self.records[n - 1] >= MIN_LAST_RECORD
            && tls::TLS13_SUITES.contains(&self.server_hello.cipher_suite)
            && (self.server_hello.group == ServerGroup::X25519MlKem768
                || total >= CT_IN_FLIGHT_LEN + MIN_LAST_RECORD)
    }

    /// Parse a captured server flight — `ServerHello record ‖ [CCS] ‖ 0x17 records…`, exactly as
    /// read off the wire, nothing partial — into a profile. Returns `None` for anything that is not a
    /// TLS 1.3 flight this server can reproduce (TLS 1.2, HelloRetryRequest, an alert, a group other
    /// than `X25519MLKEM768`/`x25519`, out-of-bounds layout). Pure and total: a fuzz target
    /// (`fuzz/fuzz_targets/server_hello.rs`), since the bytes come from the network.
    pub fn from_server_flight(raw: &[u8]) -> Option<CoverProfile> {
        let rec_end = |p: usize| -> Option<usize> {
            let len = u16::from_be_bytes([*raw.get(p + 3)?, *raw.get(p + 4)?]) as usize;
            let end = p.checked_add(HEADER_LEN)?.checked_add(len)?;
            (end <= raw.len()).then_some(end)
        };
        let sh_end = rec_end(0)?;
        let sh = tls::parse_server_hello(&raw[..sh_end])?;
        let mut p = sh_end;
        let ccs = raw.get(p..p + tls::CCS_RECORD.len()) == Some(&tls::CCS_RECORD[..]);
        if ccs {
            p += tls::CCS_RECORD.len();
        }
        let mut records = Vec::new();
        while p < raw.len() {
            if raw.get(p..p + 3)? != crate::wire::TLS_PREFIX || records.len() >= MAX_FLIGHT_RECORDS
            {
                return None;
            }
            let end = rec_end(p)?;
            records.push(end - p - HEADER_LEN);
            p = end;
        }
        let profile = CoverProfile {
            server_hello: sh.shape,
            ccs,
            records,
        };
        profile.validate().then_some(profile)
    }
}

/// Connect to `upstream` with our Chrome ClientHello (SNI = `domain`) and capture the server's
/// flight up to the point where it waits for the client Finished. Bounded by `timeout` overall.
pub async fn learn_cover_profile(
    upstream: &str,
    domain: &str,
    timeout: Duration,
) -> Result<CoverProfile> {
    let deadline = Instant::now() + timeout;
    let mut sock = tokio::time::timeout_at(deadline, TcpStream::connect(upstream))
        .await
        .map_err(|_| timeout_err("cover connect"))??;
    let _ = sock.set_nodelay(true);
    let raw = capture_server_flight(&mut sock, domain, deadline).await?;
    CoverProfile::from_server_flight(&raw).ok_or(ObfsError::Malformed)
}

/// The Chrome ClientHello the learner sends: identical template to an obfs client's, with a real
/// `X25519MLKEM768` share (so the cover site can encapsulate) and a random 32-byte session_id.
fn learner_client_hello(domain: &str) -> Vec<u8> {
    let (_initiator, init) = kem::Initiator::start();
    let mut share = Vec::with_capacity(tls::HYBRID_CLIENT_SHARE_LEN);
    share.extend_from_slice(&init.mlkem_ek);
    share.extend_from_slice(&init.x25519_pub);
    let mut ch = tls::build_client_hello(&mut OsRng, &share, domain);
    OsRng.fill_bytes(&mut ch[tls::SESSION_ID_OFFSET..tls::SESSION_ID_OFFSET + tls::SESSION_ID_LEN]);
    ch
}

/// Send the learner hello on `io` and read back the raw server flight (ServerHello, optional CCS,
/// encrypted records) until the server goes quiet for 1.5 s, closes, or exceeds the bounds.
pub async fn capture_server_flight<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    domain: &str,
    deadline: Instant,
) -> Result<Vec<u8>> {
    io.write_all(&learner_client_hello(domain)).await?;
    io.flush().await?;
    let mut raw = Vec::with_capacity(8 * 1024);
    let mut encrypted = 0usize;
    let mut flight_bytes = 0usize;
    loop {
        // Before the first encrypted record wait up to the deadline; after it, only LEARN_IDLE.
        let wait = if encrypted == 0 {
            deadline
        } else {
            deadline.min(Instant::now() + LEARN_IDLE)
        };
        let mut hdr = [0u8; HEADER_LEN];
        match tokio::time::timeout_at(wait, io.read_exact(&mut hdr)).await {
            Ok(Ok(_)) => {}
            // Quiet or closed after the flight began: the flight is complete.
            Ok(Err(_)) | Err(_) if encrypted > 0 => return Ok(raw),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(timeout_err("cover flight read")),
        }
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let is_first = raw.is_empty();
        match hdr[0] {
            0x16 if is_first && len <= MAX_RECORD => {}
            0x14 if !is_first && encrypted == 0 && len == 1 => {}
            0x17 if !is_first && len <= MAX_CIPHERTEXT_RECORD => {
                encrypted += 1;
                flight_bytes += len;
                if encrypted > MAX_FLIGHT_RECORDS || flight_bytes > MAX_FLIGHT_BYTES {
                    return Err(ObfsError::RecordTooLarge);
                }
            }
            // Alerts, TLS 1.2 handshake continuation, anything else: not a reproducible flight.
            _ => return Err(ObfsError::Malformed),
        }
        let start = raw.len();
        raw.extend_from_slice(&hdr);
        raw.resize(start + HEADER_LEN + len, 0);
        tokio::time::timeout_at(deadline, io.read_exact(&mut raw[start + HEADER_LEN..]))
            .await
            .map_err(|_| timeout_err("cover flight read"))??;
    }
}

fn timeout_err(what: &str) -> ObfsError {
    ObfsError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{what} timed out"),
    ))
}

/// Refresh schedule of a [`CoverSite`].
#[derive(Clone, Debug)]
pub struct CoverRefresh {
    /// Mean interval between successful refreshes (default 30 min).
    pub interval: Duration,
    /// Uniform jitter applied to every wait (± this; default 5 min).
    pub jitter: Duration,
    /// Wait before retrying after a failed refresh (± jitter/4; default 2 min).
    pub retry: Duration,
    /// Bound on one learning connection (connect + flight; default 10 s).
    pub timeout: Duration,
}

impl Default for CoverRefresh {
    fn default() -> Self {
        CoverRefresh {
            interval: Duration::from_secs(30 * 60),
            jitter: Duration::from_secs(5 * 60),
            retry: Duration::from_secs(2 * 60),
            timeout: Duration::from_secs(10),
        }
    }
}

fn jittered(base: Duration, jitter: Duration) -> Duration {
    let j = jitter.as_millis().min(base.as_millis()) as u64;
    if j == 0 {
        return base;
    }
    let base = base.as_millis() as u64;
    Duration::from_millis(base - j + OsRng.gen_range(0..=2 * j))
}

struct CoverInner {
    upstream: String,
    domain: String,
    profile: RwLock<Option<Arc<CoverProfile>>>,
    refresher: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for CoverInner {
    fn drop(&mut self) {
        if let Some(h) = self
            .refresher
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            h.abort();
        }
    }
}

/// A listener's cover site: where probes are proxied (`upstream`, `host:port`), the domain clients
/// put in their SNI (`domain`), and the most recently learned [`CoverProfile`]. Cheap to clone
/// (shared state); the background refresher stops when the last clone is dropped.
#[derive(Clone)]
pub struct CoverSite {
    inner: Arc<CoverInner>,
}

impl fmt::Debug for CoverSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoverSite")
            .field("upstream", &self.inner.upstream)
            .field("domain", &self.inner.domain)
            .field("profile", &self.profile())
            .finish()
    }
}

impl CoverSite {
    /// A cover site without a profile yet (no background task). `domain` defaults to the host part of
    /// `upstream` when that is a DNS name; an error if no valid SNI domain results (e.g. an IP
    /// upstream without an explicit domain).
    pub fn new(upstream: impl Into<String>, domain: Option<&str>) -> Result<Self> {
        let upstream = upstream.into();
        let domain = match domain {
            Some(d) => d.trim().trim_end_matches('.').to_ascii_lowercase(),
            None => host_of(&upstream).to_ascii_lowercase(),
        };
        if !tls::sni_is_valid(&domain) {
            return Err(ObfsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cover domain must be a DNS name (give it explicitly for an IP upstream)",
            )));
        }
        Ok(CoverSite {
            inner: Arc::new(CoverInner {
                upstream,
                domain,
                profile: RwLock::new(None),
                refresher: Mutex::new(None),
            }),
        })
    }

    /// [`CoverSite::new`] + [`CoverSite::start`] with the default schedule (learn now, then every
    /// 30 min ± 5 min). Must be called inside a Tokio runtime.
    pub fn spawn(upstream: impl Into<String>, domain: Option<&str>) -> Result<Self> {
        let site = Self::new(upstream, domain)?;
        site.start(CoverRefresh::default());
        Ok(site)
    }

    /// Start the background refresher (idempotent): learn immediately, then on `schedule`. Failures
    /// keep the last good profile. Must be called inside a Tokio runtime.
    pub fn start(&self, schedule: CoverRefresh) {
        let mut slot = self
            .inner
            .refresher
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if slot.is_some() {
            return;
        }
        let weak = Arc::downgrade(&self.inner);
        *slot = Some(tokio::spawn(refresher(weak, schedule)));
    }

    /// Learn the profile now. On success it replaces the current one; on failure the last good
    /// profile (or none) is kept and the error returned.
    pub async fn refresh(&self, timeout: Duration) -> Result<Arc<CoverProfile>> {
        match learn_cover_profile(&self.inner.upstream, &self.inner.domain, timeout).await {
            Ok(p) => {
                tracing::debug!(
                    server_hello = p.server_hello_len(),
                    ccs = p.ccs,
                    records = ?p.records,
                    "cover profile learned"
                );
                let p = Arc::new(p);
                self.set_profile_arc(p.clone());
                Ok(p)
            }
            Err(e) => {
                tracing::debug!(error = %e, kept = self.profile().is_some(), "cover profile refresh failed");
                Err(e)
            }
        }
    }

    /// Install a profile (e.g. operator-pinned or from a capture). Ignored unless it validates.
    pub fn set_profile(&self, profile: CoverProfile) -> bool {
        if !profile.validate() {
            return false;
        }
        self.set_profile_arc(Arc::new(profile));
        true
    }

    fn set_profile_arc(&self, p: Arc<CoverProfile>) {
        *self
            .inner
            .profile
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(p);
    }

    /// The last good profile, if any has been learned.
    pub fn profile(&self) -> Option<Arc<CoverProfile>> {
        self.inner
            .profile
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The upstream `host:port` probes are proxied to and the profile is learned from.
    pub fn upstream(&self) -> &str {
        &self.inner.upstream
    }

    /// The cover domain (the SNI clients must send for the mimicry to be consistent).
    pub fn domain(&self) -> &str {
        &self.inner.domain
    }
}

async fn refresher(weak: Weak<CoverInner>, schedule: CoverRefresh) {
    loop {
        let Some(inner) = weak.upgrade() else {
            return;
        };
        let site = CoverSite { inner };
        let ok = site.refresh(schedule.timeout).await.is_ok();
        drop(site);
        let wait = if ok {
            jittered(schedule.interval, schedule.jitter)
        } else {
            jittered(schedule.retry, schedule.jitter / 4)
        };
        tokio::time::sleep(wait).await;
    }
}

/// Host part of `host:port` / `[v6]:port` / bare host.
fn host_of(upstream: &str) -> &str {
    let s = upstream.trim();
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A raw cover flight: ServerHello of `shape`, optional CCS, 0x17 records of `records` sizes.
    pub(crate) fn flight(shape: &ServerHelloShape, ccs: bool, records: &[usize]) -> Vec<u8> {
        let share = vec![0x42; shape.group.share_len()];
        let mut raw = tls::build_server_hello_shaped(&mut OsRng, &[7; 32], shape, &share);
        if ccs {
            raw.extend_from_slice(&tls::CCS_RECORD);
        }
        for &l in records {
            raw.extend_from_slice(&crate::wire::TLS_PREFIX);
            raw.extend_from_slice(&(l as u16).to_be_bytes());
            raw.extend(std::iter::repeat_n(0xA5, l));
        }
        raw
    }

    fn x25519() -> ServerHelloShape {
        ServerHelloShape {
            cipher_suite: 0x1302,
            group: ServerGroup::X25519,
            key_share_first: true,
        }
    }

    #[test]
    fn parses_common_layouts() {
        // Cloudflare/BoringSSL-like: PQ, CCS, one coalesced record.
        let p =
            CoverProfile::from_server_flight(&flight(&ServerHelloShape::default(), true, &[3561]))
                .unwrap();
        assert_eq!(p.records, vec![3561]);
        assert!(p.ccs);
        assert_eq!(p.server_hello_len(), 1215);
        // nginx/OpenSSL-like: x25519, AES-256, EE/Cert/CV/Fin split, no CCS.
        let p = CoverProfile::from_server_flight(&flight(&x25519(), false, &[36, 2875, 281, 69]))
            .unwrap();
        assert_eq!(p.records, vec![36, 2875, 281, 69]);
        assert!(!p.ccs);
        assert_eq!(p.server_hello, x25519());
        assert_eq!(p.server_hello_len(), 127);
    }

    #[test]
    fn rejects_out_of_bounds_layouts() {
        let d = ServerHelloShape::default();
        let parse = |raw: Vec<u8>| CoverProfile::from_server_flight(&raw);
        assert!(
            parse(flight(&d, true, &[])).is_none(),
            "no encrypted records"
        );
        assert!(parse(flight(&d, true, &[100; 9])).is_none(), "> 8 records");
        assert!(
            parse(flight(&d, true, &[16000, 16000, 1000])).is_none(),
            "> 32 KiB"
        );
        assert!(parse(flight(&d, true, &[2000, 40])).is_none(), "last < 53");
        assert!(parse(flight(&d, true, &[100; 8])).is_some(), "8 records ok");
        // x25519 needs room for the 1088-byte ct ahead of the confirmation.
        assert!(parse(flight(&x25519(), true, &[1000, 100])).is_none());
        assert!(parse(flight(&x25519(), true, &[1088, 53])).is_some());
        // Trailing partial record, an alert, garbage after the CCS.
        let mut t = flight(&d, true, &[3000]);
        t.pop();
        assert!(parse(t).is_none());
        let mut a = flight(&d, true, &[3000]);
        a.extend_from_slice(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);
        assert!(parse(a).is_none());
        assert!(parse(vec![]).is_none());
        // A ServerHello alone (TLS 1.2-style continuation would be 0x16) is not a flight.
        let mut h = flight(&d, false, &[]);
        h.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x04, 0x0b, 0, 0, 0]);
        assert!(parse(h).is_none());
    }

    #[test]
    fn parser_is_total_on_truncations() {
        let raw = flight(&x25519(), true, &[36, 2875, 281, 69]);
        for n in 0..raw.len() {
            let _ = CoverProfile::from_server_flight(&raw[..n]);
        }
    }

    #[test]
    fn cover_domain_defaults_to_upstream_host() {
        let s = CoverSite::new("www.example.com:443", None).unwrap();
        assert_eq!(s.domain(), "www.example.com");
        assert!(CoverSite::new("203.0.113.5:443", None).is_err());
        let s = CoverSite::new("203.0.113.5:443", Some("Cdn.Example.NET.")).unwrap();
        assert_eq!(s.domain(), "cdn.example.net");
        assert_eq!(host_of("[2001:db8::1]:443"), "2001:db8::1");
        assert!(s.profile().is_none());
        assert!(!s.set_profile(CoverProfile {
            server_hello: ServerHelloShape::default(),
            ccs: true,
            records: vec![],
        }));
    }

    #[test]
    fn jitter_stays_in_range() {
        for _ in 0..200 {
            let d = jittered(Duration::from_secs(1800), Duration::from_secs(300));
            assert!((1500..=2100).contains(&d.as_secs()));
        }
        assert_eq!(
            jittered(Duration::from_millis(5), Duration::ZERO),
            Duration::from_millis(5)
        );
    }
}
