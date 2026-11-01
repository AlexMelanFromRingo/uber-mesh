//! Opt-in Prometheus `/metrics` HTTP endpoint (no framework — the exposition format is plain text).
//!
//! The endpoint is unauthenticated plaintext HTTP whose metric names (`umesh_*`) identify the host
//! as an uber-mesh node to anyone who can reach it — a censor scanning the host would defeat the
//! obfs layer's probe resistance (constitution Principle II). It is therefore:
//! - **off by default** — enabled only by `--metrics-addr` / `UMESH_METRICS_ADDR`;
//! - **loopback by default** — a bare port binds `127.0.0.1`; a non-loopback bind is warned about;
//! - **bounded** — header-read and write timeouts, a header size cap, and a concurrent-connection
//!   cap, so it cannot be used to exhaust the node (slowloris / connection floods).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Env var enabling the endpoint (same syntax as `--metrics-addr`).
pub const ENV_ADDR: &str = "UMESH_METRICS_ADDR";
/// Legacy env var (pre-hardening: on by default on `0.0.0.0`). Now opt-in and loopback-only.
pub const ENV_LEGACY_PORT: &str = "METRICS_PORT";

/// Resource limits for the endpoint.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Max time to receive the full request head.
    pub header_timeout: Duration,
    /// Max time to write the response.
    pub write_timeout: Duration,
    /// Max request-head size in bytes.
    pub max_header: usize,
    /// Max concurrently served connections; excess connections are closed immediately.
    pub max_conns: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            header_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            max_header: 8 * 1024,
            max_conns: 8,
        }
    }
}

/// Parse a metrics address: `off`/empty ⇒ disabled; a bare port ⇒ `127.0.0.1:<port>`;
/// otherwise an explicit `ip:port` (e.g. `0.0.0.0:9100` inside a private container network).
pub fn parse_addr(s: &str) -> anyhow::Result<Option<SocketAddr>> {
    let s = s.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    if let Ok(port) = s.parse::<u16>() {
        return Ok(Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)));
    }
    s.parse::<SocketAddr>()
        .map(Some)
        .with_context(|| format!("invalid metrics address {s:?} (expected PORT, IP:PORT or off)"))
}

/// Resolve the metrics bind address from (in precedence order) the CLI flag, `UMESH_METRICS_ADDR`,
/// and the legacy `METRICS_PORT`. Returns `None` (disabled) when none is set.
pub fn resolve_addr(
    flag: Option<&str>,
    env_addr: Option<&str>,
    legacy_port: Option<&str>,
) -> anyhow::Result<Option<SocketAddr>> {
    if let Some(f) = flag {
        return parse_addr(f);
    }
    if let Some(e) = env_addr {
        return parse_addr(e);
    }
    if let Some(p) = legacy_port {
        let p = p.trim();
        if p.is_empty() || p.eq_ignore_ascii_case("off") {
            return Ok(None);
        }
        let Ok(port) = p.parse::<u16>() else {
            bail!("invalid {ENV_LEGACY_PORT} {p:?}");
        };
        tracing::warn!(
            "{ENV_LEGACY_PORT} is deprecated; binding metrics to 127.0.0.1:{port} only. \
             Use --metrics-addr / {ENV_ADDR} to choose the address explicitly."
        );
        return Ok(Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)));
    }
    Ok(None)
}

/// Bind the endpoint (failing loudly — it was explicitly requested) and warn on exposure.
pub async fn bind(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    if !addr.ip().is_loopback() {
        tracing::warn!(
            %addr,
            "metrics endpoint bound to a non-loopback address: it is unauthenticated and its \
             metric names identify this host as an uber-mesh node to scanners"
        );
    }
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding metrics endpoint {addr}"))
}

/// Serve `GET /metrics` on `listener` forever, rendering the body with `render`.
pub async fn serve<F>(listener: TcpListener, limits: Limits, render: F)
where
    F: Fn() -> String + Send + Sync + 'static,
{
    let render = Arc::new(render);
    let slots = Arc::new(Semaphore::new(limits.max_conns.max(1)));
    loop {
        let sock = match listener.accept().await {
            Ok((sock, _)) => sock,
            Err(e) => {
                tracing::debug!(error = %e, "metrics accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        // Over the cap: close immediately rather than queueing unbounded work.
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            drop(sock);
            continue;
        };
        let render = render.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle(sock, limits, &*render).await;
        });
    }
}

async fn handle(mut sock: TcpStream, limits: Limits, render: &(dyn Fn() -> String + Send + Sync)) {
    let head = match tokio::time::timeout(
        limits.header_timeout,
        read_head(&mut sock, limits.max_header),
    )
    .await
    {
        Ok(Some(h)) => h,
        _ => return, // timeout, oversize, EOF or I/O error: just close
    };
    let resp = if is_metrics_request(&head) {
        let body = render();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    } else {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    };
    let _ = tokio::time::timeout(limits.write_timeout, sock.write_all(resp.as_bytes())).await;
}

/// Read until the end of the request head (`\r\n\r\n`). `None` on EOF, error or oversize.
async fn read_head(sock: &mut TcpStream, max: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        let n = sock.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Some(buf);
        }
        if buf.len() >= max {
            return None;
        }
    }
}

fn is_metrics_request(head: &[u8]) -> bool {
    let line = head.split(|&b| b == b'\r').next().unwrap_or_default();
    let mut parts = line.split(|&b| b == b' ');
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return false;
    };
    method == b"GET" && (target == b"/metrics" || target.starts_with(b"/metrics?"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_are_off_by_default() {
        assert_eq!(resolve_addr(None, None, None).unwrap(), None);
    }

    #[test]
    fn bare_port_binds_loopback() {
        let a = resolve_addr(Some("9100"), None, None).unwrap().unwrap();
        assert_eq!(a, "127.0.0.1:9100".parse().unwrap());
        // Legacy METRICS_PORT is now loopback-only too (was 0.0.0.0).
        let a = resolve_addr(None, None, Some("9100")).unwrap().unwrap();
        assert!(a.ip().is_loopback());
        assert_eq!(resolve_addr(None, None, Some("off")).unwrap(), None);
    }

    #[test]
    fn explicit_addr_and_precedence() {
        let a = resolve_addr(Some("0.0.0.0:9200"), Some("9300"), Some("9400"))
            .unwrap()
            .unwrap();
        assert_eq!(a, "0.0.0.0:9200".parse().unwrap());
        let a = resolve_addr(None, Some("[::1]:9300"), Some("9400"))
            .unwrap()
            .unwrap();
        assert_eq!(a, "[::1]:9300".parse().unwrap());
        assert_eq!(resolve_addr(Some("off"), Some("9300"), None).unwrap(), None);
        assert!(resolve_addr(Some("not-an-addr"), None, None).is_err());
    }

    async fn start(limits: Limits) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(serve(l, limits, || "umesh_test 1\n".to_string()));
        addr
    }

    async fn get(addr: SocketAddr, req: &[u8]) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(req).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn serves_metrics_and_404s_other_paths() {
        let addr = start(Limits::default()).await;
        let r = get(addr, b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
        assert!(r.ends_with("umesh_test 1\n"));
        let r = get(addr, b"GET / HTTP/1.1\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 404"), "{r}");
        assert!(
            !r.contains("umesh_"),
            "non-metrics paths must not leak metric names"
        );
    }

    #[tokio::test]
    async fn slow_header_is_cut_off_and_conn_cap_enforced() {
        let limits = Limits {
            header_timeout: Duration::from_millis(200),
            max_conns: 1,
            ..Limits::default()
        };
        let addr = start(limits).await;

        // Slowloris: never finishes the head ⇒ closed after the header timeout, no response.
        let mut slow = TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET /metrics HTTP/1.1\r\n").await.unwrap();
        // While `slow` holds the only slot, another connection is closed immediately.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut over = TcpStream::connect(addr).await.unwrap();
        let mut buf = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(1), over.read_to_end(&mut buf))
            .await
            .expect("over-cap connection should be closed promptly");
        assert_eq!(n.unwrap_or(0), 0);

        let mut buf = Vec::new();
        let r = tokio::time::timeout(Duration::from_secs(2), slow.read_to_end(&mut buf))
            .await
            .expect("slow client must be cut off by the header timeout");
        assert_eq!(r.unwrap_or(0), 0, "no response to an incomplete request");

        // Slot freed (give the handler task a moment to release it): a normal scrape works again.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let r = get(addr, b"GET /metrics HTTP/1.1\r\n\r\n").await;
        assert!(r.starts_with("HTTP/1.1 200 OK"));
    }
}
