//! SOCKS5 and HTTP-CONNECT proxy clients with auth.
//! These are the ONLY sanctioned ways resibox talks to a residential endpoint.

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq)]
pub enum ProxyType {
    Socks5,
    HttpConnect,
}

#[derive(Debug, Clone)]
pub struct ProxyUrl {
    pub kind: ProxyType,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
}

/// Resolve WITHOUT tokio's blocking-pool (this sandbox sometimes refuses
/// thread creation; std resolution runs inline on the current thread).
pub fn resolve_inline(host: &str, port: u16) -> std::io::Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("no addr for {host}")))
}

/// Parse socks5:// / http:// proxy URLs.
pub fn parse_proxy(url: &str) -> Result<ProxyUrl> {
    let (kind, rest) = if let Some(r) = url.strip_prefix("socks5://") {
        (ProxyType::Socks5, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (ProxyType::HttpConnect, r)
    } else if let Some(r) = url.strip_prefix("https://") {
        // Many residential gateways speak plain HTTP CONNECT on TLS ports; treat as CONNECT.
        (ProxyType::HttpConnect, r)
    } else {
        bail!("unsupported proxy scheme in {url} (want socks5:// or http://)");
    };

    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((a, h)) => (Some(a), h),
        None => (None, rest),
    };
    let hostport = hostport.trim_end_matches('/');

    let (user, pass) = match auth {
        Some(a) => {
            let (u, p) = a.split_once(':').unwrap_or((a, ""));
            (
                Some(urldecode(u)),
                Some(urldecode(p)),
            )
        }
        None => (None, None),
    };

    // IPv6 literal or hostname:port — split at LAST colon.
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (
            h.trim_matches(|c| c == '[' || c == ']').to_string(),
            p.parse::<u16>().context("proxy port")?,
        ),
        None => (hostport.to_string(), if kind == ProxyType::Socks5 { 1080 } else { 8080 }),
    };
    Ok(ProxyUrl { kind, host, port, user, pass })
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() + 1 && i + 2 < bytes.len() + 1 => {
                if let (Some(h), Some(l)) = (
                    bytes.get(i + 1).and_then(|c| (*c as char).to_digit(16)),
                    bytes.get(i + 2).and_then(|c| (*c as char).to_digit(16)),
                ) {
                    out.push(((h << 4) | l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Open a raw TCP tunnel to `target` through the proxy.
pub async fn connect_through(
    proxy: &ProxyUrl,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    match proxy.kind {
        ProxyType::Socks5 => socks5_connect(proxy, target_host, target_port).await,
        ProxyType::HttpConnect => http_connect(proxy, target_host, target_port).await,
    }
}

async fn socks5_connect(p: &ProxyUrl, host: &str, port: u16) -> Result<TcpStream> {
    let addr = resolve_inline(&p.host, p.port)?;
    let mut s = TcpStream::connect(addr)
        .await
        .with_context(|| format!("tcp connect to proxy {}:{}", p.host, p.port))?;
    s.set_nodelay(true).ok();

    // Greeting: offer no-auth (x00); add user/pass (x02) when creds present.
    let mut greeting = vec![5u8];
    let methods: &[u8] = if p.user.is_some() { &[0x00, 0x02] } else { &[0x00] };
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    s.write_all(&greeting).await?;

    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 5 {
        bail!("not a SOCKS5 server");
    }
    match resp[1] {
        0x00 => {}
        0x02 => {
            let u = p.user.as_deref().ok_or_else(|| anyhow!("proxy demands auth"))?;
            let pw = p.pass.as_deref().unwrap_or("");
            let mut req = vec![1u8, u.len() as u8];
            req.extend_from_slice(u.as_bytes());
            req.push(pw.len() as u8);
            req.extend_from_slice(pw.as_bytes());
            s.write_all(&req).await?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await?;
            if ar[1] != 0x00 {
                bail!("SOCKS5 auth rejected (status {})", ar[1]);
            }
        }
        m => bail!("SOCKS5 server refused method 0x{m:02x}"),
    }

    // CONNECT via domain name — resolution happens at the EXIT node (residential side).
    let mut req = vec![5u8, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    if hdr[1] != 0x00 {
        bail!("SOCKS5 CONNECT failed with code 0x{:02x}", hdr[1]);
    }
    let skip = match hdr[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        t => bail!("bad SOCKS5 atyp 0x{t:02x}"),
    };
    let mut junk = vec![0u8; skip + 2]; // addr + port
    s.read_exact(&mut junk).await?;
    Ok(s)
}

async fn http_connect(p: &ProxyUrl, host: &str, port: u16) -> Result<TcpStream> {
    let addr = resolve_inline(&p.host, p.port)?;
    let mut s = TcpStream::connect(addr)
        .await
        .with_context(|| format!("tcp connect to proxy {}:{}", p.host, p.port))?;
    s.set_nodelay(true).ok();

    use base64_lite::*;
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(u) = &p.user {
        let cred = encode(format!("{}:{}", u, p.pass.as_deref().unwrap_or("")));
        req.push_str(&format!("Proxy-Authorization: Basic {cred}\r\n"));
    }
    req.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    s.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            bail!("proxy closed during CONNECT handshake");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 32 * 1024 {
            bail!("proxy CONNECT response too large");
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty proxy response"))?;
    // e.g. "HTTP/1.1 200 Connection established"
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| anyhow!("malformed proxy status line: {status}"))?;
    if code != 200 {
        bail!("HTTP CONNECT failed: {status}");
    }
    Ok(s)
}

/// Minimal base64 (avoids an extra dependency).
pub mod base64_lite {
    const TBL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        let d = data.as_ref();
        let mut out = String::with_capacity(d.len().div_ceil(3) * 4);
        for chunk in d.chunks(3) {
            let b = [
                chunk[0],
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(TBL[(n >> 18) as usize & 63] as char);
            out.push(TBL[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                TBL[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TBL[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }
}
