//! Per-container DNS relay: UDP:53 inside the netns -> TCP DNS THROUGH the
//! assigned proxy. Applications never touch a resolver outside the tunnel;
//! plain UDP egress is firewalled to DROP anyway.

use crate::proxy::{connect_through, ProxyUrl};
use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct DnsRelay {
    pub bind: String,
    pub proxy: Arc<ProxyUrl>,
    pub resolvers: Vec<String>, // "9.9.9.9:53" style; queried over TCP via proxy
}

impl DnsRelay {
    pub async fn run(self) -> Result<()> {
        let sock = std::sync::Arc::new(UdpSocket::bind(&self.bind).await?);
        tracing::info!(bind = %self.bind, resolvers=?self.resolvers, "dns-relay up");
        let proxy = self.proxy.clone();
        let resolvers = self.resolvers.clone();
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    tracing::debug!("dns recv err {e}");
                    continue;
                }
            };
            let query = buf[..n].to_vec();
            let proxy = proxy.clone();
            let resolvers = resolvers.clone();
            let s = sock.clone();
            tokio::spawn(async move {
                match resolve_via_proxy(&proxy, &resolvers, &query).await {
                    Ok(resp) => {
                        let _ = s.send_to(&resp, peer).await;
                    }
                    Err(e) => {
                        tracing::debug!("dns relay fail: {e:#}");
                        // Fail-closed: send FORMERR so callers don't hang forever.
                        let mut formerr = query.clone();
                        if formerr.len() >= 4 {
                            formerr[3] = (formerr[3] & 0xF0) | 0x01; // RCODE=1
                            let _ = s.send_to(&formerr[..std::cmp::min(formerr.len(), 12)], peer).await;
                        }
                    }
                }
            });
        }
    }
}

/// DNS-over-TCP framed query, tunneled through the proxy.
pub async fn resolve_via_proxy(
    proxy: &ProxyUrl,
    resolvers: &[String],
    udp_query: &[u8],
) -> Result<Vec<u8>> {
    let mut last_err = None;
    for r in resolvers {
        let (rh, rport) = r
            .rsplit_once(':')
            .and_then(|(h, p)| Some((h.trim_matches(|c| c == '[' || c == ']'), p.parse::<u16>().ok()?)))
            .ok_or_else(|| anyhow!("bad resolver {r}"))?;
        match tcp_dns_exchange(proxy, rh, rport, udp_query).await {
            Ok(resp) => return Ok(resp),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no resolvers configured")))
}

async fn tcp_dns_exchange(
    proxy: &ProxyUrl,
    resolver_host: &str,
    resolver_port: u16,
    udp_query: &[u8],
) -> Result<Vec<u8>> {
    use std::time::Duration;
    const T: Duration = Duration::from_secs(10);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let fut = async {
        let mut s = connect_through(proxy, resolver_host, resolver_port).await?;
        s.set_nodelay(true).ok();
        let mut framed = Vec::with_capacity(udp_query.len() + 2);
        framed.extend_from_slice(&(udp_query.len() as u16).to_be_bytes());
        framed.extend_from_slice(udp_query);
        s.write_all(&framed).await?;
        let mut lbuf = [0u8; 2];
        s.read_exact(&mut lbuf).await?;
        let len = u16::from_be_bytes(lbuf) as usize;
        if len > 65_533 {
            anyhow::bail!("oversized dns reply");
        }
        let mut resp = vec![0u8; len];
        s.read_exact(&mut resp).await?;
        Ok(resp)
    };
    tokio::time::timeout(T, fut)
        .await
        .map_err(|_| anyhow!("dns exchange timeout"))?
}
