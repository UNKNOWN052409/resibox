//! Pre-flight + periodic egress-identity verification.
//!
//! Guarantees implemented here:
//!  * observed IP must match the assigned policy (exact pin or country)
//!  * observed IP must NEVER equal the host/datacenter baseline (leak check)
//!  * any failure => Err => caller MUST keep the workload stopped

use crate::proxy::{connect_through, ProxyUrl};
use anyhow::{anyhow, bail, Context, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq)]
pub enum Policy {
    ExactIp(String),
    Country(String),
    AnyResidential,
}

impl Policy {
    pub fn from_cfg(expected_ip: &str, expected_country: &str) -> Self {
        if !expected_ip.trim().is_empty() {
            Policy::ExactIp(expected_ip.trim().to_string())
        } else if !expected_country.trim().is_empty() {
            Policy::Country(expected_country.trim().to_uppercase())
        } else {
            Policy::AnyResidential
        }
    }
    pub fn describe(&self) -> String {
        match self {
            Policy::ExactIp(ip) => format!("ip=={ip}"),
            Policy::Country(c) => format!("country=={c}"),
            Policy::AnyResidential => "any residential".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Observation {
    pub ip: String,
    pub country: Option<String>,
}

/// Fetch `url` through the proxy using a raw HTTP/1.1 GET over the tunnel.
pub async fn http_get_via_proxy(proxy: &ProxyUrl, url: &str, timeout: Duration) -> Result<String> {
    let (host, port, path) = split_url(url)?;
    let is_tls = port == 443 || url.starts_with("https://");
    if is_tls {
        // Avoid pulling a TLS stack into the runtime: prefer plain-HTTP geo/IP
        // endpoints (ip-api.com etc.). If an https URL is configured we refuse
        // loudly instead of silently weakening verification.
        bail!("verify_url must be plain http:// (resibox avoids a TLS dependency; ip-api/ipify serve plain http)");
    }
    let mut s = tokio::time::timeout(timeout, connect_through(proxy, &host, port))
        .await
        .map_err(|_| anyhow!("timeout connecting via proxy"))??;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: resibox/1.0\r\nConnection: close\r\n\r\n"
    );
    tokio::time::timeout(timeout, s.write_all(req.as_bytes())).await??;
    let mut buf = Vec::new();
    tokio::time::timeout(timeout, s.read_to_end(&mut buf)).await??;
    let text = String::from_utf8_lossy(&buf);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or(&text);
    Ok(body.to_string())
}

/// Direct (no-proxy) fetch — used ONLY to learn the host's datacenter baseline.
pub async fn http_get_direct(url: &str, timeout: Duration) -> Result<String> {
    let (host, port, path) = split_url(url)?;
    if url.starts_with("https://") {
        bail!("verify_direct_url must be plain http://");
    }
    let addr = crate::proxy::resolve_inline(&host, port)?;
    let mut s = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("timeout direct connect"))??;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: resibox/1.0\r\nConnection: close\r\n\r\n");
    tokio::time::timeout(timeout, s.write_all(req.as_bytes())).await??;
    let mut buf = Vec::new();
    tokio::time::timeout(timeout, s.read_to_end(&mut buf)).await??;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or(&text);
    Ok(body.to_string())
}

fn split_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("only http:// supported: {url}"))?;
    let (hp, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match hp.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().context("port in url")?),
        None => (hp.to_string(), 80),
    };
    Ok((host, port, path))
}

fn json_path<'a>(v: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = v;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

pub fn parse_observation(body: &str, ip_field: &str, country_field: &str) -> Result<Observation> {
    let v: serde_json::Value =
        serde_json::from_str(body).with_context(|| format!("bad json from verifier: {body:.120}"))?;
    let ip = json_path(&v, ip_field)
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("missing field '{ip_field}' in verifier response"))?
        .to_string();
    let country = json_path(&v, country_field)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());
    Ok(Observation { ip, country })
}

#[derive(Debug, Clone, PartialEq)]
pub enum VerifyOutcome {
    Pass { observed: Observation },
    Fail { reason: String },
}

/// Full pre-flight / watchdog check.
pub async fn verify(
    proxy: &ProxyUrl,
    policy: &Policy,
    host_baseline: &Option<Observation>,
    g: &crate::config::General,
) -> VerifyOutcome {
    // Residential gateways are flaky under load: retry transient failures
    // before declaring the endpoint dead.
    // Build endpoint table: explicit [[verify_endpoints]] first, then the
    // legacy single-url + extras with global field names.
    let mut eps: Vec<(String, String, String)> = g
        .verify_endpoints
        .iter()
        .map(|e| (e.url.clone(), e.ip_field.clone(), e.country_field.clone()))
        .collect();
    if !g.verify_url.is_empty() {
        eps.push((g.verify_url.clone(), g.verify_ip_field.clone(), g.verify_country_field.clone()));
    }
    for u in &g.verify_urls {
        eps.push((u.clone(), g.verify_ip_field.clone(), g.verify_country_field.clone()));
    }

    let mut parsed: Option<Observation> = None;
    let mut last_err = String::new();

    'outer: for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
        for (url, ipf, cf) in &eps {
            match http_get_via_proxy(proxy, url, Duration::from_secs(g.verify_timeout_override())).await {
                Ok(b) => {
                    if b.trim().is_empty() {
                        last_err = format!("empty response from {url}");
                        continue; // endpoint ratelimited us — try next
                    }
                    match parse_observation(&b, ipf, cf) {
                        Ok(o) => {
                            parsed = Some(o);
                            break 'outer;
                        }
                        Err(e) => last_err = format!("{url}: {e}"),
                    }
                }
                Err(e) => last_err = format!("{url}: {e}"),
            }
        }
    }
    let obs = match parsed {
        Some(o) => o,
        None => return VerifyOutcome::Fail { reason: format!("verifier failed: {last_err}") },
    };

    // Leak check FIRST: if we see the host's own IP something is catastrophically wrong.
    if let Some(base) = host_baseline {
        if base.ip == obs.ip {
            return VerifyOutcome::Fail {
                reason: format!(
                    "LEAK: traffic exiting via host/datacenter IP {} instead of assigned proxy",
                    obs.ip
                ),
            };
        }
    }

    let ok = match policy {
        Policy::ExactIp(want) => obs.ip == *want,
        Policy::Country(want) => obs
            .country
            .as_deref()
            .map(|c| c.eq_ignore_ascii_case(want))
            .unwrap_or(false),
        Policy::AnyResidential => true,
    };
    if !ok {
        VerifyOutcome::Fail {
            reason: format!(
                "egress identity mismatch: observed {} ({}) but policy requires {}",
                obs.ip,
                obs.country.clone().unwrap_or_default(),
                policy.describe()
            ),
        }
    } else {
        VerifyOutcome::Pass { observed: obs }
    }
}

impl crate::config::General {
    fn verify_timeout_override(&self) -> u64 {
        // Per-attempt timeout; residential gateways can be slow under load.
        25
    }
}
