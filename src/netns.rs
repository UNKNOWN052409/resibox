//! Root-mode network isolation: one netns + veth pair + iptables egress jail
//! per container. Inside the namespace the ONLY permitted paths are:
//!   TCP  -> REDIRECT to local forwarder -> assigned proxy
//!   UDP53-> REDIRECT to local DNS relay -> TCP DNS via assigned proxy
//!   everything else -> DROP (fail-closed)

use anyhow::{anyhow, Context, Result};
use tokio::process::Command;

pub struct NetNs {
    pub name: String,      // netns name, e.g. resibox-uk-a
    pub host_if: String,   // veth host end
    pub ns_if: String,     // veth ns end
    pub subnet: String,    // "10.213.<a>.0/30"
    pub host_ip: String,   // .1
    pub ns_ip: String,     // .2
    pub proxy_ips: Vec<String>, // resolved proxy gateway IPs (exempt path)
    pub proxy_port: u16,
}

fn sh(cmd: &str, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("spawn {cmd}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "{} {:?} failed: {}",
            cmd,
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Resolve proxy host on the HOST side; we exempt these IPs from redirection.
pub fn resolve_proxy_ips(host: &str) -> Result<Vec<String>> {
    use std::net::ToSocketAddrs;
    let addrs = (host, 0u16)
        .to_socket_addrs()
        .with_context(|| format!("resolve proxy host {host}"))?;
    let ips: Vec<String> = addrs
        .map(|a| a.ip().to_string())
        .take(4)
        .collect();
    if ips.is_empty() {
        return Err(anyhow!("proxy host {host} resolved to nothing"));
    }
    Ok(ips)
}

impl NetNs {
    /// Build the full jail for one container.
    pub async fn create(
        container: &str,
        index: u8,
        proxy_host: &str,
        proxy_port: u16,
        proxy_ips: &[String],
    ) -> Result<Self> {
        let a = 10u32 + index as u32; // 10.210+.x keeps us clear of docker defaults
        let name = format!("resibox-{container}");
        let host_if = format!("rb{index}h");
        let ns_if = format!("rb{index}n");
        let subnet = format!("10.{a}.1.0/30");
        let host_ip = format!("10.{a}.1.1");
        let ns_ip = format!("10.{a}.1.2");

        Self::destroy_stale(container).await;

        sh("ip", &["netns", "add", &name])?;
        if let Err(e) = self_setup(&name, &host_if, &ns_if, &subnet, &host_ip, &ns_ip, proxy_host, proxy_port, proxy_ips).await {
            // fail-closed: never leave a half-built jail around
            let _ = Command::new("ip").args(["netns", "del", &name]).output().await;
            return Err(e);
        }

        // Host-side masquerade so container traffic can reach the real network
        let _ = sh(
            "iptables",
            &[
                "-t", "nat", "-A", "POSTROUTING", "-s", &subnet, "!",
                "-d", &subnet, "-j", "MASQUERADE",
            ],
        )
        ;   /* host masquerade */

        Ok(Self {
            name,
            host_if,
            ns_if,
            subnet,
            host_ip,
            ns_ip,
            proxy_ips: proxy_ips.to_vec(),
            proxy_port,
        })
    }

    async fn destroy_stale(container: &str) {
        let name = format!("resibox-{container}");
        let _ = sh("ip", &["netns", "del", &name]);
    }

    /// The command prefix that runs anything inside this jail.
    pub fn exec_prefix(&self) -> Vec<String> {
        vec!["ip".into(), "netns".into(), "exec".into(), self.name.clone()]
    }

    /// Teardown: remove rules and the namespace.
    pub async fn destroy(&self) {
        let _ = sh(
            "iptables",
            &["-t", "nat", "-D", "POSTROUTING", "-s", &self.subnet, "!", "-d", &self.subnet, "-j", "MASQUERADE"],
        );
        let _ = sh("ip", &["netns", "del", &self.name]);
        tracing::info!(netns = %self.name, "jail destroyed");
    }
}

async fn self_setup(
    name: &str,
    host_if: &str,
    ns_if: &str,
    subnet: &str,
    host_ip: &str,
    ns_ip: &str,
    proxy_host: &str,
    _proxy_port: u16,
    proxy_ips: &[String],
) -> Result<()> {
    // Host side veth
    sh("ip", &["link", "add", host_if, "type", "veth", "peer", "name", ns_if])?;
    sh("ip", &["link", "set", ns_if, "netns", name])?;
    sh("ip", &["addr", "add", &format!("{host_ip}/30"), "dev", host_if])?;
    sh("ip", &["link", "set", host_if, "up"])?;
    // enable forwarding for this box once (idempotent-ish)
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1");

    // Namespace side
    sh("ip", &["netns", "exec", name, "ip", "link", "set", "lo", "up"])?;
    sh("ip", &["netns", "exec", name, "ip", "addr", "add", &format!("{ns_ip}/30"), "dev", ns_if])?;
    sh("ip", &["netns", "exec", name, "ip", "link", "set", ns_if, "up"])?;
    sh("ip", &[
        "netns", "exec", name, "ip", "route", "add", "default", "via", host_ip,
    ])?;

    // ---- Egress jail inside the namespace ---------------------------------
    // NAT: exempt the assigned proxy gateway(s), redirect EVERYTHING else.
    let n = format!("ip netns exec {name} iptables");
    for ip in proxy_ips {
        sh("ip", &["netns", "exec", name, "iptables", "-t", "nat",
            "-A", "OUTPUT", "-p", "tcp", "-d", ip, "-j", "RETURN"])?;
    }
    let _ = proxy_host; // domain handled by exemption list above
    sh("ip", &["netns", "exec", name, "iptables", "-t", "nat",
        "-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "18080"])?;
    sh("ip", &["netns", "exec", name, "iptables", "-t", "nat",
        "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"])?;

    // FILTER: default DROP; allow loopback, established, and proxy-gateway path only.
    sh("ip", &["netns", "exec", name, "iptables", "-P", "OUTPUT", "DROP"])?;
    sh("ip", &["netns", "exec", name, "iptables", "-A", "OUTPUT",
        "-o", "lo", "-j", "ACCEPT"])?;
    sh("ip", &["netns", "exec", name, "iptables", "-A", "OUTPUT",
        "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])?;
    for ip in proxy_ips {
        sh("ip", &["netns", "exec", name, "iptables", "-A", "OUTPUT",
            "-p", "tcp", "-d", ip, "-j", "ACCEPT"])?;
    }
    // (REDIRECTed packets hit -o lo as dst 127.0.0.1 and pass the lo rule.)

    tracing::info!(netns = %name, subnet = %subnet, "egress jail built");
    let _ = n;
    Ok(())
}
