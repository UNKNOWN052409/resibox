//! Transparent per-container TCP forwarder ("the only egress door").
//!
//! Runs INSIDE each container's network namespace. iptables REDIRECTs every
//! app TCP connection to this listener; we recover the original destination
//! with SO_ORIGINAL_DST (netfilter conntrack) and relay the stream through
//! the container's ONE assigned residential proxy.
//!
//! Fail-closed: if the proxy is unreachable, connections simply fail —
//! nothing ever falls back to a direct route (which is firewalled anyway).

use crate::proxy::{connect_through, ProxyUrl};
use anyhow::Result;
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;

pub struct Forwarder {
    pub bind: String,
    pub proxy: Arc<ProxyUrl>,
}

impl Forwarder {
    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(&self.bind).await?;
        tracing::info!(bind = %self.bind, upstream = %self.proxy.host, "forwarder up");
        loop {
            let (down, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    tracing::debug!("accept err {e}");
                    continue;
                }
            };
            let proxy = self.proxy.clone();
            tokio::spawn(async move {
                match original_dst(&down) {
                    Some((host, port)) => {
                        if let Err(e) = relay(down, proxy, &host, port).await {
                            tracing::debug!(dst = %host, port, "relay closed: {e:#}");
                        }
                    }
                    None => {
                        // No conntrack entry => connection was NOT redirected by
                        // our rules (someone connected to us directly). Refuse:
                        // we never guess destinations.
                        tracing::warn!("connection without SO_ORIGINAL_DST; refusing");
                    }
                }
            });
        }
    }
}

async fn relay(
    mut down: tokio::net::TcpStream,
    proxy: Arc<ProxyUrl>,
    host: &str,
    port: u16,
) -> Result<()> {
    down.set_nodelay(true).ok();
    let mut up = connect_through(&proxy, host, port).await?;
    up.set_nodelay(true).ok();
    copy_bidirectional(&mut down, &mut up).await?;
    Ok(())
}

/// Read the pre-NAT destination address for a REDIRECTed socket.
#[cfg(target_os = "linux")]
fn original_dst(sock: &tokio::net::TcpStream) -> Option<(String, u16)> {
    use std::os::unix::io::AsRawFd;
    const SO_ORIGINAL_DST: i32 = 80;
    let fd = sock.as_raw_fd();
    unsafe {
        let mut addr: libc_sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc_sockaddr_in>() as u32;
        // getsockopt(fd, SOL_IP=0, SO_ORIGINAL_DST=80, ...)
        let rc = raw_getsockopt(fd, 0, SO_ORIGINAL_DST, &mut addr as *mut _ as *mut u8, &mut len);
        if rc != 0 {
            return None;
        }
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Some((ip.to_string(), port))
    }
}

#[repr(C)]
struct libc_sockaddr_in {
    sin_family: u16,
    sin_port: u16,
    sin_addr: sin_addr_raw,
    pad: [u8; 8],
}
#[repr(C)]
struct sin_addr_raw {
    s_addr: u32,
}

extern "C" {
    fn getsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *mut u8,
        optlen: *mut u32,
    ) -> i32;
}

#[inline]
fn raw_getsockopt(fd: i32, lvl: i32, name: i32, v: *mut u8, l: &mut u32) -> i32 {
    unsafe { getsockopt(fd, lvl, name, v, l) }
}

#[cfg(not(target_os = "linux"))]
fn original_dst(_sock: &tokio::net::TcpStream) -> Option<(String, u16)> {
    None
}
