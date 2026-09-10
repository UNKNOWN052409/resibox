//! Integration tests for resibox core guarantees — fully offline.
//!
//! Mock topology:
//!   resibox verifier --(socks5)--> mock proxy --tcp--> local JSON endpoint
//!
//! Proven here:
//!  1. SOCKS5 tunnel relays traffic (forwarder primitive)
//!  2. Pre-flight PASS starts the workload (userspace mode)
//!  3. Pre-flight FAIL (wrong country) keeps it stopped
//!  4. Watchdog kills the workload and BLOCKS when the proxy dies (fail-closed)

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Minimal SOCKS5 server (no-auth) that tunnels to real targets.
async fn spawn_mock_socks5() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { continue };
            tokio::spawn(async move {
                let mut hdr = [0u8; 2];
                if s.read_exact(&mut hdr).await.is_err() { return; }
                let n = hdr[1] as usize;
                let mut methods = vec![0u8; n];
                if s.read_exact(&mut methods).await.is_err() { return; }
                let _ = s.write_all(&[5, 0]).await;
                let mut head = [0u8; 4];
                if s.read_exact(&mut head).await.is_err() { return; }
                let target = match head.get(3).copied().unwrap_or(3) {
                    3 => {
                        let mut lb = [0u8; 1];
                        s.read_exact(&mut lb).await.unwrap();
                        let mut dom = vec![0u8; lb[0] as usize];
                        s.read_exact(&mut dom).await.unwrap();
                        String::from_utf8(dom).unwrap()
                    }
                    1 => {
                        let mut ipb = [0u8; 4];
                        s.read_exact(&mut ipb).await.unwrap();
                        std::net::Ipv4Addr::from(ipb).to_string()
                    }
                    _ => return,
                };
                let mut pb = [0u8; 2];
                s.read_exact(&mut pb).await.unwrap();
                let port_n = u16::from_be_bytes(pb);
                match TcpStream::connect((target.as_str(), port_n)).await {
                    Ok(mut up) => {
                        let _ = s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                        let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                    }
                    Err(_) => {
                        let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                    }
                }
            });
        }
    });
    port
}

/// HTTP JSON server returning {"query": ip, "countryCode": cc} with a kill switch.
struct JsonServer {
    port: u16,
    dead: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

async fn spawn_json_server(ip: &'static str, cc: &'static str) -> JsonServer {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let dead = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let d2 = dead.clone();
    tokio::spawn(async move {
        loop {
            if d2.load(std::sync::atomic::Ordering::Relaxed) { return; }
            let Ok((mut s, _)) = l.accept().await else { continue };
            let body = format!(r#"{{"query":"{ip}","countryCode":"{cc}"}}"#);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await;
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    JsonServer { port, dead }
}

// ---------------------------------------------------------------- unit-ish

#[test]
fn parse_proxy_variants() {
    use resibox::proxy::parse_proxy;
    let p = parse_proxy("socks5://u:p%40ss@gw.example.com:1080").unwrap();
    assert_eq!(p.host, "gw.example.com");
    assert_eq!(p.port, 1080);
    assert_eq!(p.user.as_deref(), Some("u"));
    assert_eq!(p.pass.as_deref(), Some("p@ss"));

    let p = parse_proxy("http://gw2.example.com:8080").unwrap();
    assert_eq!(p.port, 8080);
    assert!(p.user.is_none());

    assert!(parse_proxy("ftp://x").is_err());
}

#[tokio::test]
async fn socks_tunnel_relays_http() {
    let js = spawn_json_server("203.0.113.7", "GB").await;
    let socks_port = spawn_mock_socks5().await;

    let proxy = resibox::proxy::parse_proxy(&format!("socks5://127.0.0.1:{socks_port}")).unwrap();
    let body = resibox::verify::http_get_via_proxy(
        &proxy,
        &format!("http://127.0.0.1:{}/json", js.port),
        Duration::from_secs(5),
    )
    .await
    .expect("fetch via mock socks5");
    assert!(body.contains("203.0.113.7"), "body={body}");
}

#[test]
fn verifier_policy_matrix() {
    use resibox::verify::{parse_observation, Policy};
    let obs = parse_observation(
        r#"{"query":"198.51.100.9","countryCode":"FR"}"#,
        "query",
        "countryCode",
    )
    .unwrap();
    assert_eq!(obs.ip, "198.51.100.9");
    assert_eq!(obs.country.as_deref(), Some("FR"));
    assert_eq!(Policy::from_cfg("", "fr"), Policy::Country("FR".into()));
    assert_eq!(
        Policy::from_cfg("1.2.3.4", ""),
        Policy::ExactIp("1.2.3.4".into())
    );
}


/// Kills the resibox child on drop (even when an assert panics) so cargo test
/// never hangs waiting for inherited stdio pipes.
struct KillGuard(tokio::process::Child);
impl Drop for KillGuard {
    fn drop(&mut self) {
        use tokio::process::Child;
        let _ = self.0.start_kill();
    }
}

// ------------------------------------------------------------- e2e binary

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_preflight_pass_starts_failclosed_kills() {
    // Egress seen THROUGH the proxy vs the HOST's real (datacenter) baseline
    // must differ — otherwise the built-in leak detector blocks (by design).
    let js = spawn_json_server("203.0.113.7", "GB").await;        // via proxy: UK residential
    let base = spawn_json_server("198.51.100.1", "US").await;     // direct: host DC ip
    let socks = spawn_mock_socks5().await;
    let health = free_port();

    let dir = std::env::temp_dir().join(format!("resibox-t-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("good.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
[general]
health_port = {health}
verify_interval_secs = 3
verify_url = "http://127.0.0.1:{v}/json"
verify_direct_url = "http://127.0.0.1:{d}/json"
enforcement = "userspace"
max_consecutive_failures = 1

[[container]]
name = "uk-test"
proxy = "socks5://127.0.0.1:{s}"
expected_country = "GB"
hg_cmd = ["sleep", "600"]
pawns_cmd = []
"#,
            v = js.port,
            d = base.port,
            s = socks
        ),
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_resibox");
    let mut child = tokio::process::Command::new(bin)
        .arg(&cfg_path)
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();
    let mut child = KillGuard(child);

    let ok = poll_health(health, |j| j["details"][0]["state"] == "Running", 20_000).await;
    assert!(ok, "never reached Running; health: {}", get_health(health).await);

    // Verification path dies -> watchdog must fail-closed.
    js.dead.store(true, std::sync::atomic::Ordering::Relaxed);
    let ok = poll_health(
        health,
        |j| j["details"][0]["state"] == "Blocked" || j["details"][0]["state"] == "Isolated",
        30_000,
    )
    .await;
    assert!(ok, "watchdog failed to fail-close; health: {}", get_health(health).await);

    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_preflight_wrong_country_never_starts() {
    let js = spawn_json_server("203.0.113.99", "US").await;
    let socks = spawn_mock_socks5().await;
    let health = free_port();

    let dir = std::env::temp_dir().join(format!("resibox-t2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("bad.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
[general]
health_port = {health}
verify_interval_secs = 3
verify_url = "http://127.0.0.1:{v}/json"
verify_direct_url = "http://127.0.0.1:{d}/json"
enforcement = "userspace"

[[container]]
name = "uk-must-not-start"
proxy = "socks5://127.0.0.1:{s}"
expected_country = "GB"
hg_cmd = ["sleep", "600"]
pawns_cmd = []
"#,
            v = js.port,
            d = js.port,
            s = socks
        ),
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_resibox");
    let mut child = tokio::process::Command::new(bin)
        .arg(&cfg_path)
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();
    let mut _child = KillGuard(child);

    let blocked =
        poll_health(health, |j| j["details"][0]["state"] == "Blocked", 15_000).await;
    assert!(blocked, "expected Blocked state");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let h = get_health(health).await;
    let j: serde_json::Value = serde_json::from_str(&h).unwrap();
    assert_eq!(j["running"], 0, "workload must NOT run after failed preflight: {h}");

    drop(_child);
    let _ = std::fs::remove_dir_all(&dir);
}

async fn get_health(port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let Some(mut s) = tokio::net::TcpStream::connect(&addr).await.ok() else {
        return String::new();
    };
    let _ = s
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default()
}

async fn poll_health(port: u16, pred: impl Fn(&serde_json::Value) -> bool, ms: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_millis(ms);
    while std::time::Instant::now() < deadline {
        let txt = get_health(port).await;
        if let Ok(j) = serde_json::from_str::<serde_json::Value>(&txt) {
            if !j["details"].as_array().map(|a| a.is_empty()).unwrap_or(true) && pred(&j) {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    false
}
