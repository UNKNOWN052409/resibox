//! /health endpoint — per-container states, observed IPs, isolation summary.

use crate::container::{ContainerState, State};
use std::sync::Arc;
use std::time::Instant;

pub async fn serve(port: u16, containers: Arc<Vec<Arc<ContainerState>>>) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!(port, "health endpoint up");
    let start = Instant::now();
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let cs = containers.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let body = render(&cs);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
        let _ = start; // uptime available if needed later
    }
}

fn state_str(s: &State) -> &'static str {
    match s {
        State::Preflight => "Preflight",
        State::Running => "Running",
        State::Isolated => "Isolated",
        State::Blocked => "Blocked",
        State::Rotating => "Rotating",
    }
}

pub fn render(cs: &Arc<Vec<Arc<ContainerState>>>) -> String {
    // Synchronous snapshot — Mutexes are short-held; block briefly.
    let mut details = Vec::new();
    let (mut running, mut blocked) = (0usize, 0usize);
    for c in cs.iter() {
        let st = c.state.lock().unwrap();
        let ip = c.observed_ip.lock().unwrap().clone();
        let country = c.observed_country.lock().unwrap().clone();
        let failures = *c.failures.lock().unwrap();
        let rotations = *c.rotations.lock().unwrap();
        let last = c.last_error.lock().unwrap().clone();
        let mode = c.enforcement_used.lock().unwrap().clone();
        let s = state_str(&st);
        if *st == State::Running { running += 1; }
        if matches!(*st, State::Blocked | State::Isolated) { blocked += 1; }
        details.push(serde_json::json!({
            "name": c.cfg.name,
            "state": s,
            "observed_ip": ip,
            "country": country,
            "enforcement": mode,
            "failures": failures,
            "rotations": rotations,
            "last_error": last,
        }));
    }
    let total = details.len();
    let unique_ips: std::collections::HashSet<_> =
        details.iter().filter_map(|d| d["observed_ip"].as_str()).collect();
    let isolation = if total > 0 && running == total && unique_ips.len() == running {
        "100%"
    } else {
        "degraded"
    };
    serde_json::json!({
        "status": if blocked == 0 { "ok" } else { "fail-closed" },
        "containers": total,
        "running": running,
        "blocked_or_isolated": blocked,
        "unique_egress_ips": unique_ips.len(),
        "ip_isolation": isolation,
        "details": details,
    })
    .to_string()
}
