//! resibox — Rust-based isolated residential-IP container runtime.
//!
//! One container -> one assigned residential proxy -> one isolated egress path.
//! Honeygain + Pawns.app run inside each jail. Fail-closed by construction.

use anyhow::{Context, Result};
use resibox::{config, container, health, verify};
use std::sync::Arc;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();

    // Inner mode: forwarder+dns inside a netns (spawned by the supervisor).
    if args.first().map(|s| s.as_str()) == Some("__inner") || args.get(1).map(|s| s.as_str()) == Some("__inner") {
        return inner_main(&args).await;
    }

    let cfg_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "config.toml".to_string());
    let cfg = Arc::new(config::load(&cfg_path).context("config load")?);
    let g = Arc::new(cfg.general.clone());

    if cfg.container.is_empty() {
        anyhow::bail!("no [[container]] defined in {cfg_path}");
    }

    let mode = container::effective_mode(&g);
    tracing::info!(
        containers = cfg.container.len(),
        enforcement = ?mode,
        "resibox starting — one container, one proxy, zero fallback"
    );

    let baseline = verify::http_get_direct(
        &g.verify_direct_url,
        std::time::Duration::from_secs(15),
    )
    .await
    .ok()
    .and_then(|body| {
        verify::parse_observation(&body, &g.verify_ip_field, &g.verify_country_field).ok()
    });
    if let Some(b) = &baseline {
        tracing::info!(ip = %b.ip, "host datacenter baseline (leak detector armed)");
    } else {
        tracing::warn!("could not learn host baseline; leak check disabled this session");
    }

    let mut states = Vec::new();
    for c in &cfg.container {
        states.push(Arc::new(container::ContainerState::new(c.clone())));
    }
    let states = Arc::new(states);

    // Health endpoint (optional).
    let hport = g.health_port;
    if hport > 0 {
        let s = states.clone();
        tokio::spawn(async move {
            if let Err(e) = health::serve(hport, s).await {
                tracing::error!("health server died: {e:#}");
            }
        });
    }

    // One supervisor task per container, staggered so N containers never
    // hammer verification endpoints / proxy gateways simultaneously.
    let mut tasks = Vec::new();
    let stagger = g.startup_stagger_secs;
    for (i, st) in states.iter().enumerate() {
        let st = st.clone();
        let g = g.clone();
        let baseline_c = baseline.clone();
        tasks.push(tokio::spawn(async move {
            if i > 0 && stagger > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(stagger)).await;
            }
            container::run_container(st, g, baseline_c).await;
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

async fn inner_main(args: &[String]) -> Result<()> {
    // args like: resibox __inner --bind 127.0.0.1:18080 --dns-bind 127.0.0.1:5353 --proxy socks5://... --resolvers a,b
    let get = |flag: &str| -> Option<String> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let bind = get("--bind").unwrap_or_else(|| "127.0.0.1:18080".into());
    let dns_bind = get("--dns-bind").unwrap_or_else(|| "127.0.0.1:5353".into());
    let proxy = get("--proxy").context("--proxy required in __inner mode")?;
    let resolvers: Vec<String> = get("--resolvers")
        .unwrap_or_else(|| "9.9.9.9:53,1.1.1.1:53".into())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    container::run_inner(bind, dns_bind, proxy, resolvers).await
}
