//! Container lifecycle: PRE-FLIGHT -> START -> WATCHDOG -> FAIL-CLOSED.
//!
//! State machine per container:
//!   Preflight -> (pass)  Running  -> watchdog pass -> stay Running
//!   Preflight -> (fail)  Blocked  (apps NEVER start)
//!   Running   -> (watchdog fail) Isolated: apps killed instantly
//!             -> revalidate proxy -> pass => resume; fail => Blocked
//!   Endpoint confirmed dead + replacements configured => authorized rotation,
//!   then FULL re-preflight before any app restarts.

use crate::config::{ContainerCfg, Enforcement, General};
use crate::netns::NetNs;
use crate::proxy::{parse_proxy, ProxyUrl};
use crate::verify::{http_get_direct, parse_observation, verify, Observation, Policy, VerifyOutcome};
use anyhow::{anyhow, Context, Result};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::process::Child;

#[derive(Debug, Clone, PartialEq)]
pub enum State {
    Preflight,
    Running,
    Isolated, // apps killed, revalidating
    Blocked,  // fail-closed, nothing running
    Rotating, // authorized endpoint replacement in progress
}

pub struct ContainerState {
    pub cfg: ContainerCfg,
    pub state: Mutex<State>,
    pub observed_ip: Mutex<Option<String>>,
    pub observed_country: Mutex<Option<String>>,
    pub failures: Mutex<u32>,
    pub rotations: Mutex<u32>,
    pub last_error: Mutex<String>,
    pub enforcement_used: Mutex<String>,
    pub overuse_hits: Mutex<u32>,
    pub device_conflict: Mutex<bool>,
}

struct Procs {
    hg: Option<Child>,
    pawns: Option<Child>,
    inner_fwd: Option<Child>, // forwarder+dns process inside netns
    netns: Option<NetNs>,
}

impl ContainerState {
    pub fn new(cfg: ContainerCfg) -> Self {
        Self {
            cfg,
            state: Mutex::new(State::Preflight),
            observed_ip: Mutex::new(None),
            observed_country: Mutex::new(None),
            failures: Mutex::new(0),
            rotations: Mutex::new(0),
            last_error: Mutex::new(String::new()),
            enforcement_used: Mutex::new(String::new()),
            overuse_hits: Mutex::new(0),
            device_conflict: Mutex::new(false),
        }
    }

    fn set_sync(&self, s: State) {
        *self.state.lock().unwrap() = s.clone();
        tracing::info!(container = %self.cfg.name, state = ?s, "state ->");
    }
}

/// Decide enforcement mode for this box.
pub fn effective_mode(g: &General) -> Enforcement {
    match g.enforcement {
        Enforcement::Netns => Enforcement::Netns,
        Enforcement::Userspace => Enforcement::Userspace,
        Enforcement::Auto => {
            if is_root() && which_ok("ip") && which_ok("iptables") {
                Enforcement::Netns
            } else {
                Enforcement::Userspace
            }
        }
    }
}

fn is_root() -> bool { nix_uid() == Some(0) }
fn nix_uid() -> Option<u32> {
    // no libc crate: read /proc
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(|x| x.to_string()))
        })
        .and_then(|x| x.parse().ok())
}
fn which_ok(bin: &str) -> bool {
    std::env::var("PATH").unwrap_or_default().split(':').any(|d| {
        let p = std::path::Path::new(d).join(bin);
        p.exists()
    }) || std::path::Path::new("/usr/sbin").join(bin).exists()
}

async fn host_baseline(g: &General) -> Result<Option<Observation>> {
    let body = http_get_direct(&g.verify_direct_url, Duration::from_secs(15)).await?;
    let obs = parse_observation(&body, &g.verify_ip_field, &g.verify_country_field)?;
    tracing::info!(ip = %obs.ip, "host datacenter baseline learned");
    Ok(Some(obs))
}

/// Main loop for one container.
pub async fn run_container(cs: Arc<ContainerState>, g: Arc<General>, baseline: Option<Observation>) {
    let mut procs = Procs { hg: None, pawns: None, inner_fwd: None, netns: None };
    let mode = effective_mode(&g);
    *cs.enforcement_used.lock().unwrap() =
        match mode { Enforcement::Netns => "netns".into(), _ => "userspace".into() };

    // Current active proxy slot (index into [primary]+replacements).
    let endpoints: Arc<Mutex<Vec<Endpoint>>> = Arc::new(Mutex::new(vec![]));

    'outer: loop {
        // ---- gather current candidate endpoint ----------------------------
        let ep = {
            let list = endpoints.lock().unwrap();
            list.first().cloned()
        };
        let ep = match ep {
            Some(e) => e,
            None => {
                // first run / after exhausting replacements: rebuild from config
                let mut list = vec![Endpoint {
                    url: cs.cfg.proxy.clone(),
                    policy: Policy::from_cfg(&cs.cfg.expected_ip, &cs.cfg.expected_country),
                }];
                for r in &cs.cfg.replacement {
                    list.push(Endpoint {
                        url: r.proxy.clone(),
                        policy: Policy::from_cfg(&r.expected_ip, &r.expected_country),
                    });
                }
                let e = list.remove(0);
                *endpoints.lock().unwrap() = list;
                e
            }
        };

        let proxy = match parse_proxy(&ep.url) {
            Ok(p) => Arc::new(p),
            Err(e) => {
                hard_block(&cs, &mut procs, format!("bad proxy url: {e:#}")).await;
                sleep_backoff(g.verify_interval_secs).await;
                continue;
            }
        };

        // ---- build netns jail (root mode) ---------------------------------
        if mode == Enforcement::Netns {
            match build_jail(&cs, &proxy).await {
                Ok(ns) => {
                    // spawn inner forwarder + dns relay inside the jail
                    match spawn_inner(&ns, &proxy, g.dns_resolvers.clone()).await {
                        Ok(child) => procs.inner_fwd = Some(child),
                        Err(e) => {
                            hard_block(&cs, &mut procs, format!("inner services failed: {e:#}")).await;
                            if let Some(n) = procs.netns.take() { n.destroy().await; }
                            sleep_backoff(g.verify_interval_secs).await;
                            continue;
                        }
                    }
                    procs.netns = Some(ns);
                }
                Err(e) => {
                    hard_block(&cs, &mut procs, format!("netns jail build failed: {e:#}")).await;
                    sleep_backoff(g.verify_interval_secs).await;
                    continue;
                }
            }
        }

        // ---- PRE-FLIGHT: apps must not exist yet --------------------------
        cs.set_sync(State::Preflight);
        kill_apps(&mut procs).await;
        match verify(&proxy, &ep.policy, &baseline, &g).await {
            VerifyOutcome::Pass { observed } => {
                *cs.overuse_hits.lock().unwrap() = 0;
                *cs.device_conflict.lock().unwrap() = false;
                *cs.observed_ip.lock().unwrap() = Some(observed.ip.clone());
                *cs.observed_country.lock().unwrap() = observed.country.clone();
                *cs.last_error.lock().unwrap() = String::new();
                *cs.failures.lock().unwrap() = 0;
                tracing::info!(container = %cs.cfg.name, ip = %observed.ip,
                               "PRE-FLIGHT PASS — starting honeygain + pawns");
            }
            VerifyOutcome::Fail { reason } => {
                *cs.failures.lock().unwrap() += 1;
                *cs.last_error.lock().unwrap() = reason.clone();
                tracing::error!(container = %cs.cfg.name, %reason, "PRE-FLIGHT FAIL — workload stays STOPPED");

                if should_rotate(&cs, &reason).await {
                    if rotate_authorized(&cs, &endpoints).await {
                        teardown(&mut procs).await;
                        cs.set_sync(State::Rotating);
                        continue 'outer;
                    }
                }
                teardown(&mut procs).await;
                hard_block(&cs, &mut procs, reason).await;
                sleep_backoff(g.verify_interval_secs).await;
                continue;
            }
        }

        // ---- START workloads ----------------------------------------------
        match spawn_apps(&cs, &procs, mode == Enforcement::Netns).await {
            Ok((hg, pb)) => {
                procs.hg = hg;
                procs.pawns = pb;
                cs.set_sync(State::Running);
            }
            Err(e) => {
                hard_block(&cs, &mut procs, format!("spawn failed: {e:#}")).await;
                sleep_backoff(g.verify_interval_secs).await;
                continue;
            }
        }

        // ---- WATCHDOG ------------------------------------------------------
        // Sleep is split into keep-alive chunks: each tiny request goes out
        // through the SAME sticky url, holding the exit-IP binding warm so
        // the provider keeps handing us the same residential IP.
        loop {
            {
                let ka = g.keepalive_secs.clamp(5, 300);
                let total = g.verify_interval_secs.max(ka);
                let mut slept = 0u64;
                while slept < total {
                    let chunk = ka.min(total - slept);
                    tokio::time::sleep(Duration::from_secs(chunk)).await;
                    slept += chunk;
                    let _ = crate::verify::http_get_via_proxy(
                        &proxy,
                        &g.keepalive_url,
                        Duration::from_secs(8),
                    )
                    .await;
                }
            }

            // DEVICE CONFLICT: old session still registered server-side.
            // Rotate to a persisted-but-fresh device id and recycle.
            if *cs.device_conflict.lock().unwrap() {
                let new_id = next_device_id(&cs.cfg.name);
                tracing::warn!(container = %cs.cfg.name, %new_id,
                               "rotating device id after conflict");
                *cs.overuse_hits.lock().unwrap() = 0;
                teardown(&mut procs).await;
                // brief cool-off lets the server release the old session
                tokio::time::sleep(Duration::from_secs(20)).await;
                continue 'outer;
            }

            // PROVIDER SIGNAL: too many "Network Overused" hits => this
            // sticky endpoint has gone sour. Rotate to a FRESH session IP
            // (authorized by provider behavior), then FULL preflight again.
            if *cs.overuse_hits.lock().unwrap() >= g.overuse_rotate_threshold {
                if let Some(new_url) = rotate_sticky(&ep.url) {
                    tracing::warn!(container = %cs.cfg.name,
                                   "OVERUSE ROTATION: switching to fresh sticky session");
                    endpoints.lock().unwrap().insert(0, Endpoint {
                        url: new_url,
                        policy: ep.policy.clone(),
                    });
                    *cs.overuse_hits.lock().unwrap() = 0;
                    *cs.rotations.lock().unwrap() += 1;
                    teardown(&mut procs).await;
                    cs.set_sync(State::Rotating);
                    continue 'outer;
                }
            }

            // If both children died on their own, restart via outer preflight.
            let hg_alive = procs.hg.as_mut().map(|c| {
                let st = c.try_wait().ok().flatten();
                if let Some(st) = &st {
                    tracing::warn!(container = %cs.cfg.name, app="honeygain", ?st, "child exited");
                }
                st.is_none()
            });
            let pb_alive = procs.pawns.as_mut().map(|c| {
                let st = c.try_wait().ok().flatten();
                if let Some(st) = &st {
                    tracing::warn!(container = %cs.cfg.name, app="pawns", ?st, "child exited");
                }
                st.is_none()
            });

            match verify(&proxy, &ep.policy, &baseline, &g).await {
                VerifyOutcome::Pass { observed } => {
                    *cs.failures.lock().unwrap() = 0;
                    *cs.observed_ip.lock().unwrap() = Some(observed.ip);
                    *cs.last_error.lock().unwrap() = String::new();

                    // auto-restart crashed workloads through full preflight
                    if hg_alive == Some(false) || pb_alive == Some(false) {
                        tracing::warn!(container = %cs.cfg.name, "app exited; recycling through preflight");
                        teardown(&mut procs).await;
                        continue 'outer;
                    }
                }
                VerifyOutcome::Fail { reason } => {
                    *cs.failures.lock().unwrap() += 1;
                    *cs.last_error.lock().unwrap() = reason.clone();
                    let fails = *cs.failures.lock().unwrap();
                    tracing::error!(container = %cs.cfg.name, %reason, fails, "WATCHDOG FAIL — killing traffic");

                    // FAIL-CLOSED FIRST. Always. Before any retry logic.
                    kill_apps(&mut procs).await;
                    cs.set_sync(State::Isolated);

                    if fails >= g.max_consecutive_failures && should_rotate(&cs, &reason).await {
                        if rotate_authorized(&cs, &endpoints).await {
                            teardown(&mut procs).await;
                            cs.set_sync(State::Rotating);
                            continue 'outer;
                        }
                    }

                    // Revalidate same endpoint; resume ONLY after a clean pass.
                    match verify(&proxy, &ep.policy, &baseline, &g).await {
                        VerifyOutcome::Pass { observed } => {
                            tracing::info!(container = %cs.cfg.name, ip = %observed.ip, "revalidated — resuming");
                            match spawn_apps(&cs, &procs, mode == Enforcement::Netns).await {
                                Ok((hg, pb)) => {
                                    procs.hg = hg;
                                    procs.pawns = pb;
                                    cs.set_sync(State::Running);
                                }
                                Err(e) => {
                                    hard_block(&cs, &mut procs, format!("respawn failed: {e:#}")).await;
                                    continue 'outer;
                                }
                            }
                        }
                        VerifyOutcome::Fail { reason } => {
                            *cs.last_error.lock().unwrap() = reason.clone();
                            hard_block(&cs, &mut procs, reason).await;
                            continue 'outer;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
struct Endpoint {
    url: String,
    policy: Policy,
}

fn sleep_backoff(secs: u64) -> impl std::future::Future<Output = ()> {
    tokio::time::sleep(Duration::from_secs(secs.max(5)))
}

/// Rotate only when the failure indicates the ENDPOINT itself is dead/invalid —
/// never on transient geo mismatches alone.
async fn should_rotate(_cs: &Arc<ContainerState>, reason: &str) -> bool {
    let r = reason.to_lowercase();
    r.contains("unreachable")
        || r.contains("timeout")
        || r.contains("auth rejected")
        || r.contains("connect failed")
        || r.contains("refused method")
        || r.contains("closed during connect")
}

/// Advance to next authorized replacement (if any). Returns true on rotation.
async fn rotate_authorized(
    cs: &Arc<ContainerState>,
    endpoints: &Arc<Mutex<Vec<Endpoint>>>,
) -> bool {
    let mut list = endpoints.lock().unwrap();
    if list.is_empty() {
        tracing::warn!(container = %cs.cfg.name, "endpoint invalid but NO authorized replacement configured — staying blocked (fail-closed)");
        return false;
    }
    let next = list.remove(0);
    {
        let mut r = cs.rotations.lock().unwrap();
        *r += 1;
        tracing::warn!(container = %cs.cfg.name, rotations = *r,
                       "AUTHORIZED ROTATION to new endpoint (full re-preflight required)");
    }
    list.insert(0, next); // becomes the active one on next loop iteration
    true
}

async fn build_jail(cs: &Arc<ContainerState>, proxy: &ProxyUrl) -> Result<NetNs> {
    let idx = cs_index(&cs.cfg.name);
    let ips = crate::netns::resolve_proxy_ips(&proxy.host)?;
    NetNs::create(&cs.cfg.name, idx, &proxy.host, proxy.port, &ips).await
}

fn device_state_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    std::path::Path::new(&dir).join(".resibox-devices")
}

/// Stable per-container device suffix, persisted across restarts.
/// Regenerated ONLY when the provider reports a device-name conflict.
fn current_device_suffix(name: &str) -> String {
    let dir = device_state_path(name);
    let _ = std::fs::create_dir_all(&dir);
    let f = dir.join(format!("{name}.id"));
    if let Ok(id) = std::fs::read_to_string(&f) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }
    next_device_id(name)
}

fn next_device_id(name: &str) -> String {
    let id = crate::config::nanoid6();
    let dir = device_state_path(name);
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join(format!("{name}.id")), &id);
    id
}

/// Swap the sticky-session id inside a proxy URL: host stays, exit IP changes.
/// e.g. "...res-gb-sid-483920164:..." -> "...res-gb-sid-<fresh-random>:..."
fn rotate_sticky(url: &str) -> Option<String> {
    let marker = "sid-";
    let pos = url.find(marker)?;
    let start = pos + marker.len();
    let rest = &url[start..];
    let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits < 4 {
        return None; // not a sticky-session style URL; no authorized rotation
    }
    use rand::Rng;
    let fresh: u32 = rand::thread_rng().gen_range(100000000..999999999u32);
    Some(format!("{}{}{}", &url[..start], fresh, &url[start + digits..]))
}

fn cs_index(name: &str) -> u8 {
    // stable small index from name for subnet allocation
    let h = name.bytes().fold(7u8, |a, b| a.wrapping_mul(31).wrapping_add(b));
    h % 100
}

async fn spawn_inner(ns: &NetNs, proxy: &ProxyUrl, resolvers: Vec<String>) -> Result<Child> {
    let exe = std::env::current_exe()?;
    let prefix = ns.exec_prefix();
    let mut cmd = tokio::process::Command::new(&prefix[0]);
    cmd.args(&prefix[1..])
        .arg(exe)
        .args([
            "__inner",
            "--bind",
            "127.0.0.1:18080",
            "--dns-bind",
            "127.0.0.1:5353",
            "--proxy",
            &format!("{}://{}", proto_of(proxy), sockstr(proxy)),
        ])
        .args(["--resolvers", &resolvers.join(",")])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    let child = cmd.spawn().context("spawn inner forwarder in netns")?;
    Ok(child)
}

fn proto_of(p: &ProxyUrl) -> &'static str {
    match p.kind { crate::proxy::ProxyType::Socks5 => "socks5", _ => "http" }
}
fn sockstr(p: &ProxyUrl) -> String {
    let auth = match (&p.user, &p.pass) {
        (Some(u), Some(pw)) => format!("{u}:{pw}@"),
        (Some(u), None) => format!("{u}@"),
        _ => String::new(),
    };
    format!("{auth}{}:{}", p.host, p.port)
}

async fn spawn_apps(
    cs: &Arc<ContainerState>,
    procs: &Procs,
    inside_netns: bool,
) -> Result<(Option<Child>, Option<Child>)> {
    let wrap = |argv: &[String]| -> tokio::process::Command {
        let mut c = if inside_netns {
            let prefix = procs.netns.as_ref().unwrap().exec_prefix();
            let mut c = tokio::process::Command::new(&prefix[0]);
            c.args(&prefix[1..]);
            c
        } else {
            // userspace mode: best-effort env forcing (verification still guards us)
            let mut c = tokio::process::Command::new(&argv[0]);
            c.env("ALL_PROXY", all_proxy_env(cs));
            c.env("all_proxy", all_proxy_env(cs));
            c
        };
        c.args(argv[1..].iter())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        c
    };

    // Ensure unique-per-container, restart-stable device identities.
    let mut hg_argv = cs.cfg.hg_argv();
    apply_device_identity(cs, &mut hg_argv, true);
    let mut pb_argv = cs.cfg.pawns_argv();
    apply_device_identity(cs, &mut pb_argv, false);

    let mut hg = if !hg_argv.is_empty() {
        Some(wrap(&hg_argv).spawn().context("spawn honeygain")?)
    } else {
        None
    };
    let mut pb = if !pb_argv.is_empty() {
        Some(wrap(&pb_argv).spawn().context("spawn pawns-cli")?)
    } else {
        None
    };

    // Drain app output: log every line + watch for provider overuse signals.
    if let Some(ch) = hg.as_mut() {
        if let Some(out) = ch.stdout.take() {
            tokio::spawn(scan_output(cs.clone(), "honeygain", out));
        }
        if let Some(err) = ch.stderr.take() {
            tokio::spawn(scan_output(cs.clone(), "honeygain-stderr", err));
        }
    }
    if let Some(ch) = pb.as_mut() {
        if let Some(out) = ch.stdout.take() {
            tokio::spawn(scan_output(cs.clone(), "pawns", out));
        }
        if let Some(err) = ch.stderr.take() {
            tokio::spawn(scan_output(cs.clone(), "pawns-stderr", err));
        }
    }
    Ok((hg, pb))
}

/// Stream an app's output into our log; count provider overuse signals.
async fn scan_output(cs: Arc<ContainerState>, tag: &str, stream: impl tokio::io::AsyncRead + Unpin) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                tracing::info!(container = %cs.cfg.name, app = tag, "{}", line);
                let lower = line.to_lowercase();
                if lower.contains("choose a different device name") {
                    *cs.device_conflict.lock().unwrap() = true;
                    tracing::warn!(container = %cs.cfg.name,
                                   "DEVICE CONFLICT: server still holds old session; will rotate device id");
                }
                if lower.contains("overused") {
                    *cs.overuse_hits.lock().unwrap() += 1;
                    tracing::warn!(container = %cs.cfg.name,
                                   hits = *cs.overuse_hits.lock().unwrap(),
                                   "PROVIDER SIGNAL: network overused");
                }
                if lower.contains("connected") && lower.contains("running") {
                    *cs.overuse_hits.lock().unwrap() = 0;
                }
            }
            _ => break,
        }
    }
}

fn all_proxy_env(cs: &Arc<ContainerState>) -> String { cs.cfg.proxy.clone() }

/// Rewrite -device/-device-name args to include the container's stable id.
/// If a conflict was flagged, force a fresh id first.
fn apply_device_identity(cs: &Arc<ContainerState>, argv: &mut [String], honeygain: bool) {
    let base = if honeygain { &cs.cfg.honeygain_device } else { &cs.cfg.pawns_device_name };
    let base = if base.is_empty() {
        format!("{}-{}", cs.cfg.name, if honeygain { "hg" } else { "pb" })
    } else {
        base.clone()
    };
    if *cs.device_conflict.lock().unwrap() {
        let fresh = next_device_id(&cs.cfg.name);
        let full = format!("{base}-{fresh}");
        rewrite(argv, &full);
        return;
    }
    let id = current_device_suffix(&cs.cfg.name);
    let full = format!("{base}-{id}");
    rewrite(argv, &full);
}

fn rewrite(argv: &mut [String], dev: &str) {
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "-device" || a == "-device-name" {
            if let Some(slot) = argv.get_mut(i + 1) {
                *slot = dev.to_string();
            }
        } else if let Some(rest) = a.strip_prefix("-device=") {
            argv[i] = format!("-device={dev}");
        } else if let Some(rest) = a.strip_prefix("-device-name=") {
            argv[i] = format!("-device-name={dev}");
        }
        i += 1;
    }
}

async fn kill_apps(procs: &mut Procs) {
    for c in [&mut procs.hg, &mut procs.pawns] {
        if let Some(mut ch) = c.take() {
            let _ = ch.kill().await;
            let _ = ch.wait().await; // reap — no zombies
        }
    }
}

async fn teardown(procs: &mut Procs) {
    kill_apps(procs).await;
    if let Some(f) = procs.inner_fwd.as_mut() {
        let _ = f.kill().await;
    }
    procs.inner_fwd = None;
    if let Some(n) = procs.netns.take() {
        n.destroy().await;
    }
}

async fn hard_block(cs: &Arc<ContainerState>, procs: &mut Procs, reason: String) {
    kill_apps(procs).await;
    *cs.state.lock().unwrap() = State::Blocked;
    tracing::error!(container = %cs.cfg.name, %reason, "BLOCKED — fail-closed, no traffic will flow");
}

// ---------------------------------------------------------------- inner mode

/// `resibox __inner ...` — runs INSIDE a netns: forwarder + DNS relay.
pub async fn run_inner(bind: String, dns_bind: String, proxy_str: String, resolvers: Vec<String>) -> Result<()> {
    let proxy = Arc::new(parse_proxy(&proxy_str)?);
    let fwd = crate::forwarder::Forwarder { bind, proxy: proxy.clone() };
    let rel = crate::dnsrelay::DnsRelay { bind: dns_bind, proxy: proxy.clone(), resolvers };
    let (a, b) = tokio::join!(
        async { fwd.run().await.map_err(|e| anyhow!("{e:#}")) },
        async { rel.run().await.map_err(|e| anyhow!("{e:#}")) },
    );
    a.and(b)
}
