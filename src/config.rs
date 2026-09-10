use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct VerifyEndpoint {
    pub url: String,
    #[serde(default = "d_ip_field")]
    pub ip_field: String,
    #[serde(default = "d_country_field")]
    pub country_field: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct General {
    #[serde(default = "d_health")]
    pub health_port: u16,
    #[serde(default = "d_interval")]
    pub verify_interval_secs: u64,
    #[serde(default = "d_verify_url")]
    pub verify_url: String,
    /// Optional extra verifier endpoints; tried in order on failure/empty body.
    #[serde(default)]
    pub verify_urls: Vec<String>,
    /// Full-featured verifier list: each endpoint carries its own field paths.
    #[serde(default)]
    pub verify_endpoints: Vec<VerifyEndpoint>,
    /// Seconds between consecutive container startups (gateway-friendly ramp).
    #[serde(default)]
    pub startup_stagger_secs: u64,
    /// Tiny request interval that keeps the sticky session binding warm.
    #[serde(default = "d_ka")]
    pub keepalive_secs: u64,
    /// Cheap endpoint used only for keep-alive pings.
    #[serde(default = "d_ka_url")]
    pub keepalive_url: String,
    /// Overuse signal count that authorizes a sticky-id rotation.
    #[serde(default = "d_overuse_thr")]
    pub overuse_rotate_threshold: u32,
    #[serde(default = "d_ip_field")]
    pub verify_ip_field: String,
    #[serde(default = "d_country_field")]
    pub verify_country_field: String,
    #[serde(default = "d_verify_url")]
    pub verify_direct_url: String,
    #[serde(default)]
    pub enforcement: Enforcement,
    #[serde(default = "d_maxfail")]
    pub max_consecutive_failures: u32,
    #[serde(default = "d_resolvers")]
    pub dns_resolvers: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Enforcement {
    #[default]
    Auto,
    Netns,
    Userspace,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Replacement {
    pub proxy: String,
    #[serde(default)]
    pub expected_ip: String,
    #[serde(default)]
    pub expected_country: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ContainerCfg {
    pub name: String,
    pub proxy: String,
    #[serde(default)]
    pub expected_ip: String,
    #[serde(default)]
    pub expected_country: String,

    // Honeygain (all optional — command template override wins if present)
    #[serde(default)]
    pub honeygain_email: String,
    #[serde(default)]
    pub honeygain_pass: String,
    #[serde(default)]
    pub honeygain_device: String,
    #[serde(default)]
    pub hg_cmd: Option<Vec<String>>,

    // Pawns.app CLI
    #[serde(default)]
    pub pawns_email: String,
    #[serde(default)]
    pub pawns_pass: String,
    #[serde(default)]
    pub pawns_device_name: String,
    #[serde(default)]
    pub pawns_cmd: Option<Vec<String>>,

    #[serde(default)]
    pub replacement: Vec<Replacement>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "d_general")]
    pub general: General,
    #[serde(default)]
    pub container: Vec<ContainerCfg>,
}

fn d_health() -> u16 { 8080 }
fn d_interval() -> u64 { 60 }
fn d_verify_url() -> String { "http://ip-api.com/json/?fields=query,countryCode".into() }
fn d_ip_field() -> String { "query".into() }
fn d_country_field() -> String { "countryCode".into() }
fn d_maxfail() -> u32 { 3 }
fn d_resolvers() -> Vec<String> { vec!["9.9.9.9:53".into(), "1.1.1.1:53".into()] }
fn d_ka() -> u64 { 30 }
fn d_ka_url() -> String { "http://canhazip.com/".into() }
fn d_overuse_thr() -> u32 { 12 }
fn d_general() -> General {
    General {
        health_port: d_health(),
        verify_interval_secs: d_interval(),
        verify_url: d_verify_url(),
        verify_urls: vec![],
        verify_endpoints: vec![],
        startup_stagger_secs: 0,
        keepalive_secs: d_ka(),
        keepalive_url: d_ka_url(),
        overuse_rotate_threshold: d_overuse_thr(),
        verify_ip_field: d_ip_field(),
        verify_country_field: d_country_field(),
        verify_direct_url: d_verify_url(),
        enforcement: Enforcement::Auto,
        max_consecutive_failures: d_maxfail(),
        dns_resolvers: d_resolvers(),
    }
}

impl ContainerCfg {
    /// Substitute {email} {pass} {device} placeholders in custom command lines.
    fn subst(&self, argv: Vec<String>, device: &str) -> Vec<String> {
        argv.into_iter()
            .map(|a| {
                a.replace("{email}", &self.honeygain_email)
                    .replace("{pass}", &self.honeygain_pass)
                    .replace("{pawns_pass}", &self.pawns_pass)
                    .replace("{device}", device)
            })
            .collect()
    }

    /// Honeygain argv with placeholders substituted.
    pub fn hg_argv(&self) -> Vec<String> {
        let dev = Self::device_name("HG", &self.honeygain_device);
        let default = vec![
            "./honeygain".into(),
            "-email".into(), self.honeygain_email.clone(),
            "-pass".into(), self.honeygain_pass.clone(),
            "-device".into(), dev.clone(),
            "-tou-accept".into(),
        ];
        let argv = self.hg_cmd.clone().unwrap_or(default);
        self.subst(argv, &dev)
    }

    /// Pawns.app CLI argv with placeholders substituted.
    pub fn pawns_argv(&self) -> Vec<String> {
        let dev = Self::device_name("PB", &self.pawns_device_name);
        let mut default = vec![
            format!("-email={}", self.pawns_email),
            format!("-password={}", self.pawns_pass),
            format!("-device-name={}", dev.clone()),
            "-accept-tos".to_string(),
        ];
        default.insert(0, "./pawns-cli".to_string());
        default.retain(|a| !a.ends_with('=') && !a.is_empty());
        let argv = self.pawns_cmd.clone().unwrap_or(default);
        self.subst(argv, &dev)
    }

    fn device_name(prefix: &str, given: &str) -> String {
        if !given.is_empty() {
            given.to_string()
        } else {
            format!("{prefix}-{}", nanoid6())
        }
    }
}

pub fn nanoid6() -> String {
    use rand::Rng;
    const AL: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut r = rand::thread_rng();
    (0..6).map(|_| AL[r.gen_range(0..AL.len())] as char).collect()
}

pub fn load(path: &str) -> Result<Config> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    let cfg: Config = toml::from_str(&raw).context("parse config")?;
    for c in &cfg.container {
        crate::proxy::parse_proxy(&c.proxy)
            .with_context(|| format!("container {}: bad proxy url", c.name))?;
    }
    Ok(cfg)
}
