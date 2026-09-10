# 📦 resibox — Rust-Based Isolated Residential IP Container Runtime

**One container → one assigned residential proxy → one isolated egress path.**
Honeygain + Pawns.app run inside each jail. Fail-closed by construction.

```
                 ┌──────────────────────────────────────────────┐
                 │              resibox (Rust, 1 binary)        │
                 │  preflight → start → watchdog → fail-closed  │
                 └───────┬──────────────┬──────────────┬────────┘
                         │              │              │
              ┌──────────▼───┐ ┌────────▼─────┐ ┌──────▼───────┐
              │ netns: uk-a  │ │ netns: fr-b  │ │ netns: de-c  │
              │ ├ honeygain  │ │ ├ honeygain  │ │ ├ honeygain  │
              │ ├ pawns-cli  │ │ ├ pawns-cli  │ │ ├ pawns-cli  │
              │ └ fwd + dns  │ │ └ fwd + dns  │ │ └ fwd + dns  │
              │ iptables jail│ │ iptables jail│ │ iptables jail│
              └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
                     ▼                ▼                ▼
               UK residential   FR residential   DE residential
                  (ONLY)           (ONLY)           (ONLY)
```

## Guarantees (all enforced, none advisory)

| Requirement | How it is enforced |
|---|---|
| One proxy per container | Each container's config carries exactly one `proxy` URL; no inheritance possible |
| Network-level isolation | Per-container `ip netns` + dedicated veth pair + subnet (root mode) |
| All TCP through assigned proxy | iptables REDIRECT → per-container forwarder → SOCKS5/HTTP-CONNECT tunnel |
| DNS cannot escape | UDP:53 REDIRECT → local DNS relay → **TCP DNS over the proxy** |
| Everything else blocked | `iptables -P OUTPUT DROP` inside the namespace (fail-closed) |
| No datacenter IP leak | Host baseline learned at startup; if observed egress == host IP → **LEAK → kill + block** |
| Pre-flight verification | Observed IP must match `expected_ip` / `expected_country` BEFORE apps spawn |
| Watchdog | Re-verifies every N secs; on failure: kill apps → isolate → revalidate → resume ONLY on pass |
| IP stability | Same endpoint for the container's lifetime. Rotation ONLY when endpoint confirmed dead AND an authorized replacement exists in config |
| Cross-container blindness | Namespaces cannot reach each other's listeners; forwarder refuses connections without conntrack `SO_ORIGINAL_DST` |
| 0.1 core / phone friendly | Single ~3MB binary; **userspace mode** needs no root at all |

## Two enforcement modes

### Root mode (`enforcement = "netns"`) — full network jail
Needs root + `ip` + `iptables`. Builds a real network namespace per container.
Apps physically CANNOT bypass the proxy — the kernel drops anything that tries.

### Userspace mode (`enforcement = "userspace"`) — Render/Termux/0.1-core
No root needed. Spawns apps with `ALL_PROXY` set and runs the same strict
preflight + watchdog verification loop. If the observed identity ever drifts,
workloads are killed instantly. Weaker than the kernel jail but zero-dependency.
`auto` picks the best available mode.

## Quick start

```bash
cargo build --release
cp config.example.toml config.toml
# edit config.toml — one [[container]] block per isolated runtime

./target/release/resibox config.toml
curl localhost:8080/health   # live states, observed IPs, isolation %
```

Binaries for the workloads are expected next to the working dir:
```
bin/honeygain     # extracted from honeygain/honeygain docker image
bin/libhg.so.2.0.0
bin/pawns-cli     # https://download.iproyal.com/pawns-cli/latest/linux_<arch>/pawns-cli
```
(Override with `hg_cmd` / `pawns_cmd` arrays in config.)

## Config essentials

```toml
[[container]]
name = "uk-a"
proxy = "socks5://user:pass@gw.provider.com:1080"
expected_ip = ""            # optional exact pin (strongest)
expected_country = "GB"     # or geo check
hg_cmd = ["./bin/honeygain", "-email", "...", "-pass", "...", "-device", "HG-UK-A", "-tou-accept"]
pawns_cmd = ["./bin/pawns-cli", "-email=...", "-password=...", "-device-name=PB-UK-A", "-accept-tos"]

[[container.replacement]]   # OPTIONAL authorized replacement, tried in order
proxy = "socks5://user:pass2@gw.provider.com:1080"
expected_country = "GB"
```

## Failure behavior (implemented exactly)

```
STOP APPLICATION TRAFFIC   → apps killed first, always, before any retry logic
ISOLATE CONTAINER          → state = Isolated/Blocked, nothing can flow
LOG THE FAILURE            → reason captured in logs + /health last_error
REVALIDATE ASSIGNED PROXY  → full preflight re-run against SAME endpoint
RESUME ONLY AFTER VERIFICATION → otherwise stays Blocked forever
```

Rotation happens only on endpoint-level failures (unreachable / auth rejected /
timeout) AND only toward configured replacements — never implicit fallback.

## Tests

```bash
cargo test
```
5 tests, fully offline via mock SOCKS5 + JSON endpoints:
1. Proxy URL parsing (auth, urlencoding, schemes)
2. SOCKS5 tunnel relays HTTP end-to-end
3. Verifier policy matrix (exact IP / country)
4. E2E: preflight pass → Running → proxy death → watchdog fail-closed
5. E2E: wrong country at preflight → workload never starts

Plus a leak-detector proof: when the "via-proxy" observation equals the host
baseline, the runtime blocks the container instead of starting it.

## Notes

- Verify endpoints should be plain `http://` JSON (e.g. ip-api.com) so the
  runtime doesn't need a TLS stack; configure any equivalent endpoint.
- In root mode the proxy gateway IPs are resolved once on the host and exempted
  from redirection — this avoids redirect loops without UID tricks.
- The forwarder refuses any connection lacking a conntrack original-dst entry:
  nobody can use it as an open relay, including other containers.
