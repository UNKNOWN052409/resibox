# Scaling Guide — "1 WiFi par 1000s of containers"

## Sabse pehle: WiFi ka public IP problem NAHI hai
Har container ka public identity uske **assigned residential proxy** se aata
hai. WiFi ka IP sirf transport hai. Isliye 1 internet connection par bhi
har container alag country/IP dikhata hai.

## Asli bottlenecks (order me):

| Layer | Limit | Mitigation |
|---|---|---|
| RAM | ~60–140 MB per HG+Pawns pair | 64–128 GB machine → 400–1000 pairs |
| CPU | ~0.5–2% core per pair | 1000 pairs ≈ 10–20 modern cores |
| Router NAT | consumer router ~2–8k connections | host ko wired karo; behtar: Linux box hi gateway |
| Bandwidth | ~10–30 KB/s avg per pair | 1000 pairs ≈ 15–40 Mbps sustained; fiber recommended |
| Proxy data cost | ~2–5 GB/month/pair | 1000 pairs ≈ 2–5 TB/month — plan accordingly |
| Provider flags | mass device creation = overuse flags | staggered ramp (20–50/day), stable names |

## Recommended topology

```
WiFi/Fiber ──► Linux host (wired!) ──► resibox ──► N pairs
                    │
                    ├── LAN machine 2 ──► resibox ──► M pairs
                    └── LAN machine 3 ──► resibox ──► K pairs
Same WiFi, different machines: total = N+M+K
```

## OS tuning (host pe, 500+ pairs ke liye)

```bash
sudo sysctl -w fs.file-max=2097152
sudo sysctl -w net.netfilter.nf_conntrack_max=1048576   # agar iptables use ho
ulimit -n 1048576            # /etc/security/limits.conf me permanent karo
sudo sysctl -w kernel.pid_max=4194304
```

## Bulk config generation

```bash
# accounts.txt:   hacker@havenhaus.in:Moin@4455   (one per line)
# proxies.txt:    http://res-fr-sid-RANDOM:KEY@gw.proxyrise.com:443
#                 http://res-gb-sid-RANDOM:KEY@gw.proxyrise.com:443
# countries.txt:  FR
#                 GB
#                 DE

python3 gen-config.py --count 100 --stagger 5 --out config-100.toml
LD_LIBRARY_PATH=$PWD/bin ./target/release/resibox config-100.toml
```

`RANDOM` placeholder har container ke liye unique sticky id ban jata hai →
unique exit IP guaranteed. `--per-account-devices 8` account limit respect
karta hai (honeygain ~10/device limit ka safety margin).

## Ramp-up strategy (overuse se bachne ke liye) — IMPORTANT

- Din ke hisaab se badhao: day1: 20, day2: 50, day3: 100 ...
- Ek account pe ek hi country pin karo (account↔country mapping)
- Device names kabhi manually mat badlo — resibox persist karta hai
- Health endpoint monitor: `watch -n5 'curl -s localhost:8080/health | jq .ip_isolation'`
- `blocked_or_isolated > 0` dikhe → us container ka proxy swap (replacement pool)

## Realistic ceilings

| Setup | Comfortable | Max practical |
|---|---|---|
| Laptop 16GB, userspace mode | 80–120 pairs | ~180 |
| Server 64GB | 350–500 pairs | ~700 |
| Server 128GB + tuning | 600–900 pairs | ~1100 |
| Same WiFi + 4 such machines | 2400–3600 pairs | 4000+ |

Economics note: har pair ~2–5 GB/month proxy data khata hai — provider plan
ke rate se multiply karke dekh lena. Scale wahi tak badhao jitna margin me ho.
