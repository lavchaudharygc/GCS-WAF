# GCS-WAF v2.0

A production-grade Web Application Firewall built on OpenResty (NGINX + Lua) with Redis, automated threat intel, bot protection, ML anomaly detection, and a real-time dashboard.

---

## What's New in v2.0

| Feature | v1.x | v2.0 |
|---|---|---|
| Container stability | ❌ Crashes on startup | ✅ Tini PID1, health checks, safe init |
| Attack detection | Basic patterns | Full scoring engine (SQLi/XSS/CMDi/SSRF/RFI/Path) |
| Bot protection | ❌ Missing | ✅ JS proof-of-work cookie challenge |
| Threat intel | Manual PS1 | ✅ Auto-updating (Tor, Spamhaus, ET) via cron |
| Virtual patching | ❌ Missing | ✅ Deploy rules live via dashboard, no restart |
| ML anomaly detection | ❌ Missing | ✅ Welford Z-score on 13 request features |
| Dashboard | Basic HTML | ✅ Heatmaps, simulation panel, vpatch UI, ML stats |
| HTTPS / SSL | ❌ Missing | ✅ Let's Encrypt + auto-renewal via certbot |
| Auto-blocking | ❌ Missing | ✅ Spike detection → auto-block in 5 min |
| Alerting | ❌ Missing | ✅ Slack webhook + daily digest |

---

## Architecture

```
Internet
   │
   ▼
┌─────────────────────────────────┐
│  gcs-waf-core  (port 80/443)   │  OpenResty + Lua
│                                 │
│  ① GeoIP lookup                │  geoip.lua
│  ② Threat intel check          │  threat_intel.lua  ◄── Redis feeds
│  ③ WAF rules (score ≥50 → 403) │  waf_core.lua
│  ④ Virtual patch check         │  virtual_patch.lua ◄── Redis patches
│  ⑤ Bot JS challenge            │  bot_challenge.lua
│  ⑥ Behavior / rate limit       │  behavior.lua      ◄── Redis scores
│  ⑦ ML anomaly detection        │  ml_anomaly.lua
│  ⑧ Proxy to backend            │
└──────────┬──────────────────────┘
           │ Redis
           ▼
┌─────────────────────────────────┐
│  gcs-waf-redis                  │  State, scores, feeds, patches
└─────────────────────────────────┘
           │
┌─────────────────────────────────┐
│  gcs-waf-scheduler (cron)       │  Python
│  • Threat feed updates          │  update_feeds.py
│  • GeoIP DB updates             │  update_geoip.py
│  • Log analysis + auto-block    │  analyze_logs.py
│  • Slack alerts + daily report  │  daily_report.py
└─────────────────────────────────┘
           │
┌─────────────────────────────────┐
│  gcs-waf-dashboard  (port 8080) │  nginx + Chart.js
│  • Real-time stats + heatmaps   │
│  • Attack simulation panel      │
│  • Virtual patch management     │
│  • ML model stats               │
└─────────────────────────────────┘
```

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/lavchaudharygc/GCS-WAF
cd GCS-WAF
cp .env.example .env
```

Edit `.env`:

```env
BACKEND_HOST=your-app-ip-or-container
BACKEND_PORT=8888
WAF_SECRET=your-long-random-secret-here
MAXMIND_LICENSE_KEY=your-maxmind-key      # free at maxmind.com
```

### 2. Run setup

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

This will:
- Build all Docker images
- Start all services
- Download GeoLite2 DB (if license key set)
- Pull initial threat intel feeds

### 3. Open dashboard

```
http://localhost:8080
```

### 4. Run attack tests

```bash
chmod +x scripts/test-attacks.sh
./scripts/test-attacks.sh
```

---

## File Structure

```
GCS-WAF/
├── docker-compose.yml           # Full stack definition
├── .env.example                 # Environment variable template
│
├── waf-core/                    # OpenResty WAF engine
│   ├── Dockerfile               # Builds the WAF container
│   ├── nginx.conf               # Main nginx config (shared dicts, init)
│   ├── default.conf             # Server block + phase hooks
│   ├── waf_core.lua             # Attack pattern matching (SQLi/XSS/etc)
│   ├── behavior.lua             # Rate limiting + behavioral scoring
│   ├── bot_challenge.lua        # JS proof-of-work bot challenge
│   ├── threat_intel.lua         # Feed-based IP blocklist
│   ├── virtual_patch.lua        # Live rule deployment API
│   ├── ml_anomaly.lua           # Statistical anomaly detection
│   ├── geoip.lua                # MaxMind GeoLite2 country lookup
│   └── rules/                   # Static JSON rule files (optional)
│
├── waf-dashboard/
│   └── index.html               # Full SPA dashboard
│
├── scheduler/                   # Python cron container
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── crontab
│   ├── update_feeds.py          # Threat intel downloader
│   ├── update_geoip.py          # MaxMind DB updater
│   ├── analyze_logs.py          # Log analysis + auto-blocking
│   └── daily_report.py          # Daily Slack digest
│
├── scripts/
│   ├── setup.sh                 # First-time setup
│   ├── test-attacks.sh          # Attack test suite
│   └── dashboard-nginx.conf     # Dashboard proxy config
│
└── ssl/
    └── nginx-ssl.conf           # HTTPS / Let's Encrypt config
```

---

## Fixing the Container Crash

The most common crash causes and their fixes in v2.0:

### 1. Missing Redis on startup
**Old behaviour:** WAF crashed if Redis wasn't ready yet.  
**Fix:** All Lua modules use `pcall()` for every Redis call and fall back to the in-memory `lua_shared_dict`. The container never crashes due to Redis being slow.

### 2. Missing Lua modules
**Old behaviour:** A missing `require()` crashed the worker.  
**Fix:** `init_by_lua_block` in `nginx.conf` uses a `safe_require()` wrapper that logs a warning instead of crashing.

### 3. Wrong PID 1 (zombie processes)
**Old behaviour:** `nginx` as PID 1 doesn't reap zombie child processes → Docker eventually kills it.  
**Fix:** `tini` is now PID 1 (`ENTRYPOINT ["/sbin/tini", "--"]`).

### 4. Missing shared dict declarations
**Old behaviour:** Dicts declared in `server {}` or `location {}` blocks (invalid) caused startup failure.  
**Fix:** All `lua_shared_dict` declarations are in the `http {}` block in `nginx.conf`.

### 5. Wrong stop signal
**Fix:** `stop_signal: SIGQUIT` in docker-compose gives OpenResty time to drain connections before stopping.

**To debug crashes:**
```bash
docker-compose logs gcs-waf-core
docker-compose exec gcs-waf-core openresty -t   # config test
```

---

## WAF Scoring System

Each request is scored across all checks. A total score ≥ 50 results in a 403 block.

| Attack Category | Score | Example |
|---|---|---|
| SQL Injection (UNION/SELECT) | 90 | `?id=1 UNION SELECT...` |
| SQLi (xp_cmdshell/exec) | 80 | `'; EXEC xp_cmdshell('id')` |
| XSS (`<script>`) | 80 | `<script>alert(1)</script>` |
| Command injection | 80 | `; cat /etc/passwd` |
| SSRF (AWS metadata) | 90 | `169.254.169.254` |
| Path traversal (`../../`) | 70 | `../../../../etc/passwd` |
| RFI (remote PHP include) | 75 | `?page=http://evil.com/shell.php` |
| Scanner UA (sqlmap, nikto) | 50 | `sqlmap/1.7.8` |
| Rate limit breach | 30 | > 120 req/min |
| Behavioral anomaly | 15–30 | Repeated 404s, no referer POST |

---

## Virtual Patching

Deploy a blocking rule instantly without restarting NGINX:

```bash
# Via curl
curl -X POST http://localhost/waf-api/vpatch \
  -H 'Content-Type: application/json' \
  -d '{"pattern":"(?i)eval\\s*\\(","target":"any","description":"Block PHP eval"}'

# Via dashboard: Virtual Patches tab → paste pattern → Deploy
```

Rules are stored in Redis and activate within milliseconds.

---

## HTTPS Setup

```bash
# 1. Set your domain in .env
echo "WAF_DOMAIN=your-domain.com" >> .env
echo "CERTBOT_EMAIL=you@your-domain.com" >> .env

# 2. Get Let's Encrypt cert
docker-compose --profile ssl up gcs-waf-certbot

# 3. Copy SSL config and reload
cp ssl/nginx-ssl.conf waf-core/conf.d/ssl.conf
docker-compose exec gcs-waf-core openresty -s reload
```

Certbot will auto-renew every 12 hours.

---

## Slack Alerts

Add to `.env`:

```env
SLACK_WEBHOOK=https://hooks.slack.com/services/XXX/YYY/ZZZ
```

You'll receive:
- **Spike alerts** when > 50 blocks happen in 5 minutes
- **Daily digest** at 08:00 with attack summary

---

## GeoIP Country Blocking

```env
# Block North Korea, Iran, Russia (example)
GCS_BLOCKED_COUNTRIES=KP,IR,RU
```

Requires `MAXMIND_LICENSE_KEY`. Free signup at [maxmind.com](https://www.maxmind.com/en/geolite2/signup).

---

## Useful Commands

```bash
# View live WAF logs
docker-compose logs -f gcs-waf-core

# Check all service status
docker-compose ps

# Reload WAF config without downtime
docker-compose exec gcs-waf-core openresty -s reload

# Test config before reload
docker-compose exec gcs-waf-core openresty -t

# Manually trigger feed update
docker-compose exec gcs-waf-scheduler python /app/update_feeds.py --feed all

# Run attack test suite
./scripts/test-attacks.sh

# Access Redis CLI
docker-compose exec gcs-waf-redis redis-cli

# See blocked IPs in Redis
docker-compose exec gcs-waf-redis redis-cli KEYS "gcs:blocklist:*"
```
