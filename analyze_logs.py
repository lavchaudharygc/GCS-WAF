#!/usr/bin/env python3
"""
GCS-WAF Scheduler — analyze_logs.py
Runs every 5 minutes via cron. Parses the WAF access log, detects:
  - Attack spikes (>10 blocks in 5 min from same IP → auto-block)
  - New attack types not seen before
  - Threshold breaches → Slack webhook alert
"""

import os
import re
import json
import time
import logging
import hashlib
import requests
import redis
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("gcs-waf.analyzer")

# ── Config ────────────────────────────────────────────────────────────────────
LOG_FILE       = Path(os.getenv("WAF_LOG",      "/var/log/gcs-waf/access.log"))
REDIS_HOST     = os.getenv("REDIS_HOST",        "gcs-waf-redis")
REDIS_PORT     = int(os.getenv("REDIS_PORT",    "6379"))
SLACK_WEBHOOK  = os.getenv("SLACK_WEBHOOK",     "")
WAF_CORE_URL   = os.getenv("WAF_CORE_URL",      "http://gcs-waf-core")

# Alert thresholds
SPIKE_THRESHOLD  = 10   # blocks from one IP in 5 min → auto-block
ALERT_THRESHOLD  = 50   # total blocks in 5 min → Slack alert
AUTOBLOCK_TTL    = 3600 # auto-block duration (seconds)

# Window (match cron frequency)
WINDOW_SECONDS   = 300  # 5 minutes

# ── Redis connection ──────────────────────────────────────────────────────────
def get_redis():
    try:
        rdb = redis.Redis(host=REDIS_HOST, port=REDIS_PORT,
                          decode_responses=True, socket_timeout=5)
        rdb.ping()
        return rdb
    except redis.RedisError as e:
        log.error(f"Redis unavailable: {e}")
        return None

# ── Log parser ────────────────────────────────────────────────────────────────
def parse_log_window(window_seconds: int) -> list[dict]:
    """Read the last window_seconds of log entries."""
    if not LOG_FILE.exists():
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    entries = []

    with LOG_FILE.open("r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                # Parse ISO8601 timestamp
                ts_str = entry.get("ts", "")
                # Handle nginx format: 2024-01-15T14:32:10+05:30
                ts_str = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", ts_str)
                ts = datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S")
                ts = ts.replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    entries.append(entry)
            except (json.JSONDecodeError, ValueError):
                pass

    return entries

# ── Analysis ──────────────────────────────────────────────────────────────────
def analyze(entries: list[dict]) -> dict:
    blocked = [e for e in entries if e.get("waf_action") == "block"]
    allowed = [e for e in entries if e.get("waf_action") == "allow"]

    # Per-IP block counts
    ip_blocks: dict[str, int] = defaultdict(int)
    for e in blocked:
        ip_blocks[e.get("ip", "?")] += 1

    # Attack type counts
    type_counts: dict[str, int] = defaultdict(int)
    for e in blocked:
        rule = e.get("waf_rule", "unknown")
        category = rule.split(":")[0] if ":" in rule else rule
        type_counts[category] += 1

    # Country counts
    country_counts: dict[str, int] = defaultdict(int)
    for e in blocked:
        country_counts[e.get("country", "??") or "??"] += 1

    # Top attacking IPs (sorted by block count)
    top_ips = sorted(ip_blocks.items(), key=lambda x: x[1], reverse=True)[:10]

    # IPs exceeding spike threshold
    spike_ips = {ip: cnt for ip, cnt in ip_blocks.items() if cnt >= SPIKE_THRESHOLD}

    return {
        "total_requests": len(entries),
        "total_blocked":  len(blocked),
        "total_allowed":  len(allowed),
        "ip_blocks":      dict(ip_blocks),
        "top_ips":        top_ips,
        "type_counts":    dict(type_counts),
        "country_counts": dict(country_counts),
        "spike_ips":      spike_ips,
        "window_seconds": WINDOW_SECONDS,
    }

# ── Auto-blocker ──────────────────────────────────────────────────────────────
def auto_block_spikes(rdb: redis.Redis, spike_ips: dict[str, int]):
    if not spike_ips:
        return
    for ip, count in spike_ips.items():
        key = f"gcs:dynblock:{ip}"
        existing = rdb.get(key)
        if not existing:
            rdb.setex(key, AUTOBLOCK_TTL, f"auto_spike:{count}")
            # Also set the shared dict key that threat_intel.lua reads
            rdb.setex(f"gcs:blocklist:{ip}", AUTOBLOCK_TTL, f"auto_spike:{count}")
            log.warning(f"AUTO-BLOCKED {ip} ({count} blocks in {WINDOW_SECONDS}s)")

# ── Slack alerting ────────────────────────────────────────────────────────────
def slack_alert(stats: dict):
    if not SLACK_WEBHOOK:
        return
    if stats["total_blocked"] < ALERT_THRESHOLD:
        return

    # Dedup: don't fire same alert twice in 5 min
    sig    = hashlib.md5(str(sorted(stats["type_counts"].items())).encode()).hexdigest()[:8]
    rdb    = get_redis()
    if rdb:
        key = f"gcs:alert:sent:{sig}"
        if rdb.exists(key):
            return
        rdb.setex(key, WINDOW_SECONDS * 2, "1")

    top_ips_text = "\n".join(
        f"  `{ip}` — {cnt} blocks" for ip, cnt in stats["top_ips"][:5]
    )
    type_text = "  " + ", ".join(
        f"{k}: {v}" for k, v in sorted(stats["type_counts"].items(),
                                        key=lambda x: x[1], reverse=True)
    )

    payload = {
        "text": f":rotating_light: *GCS-WAF Attack Alert*",
        "attachments": [{
            "color": "#ff3d5a",
            "fields": [
                {"title": "Blocked requests (last 5m)",
                 "value": str(stats["total_blocked"]), "short": True},
                {"title": "Unique attacking IPs",
                 "value": str(len(stats["ip_blocks"])), "short": True},
                {"title": "Attack types",  "value": type_text,    "short": False},
                {"title": "Top attackers", "value": top_ips_text, "short": False},
            ],
            "footer": f"GCS-WAF | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        }]
    }
    try:
        r = requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
        if r.ok:
            log.info("Slack alert sent")
        else:
            log.warning(f"Slack alert failed: {r.status_code}")
    except requests.RequestException as e:
        log.warning(f"Slack alert error: {e}")

# ── Redis stats update ────────────────────────────────────────────────────────
def update_redis_stats(rdb: redis.Redis, stats: dict):
    """Push analysis results to Redis so the dashboard can read them."""
    pipe = rdb.pipeline(transaction=False)
    pipe.incrby("gcs:stats:total_blocked", stats["total_blocked"])
    pipe.incrby("gcs:stats:total_allowed", stats["total_allowed"])
    for ip, cnt in stats["top_ips"][:10]:
        pipe.zadd("gcs:stats:top_ips", {ip: cnt})
    pipe.expire("gcs:stats:top_ips", 3600)
    # Store type counts
    for cat, cnt in stats["type_counts"].items():
        pipe.incrby(f"gcs:stats:type:{cat}", cnt)
    pipe.set("gcs:stats:last_analysis", int(time.time()))
    pipe.execute()

# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info(f"Analyzing last {WINDOW_SECONDS}s of WAF logs...")

    entries = parse_log_window(WINDOW_SECONDS)
    if not entries:
        log.info("No log entries found in window")
        raise SystemExit(0)

    stats = analyze(entries)
    log.info(
        f"Window stats: {stats['total_blocked']} blocked / "
        f"{stats['total_allowed']} allowed / "
        f"{len(stats['ip_blocks'])} unique IPs"
    )

    rdb = get_redis()
    if rdb:
        auto_block_spikes(rdb, stats["spike_ips"])
        update_redis_stats(rdb, stats)

    slack_alert(stats)

    if stats["spike_ips"]:
        log.warning(f"Spike IPs auto-blocked: {list(stats['spike_ips'].keys())}")

    log.info("Analysis complete")
