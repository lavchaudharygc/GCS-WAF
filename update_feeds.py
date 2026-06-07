#!/usr/bin/env python3
"""
GCS-WAF Scheduler — update_feeds.py
Downloads threat intel feeds and pushes IP/CIDR entries into Redis
so waf-core picks them up without any restart.
"""

import os
import sys
import time
import logging
import argparse
import ipaddress
import requests
import redis

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("gcs-waf.feeds")

# ── Config ────────────────────────────────────────────────────────────────────
REDIS_HOST = os.getenv("REDIS_HOST", "gcs-waf-redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

FEEDS = {
    "tor_exit": {
        "url":    "https://check.torproject.org/torbulkexitlist",
        "ttl":    3600 * 2,   # expire from Redis in 2h (re-downloaded hourly)
        "parser": "ip_list",
        "redis_key": "gcs:feed:tor_exit",
    },
    "emerging_threats": {
        "url":    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "ttl":    3600 * 14,
        "parser": "ip_list",
        "redis_key": "gcs:feed:emerging_threats",
    },
    "spamhaus": {
        "urls": [
            "https://www.spamhaus.org/drop/drop.txt",
            "https://www.spamhaus.org/drop/edrop.txt",
        ],
        "ttl":    3600 * 26,
        "parser": "cidr_list",
        "redis_key": "gcs:feed:spamhaus",
    },
}

# ── Parsers ───────────────────────────────────────────────────────────────────
def parse_ip_list(text: str) -> list[str]:
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        parts = line.split()
        ip_str = parts[0]
        try:
            ipaddress.ip_address(ip_str)
            entries.append(ip_str)
        except ValueError:
            pass
    return entries

def parse_cidr_list(text: str) -> list[str]:
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        # Spamhaus format: "1.2.3.0/24 ; SBL12345"
        cidr_str = line.split(";")[0].strip().split()[0]
        if not cidr_str:
            continue
        try:
            ipaddress.ip_network(cidr_str, strict=False)
            entries.append(cidr_str)
        except ValueError:
            pass
    return entries

PARSERS = {
    "ip_list":   parse_ip_list,
    "cidr_list": parse_cidr_list,
}

# ── Downloader ────────────────────────────────────────────────────────────────
def fetch(url: str, timeout: int = 20) -> str | None:
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": "GCS-WAF/2.0 threat-intel-updater"})
        r.raise_for_status()
        return r.text
    except requests.RequestException as e:
        log.warning(f"Failed to fetch {url}: {e}")
        return None

# ── Redis push ────────────────────────────────────────────────────────────────
def push_to_redis(rdb: redis.Redis, key: str, entries: list[str], ttl: int):
    pipe = rdb.pipeline(transaction=False)
    pipe.delete(key)
    if entries:
        pipe.sadd(key, *entries)
        pipe.expire(key, ttl)
    pipe.set(f"{key}:count", len(entries), ex=ttl)
    pipe.set(f"{key}:updated_at", int(time.time()), ex=ttl)
    pipe.execute()
    log.info(f"Pushed {len(entries)} entries → {key}")

# ── Main ──────────────────────────────────────────────────────────────────────
def update_feed(name: str):
    cfg = FEEDS.get(name)
    if not cfg:
        log.error(f"Unknown feed: {name}")
        return

    try:
        rdb = redis.Redis(host=REDIS_HOST, port=REDIS_PORT,
                          decode_responses=True, socket_timeout=5)
        rdb.ping()
    except redis.RedisError as e:
        log.error(f"Redis connection failed: {e}")
        return

    parser_fn = PARSERS.get(cfg["parser"], parse_ip_list)
    all_entries: list[str] = []

    urls = cfg.get("urls") or [cfg["url"]]
    for url in urls:
        log.info(f"Downloading {name} from {url}")
        text = fetch(url)
        if text:
            entries = parser_fn(text)
            log.info(f"  → parsed {len(entries)} entries")
            all_entries.extend(entries)

    if all_entries:
        push_to_redis(rdb, cfg["redis_key"], all_entries, cfg["ttl"])
        log.info(f"Feed '{name}' updated: {len(all_entries)} total entries")
    else:
        log.warning(f"Feed '{name}' returned no entries, keeping existing data")

def update_all():
    for name in FEEDS:
        update_feed(name)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GCS-WAF threat feed updater")
    parser.add_argument("--feed", choices=list(FEEDS.keys()) + ["all"], default="all")
    args = parser.parse_args()

    if args.feed == "all":
        update_all()
    else:
        update_feed(args.feed)
