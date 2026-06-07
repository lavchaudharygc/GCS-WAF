#!/usr/bin/env python3
"""
GCS-WAF Scheduler — daily_report.py
Generates a daily security digest from the WAF logs and sends it to Slack.
Runs at 08:00 daily via cron.
"""

import os
import json
import time
import logging
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
log = logging.getLogger("gcs-waf.daily-report")

LOG_FILE      = Path(os.getenv("WAF_LOG",     "/var/log/gcs-waf/access.log"))
REDIS_HOST    = os.getenv("REDIS_HOST",       "gcs-waf-redis")
REDIS_PORT    = int(os.getenv("REDIS_PORT",   "6379"))
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK",    "")

def get_redis():
    try:
        rdb = redis.Redis(host=REDIS_HOST, port=REDIS_PORT,
                          decode_responses=True, socket_timeout=5)
        rdb.ping()
        return rdb
    except Exception:
        return None

def read_last_24h():
    if not LOG_FILE.exists():
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    entries = []
    with LOG_FILE.open("r", errors="replace") as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                ts = datetime.fromisoformat(e.get("ts","").replace("+00:00",""))
                ts = ts.replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    entries.append(e)
            except Exception:
                pass
    return entries

def generate_report(entries):
    blocked = [e for e in entries if e.get("waf_action") == "block"]
    allowed = [e for e in entries if e.get("waf_action") == "allow"]

    types    = defaultdict(int)
    ips      = defaultdict(int)
    countries= defaultdict(int)

    for e in blocked:
        rule = e.get("waf_rule","unknown").split(":")[0]
        types[rule]   += 1
        ips[e.get("ip","?")] += 1
        countries[e.get("country","??")] += 1

    return {
        "date":        datetime.now().strftime("%Y-%m-%d"),
        "total":       len(entries),
        "blocked":     len(blocked),
        "allowed":     len(allowed),
        "block_rate":  f"{(len(blocked)/max(1,len(entries))*100):.1f}%",
        "top_types":   sorted(types.items(),    key=lambda x:x[1], reverse=True)[:5],
        "top_ips":     sorted(ips.items(),      key=lambda x:x[1], reverse=True)[:5],
        "top_countries": sorted(countries.items(), key=lambda x:x[1], reverse=True)[:5],
    }

def send_slack_report(report):
    if not SLACK_WEBHOOK:
        log.info("SLACK_WEBHOOK not set, printing report to stdout")
        print(json.dumps(report, indent=2))
        return

    top_types = "\n".join(f"  `{k}`: {v}" for k, v in report["top_types"])
    top_ips   = "\n".join(f"  `{k}`: {v} attacks" for k, v in report["top_ips"])

    payload = {
        "text": f":bar_chart: *GCS-WAF Daily Report — {report['date']}*",
        "attachments": [{
            "color": "#00e5a0",
            "fields": [
                {"title": "Total Requests", "value": str(report["total"]),   "short": True},
                {"title": "Blocked",        "value": str(report["blocked"]), "short": True},
                {"title": "Block Rate",     "value": report["block_rate"],   "short": True},
                {"title": "Allowed",        "value": str(report["allowed"]), "short": True},
                {"title": "Top Attack Types", "value": top_types or "None",  "short": False},
                {"title": "Top Attackers",    "value": top_ips   or "None",  "short": False},
            ],
            "footer": "GCS-WAF Daily Digest",
        }]
    }
    try:
        r = requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
        log.info(f"Slack report sent: {r.status_code}")
    except Exception as e:
        log.error(f"Slack send failed: {e}")

if __name__ == "__main__":
    log.info("Generating daily report...")
    entries = read_last_24h()
    report  = generate_report(entries)
    log.info(f"Daily: {report['blocked']} blocked / {report['total']} total ({report['block_rate']})")

    # Store in Redis
    rdb = get_redis()
    if rdb:
        rdb.setex("gcs:report:daily:latest", 86400 * 2, json.dumps(report))

    send_slack_report(report)
    log.info("Daily report done")
