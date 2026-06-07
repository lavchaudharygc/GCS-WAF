#!/usr/bin/env python3
"""
GCS-WAF Scheduler — update_geoip.py
Downloads the MaxMind GeoLite2-Country MMDB database.
Requires MAXMIND_LICENSE_KEY env var (free registration at maxmind.com).
"""

import os
import sys
import gzip
import shutil
import logging
import tarfile
import requests
import tempfile
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("gcs-waf.geoip")

LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY", "")
GEOIP_DIR   = Path(os.getenv("GEOIP_DIR", "/geoip"))
DB_FILE     = GEOIP_DIR / "GeoLite2-Country.mmdb"

DOWNLOAD_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id=GeoLite2-Country&license_key={key}&suffix=tar.gz"
)

def download_geolite2():
    if not LICENSE_KEY:
        log.warning(
            "MAXMIND_LICENSE_KEY not set — skipping GeoIP update.\n"
            "Register free at https://www.maxmind.com/en/geolite2/signup\n"
            "Then set MAXMIND_LICENSE_KEY in your .env file."
        )
        return False

    url = DOWNLOAD_URL.format(key=LICENSE_KEY)
    log.info("Downloading GeoLite2-Country database from MaxMind...")

    try:
        r = requests.get(url, timeout=60, stream=True,
                         headers={"User-Agent": "GCS-WAF/2.0 geoip-updater"})
        r.raise_for_status()
    except requests.RequestException as e:
        log.error(f"Download failed: {e}")
        return False

    # Save to temp file
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        for chunk in r.iter_content(chunk_size=65536):
            tmp.write(chunk)
        tmp_path = tmp.name

    log.info(f"Downloaded {os.path.getsize(tmp_path):,} bytes, extracting...")

    try:
        GEOIP_DIR.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tmp_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("GeoLite2-Country.mmdb"):
                    # Extract just the .mmdb file
                    member.name = "GeoLite2-Country.mmdb"
                    tar.extract(member, path=GEOIP_DIR)
                    log.info(f"Extracted to {DB_FILE}")
                    break
            else:
                log.error("GeoLite2-Country.mmdb not found in archive")
                return False
    except tarfile.TarError as e:
        log.error(f"Extraction failed: {e}")
        return False
    finally:
        os.unlink(tmp_path)

    size_mb = DB_FILE.stat().st_size / 1024 / 1024
    log.info(f"GeoLite2-Country.mmdb updated successfully ({size_mb:.1f} MB)")
    return True

def verify_db():
    if not DB_FILE.exists():
        log.warning(f"GeoIP database not found at {DB_FILE}")
        return False
    size = DB_FILE.stat().st_size
    if size < 1_000_000:  # should be ~6MB
        log.warning(f"GeoIP database looks too small ({size} bytes), may be corrupt")
        return False
    log.info(f"GeoIP database OK ({size:,} bytes)")
    return True

if __name__ == "__main__":
    success = download_geolite2()
    if not success:
        verify_db()
        sys.exit(0 if DB_FILE.exists() else 1)
