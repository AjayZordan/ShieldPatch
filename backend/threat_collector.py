#!/usr/bin/env python3
"""
threat_collector.py (updated)
Tries to push indicators to backend with fallback endpoints if primary POST fails.
Usage:
  python threat_collector.py --once
"""
import argparse
import logging
import time
import requests
import json
from datetime import datetime
from typing import List, Dict

try:
    import feedparser
except Exception:
    raise SystemExit("Missing dependency 'feedparser'. Install with: pip install feedparser")

LOG = logging.getLogger("threat_collector")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BACKEND_BASE = "http://127.0.0.1:5000"
THREATS_ENDPOINT = f"{BACKEND_BASE}/api/threats/"

FEEDS = [
    {"name": "URLhaus (abuse.ch)", "type": "rss", "url": "https://urlhaus.abuse.ch/downloads/rpc/"},
    {"name": "ThreatPost", "type": "rss", "url": "https://threatpost.com/feed/"},
    {"name": "KrebsOnSecurity", "type": "rss", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "NVD (requires API key)", "type": "nvd_json_gz", "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"},
    {"name": "MalwareBazaar (may require API)", "type": "malwarebazaar_json", "url": "https://mb-api.abuse.ch/api/v1/"},
]

def mk_indicator(source: str, ioc: str, itype: str, description: str = ""):
    return {
        "source": source,
        "ioc": ioc,
        "type": itype,
        "description": description,
        "first_seen": datetime.utcnow().isoformat() + "Z"
    }

def fetch_rss(url: str) -> List[Dict]:
    LOG.info("Fetching RSS: %s", url)
    try:
        d = feedparser.parse(url)
        if d.bozo:
            LOG.warning("feedparser bozo flag true for %s (bozo_exception=%s)", url, getattr(d, "bozo_exception", None))
        items = []
        for e in d.entries:
            title = e.get("title", "")
            link = e.get("link", "")
            summary = e.get("summary", "") or e.get("description", "")
            if link:
                items.append(mk_indicator("rss", link, "url", title or summary))
            elif title:
                items.append(mk_indicator("rss", title, "text", summary))
        LOG.info("Found %d RSS entries from %s", len(items), url)
        return items
    except Exception as e:
        LOG.warning("HTTP error fetching %s: %s", url, e)
        return []

def fetch_nvd_json_gz(url: str, api_key: str = None) -> List[Dict]:
    if not api_key:
        LOG.warning("NVD requires API key; skipping NVD feed (set NVD_API_KEY env var to enable).")
        return []
    LOG.info("Fetching NVD JSON with API key (not demoed here).")
    try:
        headers = {"apiKey": api_key}
        r = requests.get(url, headers=headers, timeout=30); r.raise_for_status()
        data = r.json()
        items = []
        for item in data.get("CVE_Items", []):
            cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
            desc = item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "")
            if cve_id:
                items.append(mk_indicator("nvd", cve_id, "cve", desc))
        return items
    except Exception as e:
        LOG.warning("JSON feed failed: %s", e)
        return []

def fetch_malwarebazaar(url: str, api_key: str = None) -> List[Dict]:
    if not api_key:
        LOG.warning("MalwareBazaar requires API key; skipping.")
        return []
    LOG.info("Fetching MalwareBazaar with key (not implemented in demo).")
    return []

def try_post(url: str, payload, headers=None, timeout=12):
    try:
        r = requests.post(url, json=payload, headers=headers or {}, timeout=timeout)
        return r
    except Exception as e:
        LOG.warning("POST to %s failed: %s", url, e)
        return None

def push_to_backend(indicators: List[Dict]):
    if not indicators:
        LOG.info("No indicators to push.")
        return

    # Candidate endpoints to try in order:
    candidates = [
        THREATS_ENDPOINT,                 # primary used before
        THREATS_ENDPOINT.rstrip("/") + "/import",
        THREATS_ENDPOINT.rstrip("/") + "/bulk",
        THREATS_ENDPOINT.rstrip("/") + "/add",
    ]

    payload_bulk = {"indicators": indicators}
    headers = {"Content-Type": "application/json", "User-Agent": "ThreatCollector/1.0"}

    LOG.info("Attempting bulk push to backend (%d indicators)", len(indicators))

    for url in candidates:
        LOG.info("Trying POST -> %s", url)
        r = try_post(url, payload_bulk, headers=headers)
        if r is None:
            continue
        LOG.info("Response from %s: %s %s", url, r.status_code, (r.text[:200] if r.text else "<no-body>"))
        if 200 <= r.status_code < 300:
            LOG.info("Bulk push succeeded to %s", url)
            return
        if r.status_code == 405:
            LOG.warning("Method not allowed at %s (405). Trying next candidate.", url)
            continue
        # 4xx/5xx — try next candidate but keep response logged
    # If we reach here, bulk pushes failed. Try per-indicator POSTs to the primary endpoint.
    LOG.info("Bulk endpoints failed — trying per-indicator POSTs to %s", THREATS_ENDPOINT)
    success_count = 0
    for ind in indicators:
        payload = {"indicator": ind}  # many backends expect single object named 'indicator'
        r = try_post(THREATS_ENDPOINT, payload, headers=headers)
        if r is None:
            continue
        LOG.info("Per-item response: %s %s", r.status_code, (r.text[:200] if r.text else "<no-body>"))
        if 200 <= r.status_code < 300:
            success_count += 1
    LOG.info("Per-item push results: %d/%d succeeded", success_count, len(indicators))
    if success_count == 0:
        LOG.error("All attempts to push indicators failed. Server likely expects a different endpoint or payload. Inspect server logs or implement POST handler on backend.")
    else:
        LOG.info("Partial/complete success pushing per-item indicators.")

def collect_once() -> List[Dict]:
    all_indicators = []
    import os
    NVD_API_KEY = os.getenv("NVD_API_KEY")
    MB_API_KEY = os.getenv("MB_API_KEY")

    for feed in FEEDS:
        t = feed.get("type")
        url = feed.get("url")
        name = feed.get("name")
        LOG.info("Processing feed row: %s (%s)", name, t)
        if t == "rss":
            items = fetch_rss(url)
            for it in items:
                it["source"] = name
            all_indicators.extend(items)
        elif t == "nvd_json_gz":
            items = fetch_nvd_json_gz(url, NVD_API_KEY)
            for it in items:
                it["source"] = name
            all_indicators.extend(items)
        elif t == "malwarebazaar_json":
            items = fetch_malwarebazaar(url, MB_API_KEY)
            for it in items:
                it["source"] = name
            all_indicators.extend(items)
        else:
            LOG.warning("Unknown feed type: %s", t)

    # dedupe
    seen = set()
    dedup = []
    for ind in all_indicators:
        key = (ind.get("source"), ind.get("ioc"))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(ind)
    LOG.info("Collected indicators total: %d", len(dedup))
    return dedup

def main_loop(interval_seconds=300, once=False):
    if once:
        indicators = collect_once()
        if indicators:
            push_to_backend(indicators)
        else:
            LOG.info("No indicators collected on --once run.")
        return

    LOG.info("Starting threat collector loop (interval=%ds)", interval_seconds)
    while True:
        indicators = collect_once()
        if indicators:
            push_to_backend(indicators)
        else:
            LOG.info("No indicators this cycle.")
        time.sleep(interval_seconds)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=300)
    args = parser.parse_args()
    try:
        main_loop(interval_seconds=args.interval, once=args.once)
    except KeyboardInterrupt:
        LOG.info("Interrupted, exiting.")