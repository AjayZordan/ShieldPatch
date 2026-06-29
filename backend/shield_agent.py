#!/usr/bin/env python3
"""
shield_agent.py
Simple local agent to watch directories and upload new files to ShieldPatch backend for scanning.

Usage:
  (venv active)
  python shield_agent.py --config config.yaml
"""
import argparse
import logging
import os
import queue
import signal
import sys
import threading
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
import socket

import requests
import yaml
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileMovedEvent
from watchdog.observers import Observer

# ---------- Defaults ----------
DEFAULT_CONFIG = {
    "backend": {
        "base_url": "http://127.0.0.1:5000",
        "scan_endpoint": "/api/scan/file",
        "heartbeat_endpoint": "/api/health",
    },
    "agent": {
        "watch_dirs": [os.path.expanduser("~/Desktop")],
        "poll_interval_seconds": 300,
        "upload_retries": 3,
        "upload_backoff_seconds": 2,
        "max_file_size": 200 * 1024 * 1024,
        "user_agent": "ShieldPatchAgent/1.0",
    },
    "logging": {
        "level": "INFO",
        "logfile": "shield_agent.log",
    },
}


# ---------- Utilities ----------
def load_config(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"config file not found: {path}")
    with open(path, "r") as f:
        cfg = yaml.safe_load(f) or {}
    merged = DEFAULT_CONFIG.copy()
    merged.update(cfg)
    for k in ("backend", "agent", "logging"):
        merged[k] = {**DEFAULT_CONFIG[k], **(cfg.get(k, {}) if isinstance(cfg.get(k, {}), dict) else {})}
    return merged


def setup_logging(logfile, level=logging.INFO):
    logger = logging.getLogger("shield_agent")
    logger.setLevel(level)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    fh = RotatingFileHandler(logfile, maxBytes=2_000_000, backupCount=3)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


def _detect_local_ip():
    """
    Return a reasonable local IP string for this host (best-effort).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # connect to public DNS just to pick interface; it won't send data
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ---------- File upload logic ----------
def upload_file(path, config, logger):
    """
    Upload file at path to backend scan endpoint.
    Returns parsed JSON on success or raises.
    """
    backend = config["backend"]
    agent_cfg = config["agent"]
    url = backend["base_url"].rstrip("/") + backend["scan_endpoint"]

    if not os.path.exists(path):
        raise FileNotFoundError(path)

    size = os.path.getsize(path)
    if size > agent_cfg["max_file_size"]:
        raise ValueError(f"file too large ({size} bytes) - skipping")

    headers = {"User-Agent": agent_cfg.get("user_agent", "ShieldPatchAgent/1.0")}
    last_exc = None

    for attempt in range(1, agent_cfg["upload_retries"] + 1):
        try:
            logger.info("Uploading %s -> %s (attempt %d)", path, url, attempt)
            with open(path, "rb") as f:
                files = {"file": (os.path.basename(path), f, "application/octet-stream")}
                data = {"source": "agent", "timestamp": datetime.utcnow().isoformat()}
                resp = requests.post(url, files=files, data=data, headers=headers, timeout=30)

            logger.info("Upload response status=%s", resp.status_code)
            if 200 <= resp.status_code < 300:
                try:
                    return resp.json()
                except Exception:
                    return {"ok": True, "raw_text": resp.text}

            elif resp.status_code == 403:
                logger.warning("Upload failed: 403 Forbidden. Body: %s", resp.text)
                last_exc = RuntimeError(f"server returned 403: {resp.text.strip() or '<empty>'}")
                break

            else:
                logger.warning("Upload failed status=%s body=%s", resp.status_code, resp.text)
                last_exc = RuntimeError(f"server returned {resp.status_code}: {resp.text[:500]}")

        except requests.RequestException as e:
            last_exc = e
            logger.warning("Network/upload error: %s", e)

        backoff = agent_cfg.get("upload_backoff_seconds", 2) * attempt
        time.sleep(backoff)

    if last_exc:
        logger.error("Failed processing %s: %s", path, last_exc)
        raise last_exc

    raise RuntimeError("upload failed unknown reason")


# ---------- Watcher ----------
class NewFileHandler(FileSystemEventHandler):
    def __init__(self, queue, logger, ignore_patterns=None):
        super().__init__()
        self.queue = queue
        self.logger = logger
        self.ignore_patterns = ignore_patterns or []

    def _should_ignore(self, path):
        bn = os.path.basename(path)
        if bn.startswith(".") or bn.endswith((".crdownload", ".part", "~")):
            return True
        for p in self.ignore_patterns:
            if path.endswith(p):
                return True
        return False

    def on_created(self, event):
        if isinstance(event, FileCreatedEvent):
            path = event.src_path
            if not self._should_ignore(path):
                self.logger.info("Detected created file: %s", path)
                self.queue.put(path)

    def on_moved(self, event):
        if isinstance(event, FileMovedEvent):
            path = event.dest_path
            if not self._should_ignore(path):
                self.logger.info("Detected moved file: %s", path)
                self.queue.put(path)


# ---------- Worker ----------
def worker_loop(q, config, logger, stop_event):
    logger.info("Worker started")
    while not stop_event.is_set():
        try:
            path = q.get(timeout=1.0)
        except queue.Empty:
            continue
        try:
            logger.info("Processing file from queue: %s", path)
            time.sleep(0.5)
            result = upload_file(path, config, logger)
            logger.info("Upload result for %s: %s", path, result)
        except Exception as e:
            logger.exception("Failed processing %s: %s", path, e)
        finally:
            q.task_done()


# ---------- Periodic poller (scan trigger + heartbeat POST) ----------
def periodic_tasks(config, logger, stop_event):
    backend = config["backend"]
    agent_cfg = config["agent"]
    base = backend["base_url"].rstrip("/")
    scan_url = base + "/api/scan"
    health_url = base + backend.get("heartbeat_endpoint", "/api/health")
    interval = agent_cfg.get("poll_interval_seconds", 300)
    ua_header = agent_cfg.get("user_agent", "ShieldPatchAgent/1.0")

    logger.info("Periodic tasks running, scan every %ds", interval)

    def send_heartbeat_once():
        """
        Send a POST JSON heartbeat (this is important: backend expects a POST JSON to mark agent online)
        """
        try:
            payload = {
                "agent_ip": _detect_local_ip(),
                "status": "online",
                "user_agent": ua_header,
                "timestamp": datetime.utcnow().isoformat(),
            }
            headers = {"User-Agent": ua_header, "Content-Type": "application/json"}
            logger.info("Sending initial heartbeat (POST) to %s, payload: %s", health_url, payload)
            r = requests.post(health_url, json=payload, headers=headers, timeout=10)
            logger.info("Initial heartbeat response status: %s body: %s", r.status_code, r.text[:500])
            if 200 <= r.status_code < 300:
                logger.info("✅ Heartbeat (initial) sent successfully to %s", health_url)
            else:
                logger.warning("⚠️ Heartbeat (initial) returned status %s", r.status_code)
        except Exception as e:
            logger.warning("❌ Initial heartbeat error: %s", e)

    # send initial POST heartbeat
    send_heartbeat_once()

    # periodic loop: trigger scan (GET) and send heartbeat (POST)
    while not stop_event.wait(interval):
        # 1) Trigger backend scan endpoint (GET)
        try:
            logger.info("Triggering backend scan endpoint: %s", scan_url)
            r = requests.get(scan_url, timeout=30)
            logger.info("Scan endpoint returned: %s", r.status_code)
        except Exception as e:
            logger.warning("Scan trigger failed: %s", e)

        # 2) Send heartbeat POST
        try:
            payload = {
                "agent_ip": _detect_local_ip(),
                "status": "online",
                "user_agent": ua_header,
                "timestamp": datetime.utcnow().isoformat(),
            }
            headers = {"User-Agent": ua_header, "Content-Type": "application/json"}
            logger.info("Sending heartbeat to: %s", health_url)
            r = requests.post(health_url, json=payload, headers=headers, timeout=10)
            logger.info("Heartbeat status: %s", r.status_code)
            if r.status_code >= 200 and r.status_code < 300:
                logger.info("Heartbeat posted OK (server responded 2xx).")
            else:
                logger.warning("Heartbeat POST returned non-2xx: %s", r.status_code)
        except Exception as e:
            logger.warning("Heartbeat failed: %s", e)


# ---------- Main ----------
def main(argv=None):
    parser = argparse.ArgumentParser(description="ShieldPatch Agent")
    parser.add_argument("--config", "-c", required=True, help="Path to config.yaml")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    logcfg = cfg["logging"]

    logger = setup_logging(logcfg.get("logfile", "shield_agent.log"), getattr(logging, logcfg.get("level", "INFO")))
    logger.info("Agent starting with config %s", args.config)

    q = queue.Queue()
    stop_event = threading.Event()
    worker = threading.Thread(target=worker_loop, args=(q, cfg, logger, stop_event), daemon=True)
    worker.start()

    event_handler = NewFileHandler(q, logger)
    observer = Observer()
    for d in cfg["agent"]["watch_dirs"]:
        dd = os.path.expanduser(d)
        if os.path.isdir(dd):
            observer.schedule(event_handler, dd, recursive=False)
            logger.info("Watching directory: %s", dd)
        else:
            logger.warning("Watch dir does not exist (skipping): %s", dd)
    observer.start()

    periodic = threading.Thread(target=periodic_tasks, args=(cfg, logger, stop_event), daemon=True)
    periodic.start()

    def handle_sig(sig, frame):
        logger.info("Shutting down (signal %s)", sig)
        stop_event.set()
        observer.stop()

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    finally:
        logger.info("Waiting for observer/thread to stop...")
        observer.join(timeout=3)
        stop_event.set()
        worker.join(timeout=3)
        logger.info("Agent stopped.")


if __name__ == "__main__":
    main()