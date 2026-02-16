#!/usr/bin/env python3
"""Pinger - Lightweight network monitoring with Pushover alerts."""

import csv
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("pinger")

# ── Configuration from environment ──────────────────────────────────────────

CSV_PATH = os.environ.get("CSV_PATH", "/app/targets.csv")
PING_INTERVAL = int(os.environ.get("PING_INTERVAL", "120"))
PING_FAIL_INTERVAL = int(os.environ.get("PING_FAIL_INTERVAL", "60"))
PING_TYPE = os.environ.get("PING_TYPE", "icmp").lower()
FAILURE_THRESHOLD = int(os.environ.get("FAILURE_THRESHOLD", "12"))
FAILURE_CHECK_INTERVAL = int(os.environ.get("FAILURE_CHECK_INTERVAL", "5"))
ALERT_OFFLINE_INTERVAL = int(os.environ.get("ALERT_OFFLINE_INTERVAL", "1800"))
ALERT_ONLINE_INTERVAL = int(os.environ.get("ALERT_ONLINE_INTERVAL", "0"))
PUSHOVER_USER_KEY = os.environ.get("PUSHOVER_USER_KEY", "")
PUSHOVER_API_TOKEN = os.environ.get("PUSHOVER_API_TOKEN", "")
HEARTBEAT_PORT = int(os.environ.get("HEARTBEAT_PORT", "8080"))
HEARTBEAT_API_KEY = os.environ.get("HEARTBEAT_API_KEY", "")
HEARTBEAT_STALE_SECONDS = int(os.environ.get("HEARTBEAT_STALE_SECONDS", "120"))


# ── Heartbeat state ────────────────────────────────────────────────────────

heartbeat_timestamps = {}
heartbeat_lock = threading.Lock()


# ── Heartbeat HTTP server ──────────────────────────────────────────────────

class HeartbeatHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if HEARTBEAT_API_KEY:
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {HEARTBEAT_API_KEY}":
                self.send_response(401)
                self.end_headers()
                return

        parts = self.path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "heartbeat":
            hb_id = parts[1]
            with heartbeat_lock:
                heartbeat_timestamps[hb_id] = time.time()
            logger.debug(f"Heartbeat received: {hb_id}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def start_heartbeat_server():
    server = HTTPServer(("0.0.0.0", HEARTBEAT_PORT), HeartbeatHandler)
    logger.info(f"Heartbeat server listening on port {HEARTBEAT_PORT}")
    server.serve_forever()


# ── Pushover notification ──────────────────────────────────────────────────

def send_pushover(title, message, priority=0):
    """Send a notification via the Pushover API. Returns True on success."""
    if not PUSHOVER_USER_KEY or not PUSHOVER_API_TOKEN:
        logger.warning("Pushover credentials not configured, skipping notification")
        return False

    data = urllib.parse.urlencode(
        {
            "token": PUSHOVER_API_TOKEN,
            "user": PUSHOVER_USER_KEY,
            "title": title,
            "message": message,
            "priority": priority,
        }
    ).encode("utf-8")

    try:
        req = urllib.request.Request(
            "https://api.pushover.net/1/messages.json", data=data
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                logger.info(f"Pushover notification sent: {title}")
                return True
    except Exception as e:
        logger.error(f"Failed to send Pushover notification: {e}")
    return False


# ── Ping functions ─────────────────────────────────────────────────────────

def ping_icmp(address, timeout=5):
    """ICMP ping using the system ping command. Returns True if reachable."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), address],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        logger.error(f"ICMP ping error for {address}: {e}")
        return False


def ping_tcp(address, timeout=5):
    """TCP connection check. Returns True if a TCP connection can be established.

    Address format: host:port (e.g. 8.8.8.8:53, 1.1.1.1:443).
    Defaults to port 443 if no port specified.
    """
    if ":" in address:
        host, port_str = address.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            host, port = address, 443
    else:
        host, port = address, 443

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, OSError):
        return False


def ping_dns(address, timeout=5):
    """DNS resolution check. Returns True if the hostname resolves successfully."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(address, None)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False


def ping_http(address, timeout=5):
    """HTTP(S) health check. Returns True if the server responds with a non-server-error status."""
    url = (
        address
        if address.startswith(("http://", "https://"))
        else f"https://{address}"
    )
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


def ping_heartbeat(address, timeout=5):
    """Check if a heartbeat has been received recently.

    The address is the heartbeat ID that the sender posts to.
    Returns True if a heartbeat was received within HEARTBEAT_STALE_SECONDS.
    """
    with heartbeat_lock:
        last_seen = heartbeat_timestamps.get(address, 0)
    if last_seen == 0:
        return False
    return (time.time() - last_seen) < HEARTBEAT_STALE_SECONDS


# ── Per-target monitor ─────────────────────────────────────────────────────

PING_FUNCTIONS = {
    "icmp": ping_icmp,
    "tcp": ping_tcp,
    "dns": ping_dns,
    "http": ping_http,
    "heartbeat": ping_heartbeat,
}


def monitor_target(address, name, check_type, stop_event):
    """State machine that monitors a single target and sends alerts."""
    ping_fn = PING_FUNCTIONS[check_type]

    is_online = True
    consecutive_failures = 0
    last_offline_alert = 0.0
    last_online_alert = 0.0

    # For heartbeat targets, allow time for the first heartbeat to arrive
    if check_type == "heartbeat":
        logger.info(
            f"Monitoring {name} ({address}) via heartbeat "
            f"(stale after {HEARTBEAT_STALE_SECONDS}s)"
        )
        logger.info(
            f"Waiting {HEARTBEAT_STALE_SECONDS}s for initial heartbeat from {name}"
        )
        stop_event.wait(HEARTBEAT_STALE_SECONDS)
    else:
        logger.info(f"Monitoring {name} ({address}) via {check_type}")

    while not stop_event.is_set():
        success = ping_fn(address)

        if success:
            if not is_online:
                # ── Recovery ────────────────────────────────────────────
                is_online = True
                consecutive_failures = 0
                logger.info(f"{name} ({address}) is back ONLINE")
                send_pushover(
                    f"{name} - Online",
                    f"{name} ({address}) has recovered and is back online.",
                    priority=0,
                )
                last_online_alert = time.time()
            elif consecutive_failures > 0:
                # Was in failure-confirmation phase but recovered
                logger.info(
                    f"{name} ({address}) recovered during failure confirmation "
                    f"({consecutive_failures}/{FAILURE_THRESHOLD})"
                )
                consecutive_failures = 0
            else:
                # ── Steady online ───────────────────────────────────────
                if ALERT_ONLINE_INTERVAL > 0:
                    now = time.time()
                    if now - last_online_alert >= ALERT_ONLINE_INTERVAL:
                        send_pushover(
                            f"{name} - Online",
                            f"{name} ({address}) is online.",
                            priority=-1,
                        )
                        last_online_alert = now

            stop_event.wait(PING_INTERVAL)

        else:
            consecutive_failures += 1

            if is_online and consecutive_failures < FAILURE_THRESHOLD:
                # ── Failure confirmation phase ──────────────────────────
                logger.warning(
                    f"{name} ({address}) check failed "
                    f"({consecutive_failures}/{FAILURE_THRESHOLD})"
                )
                stop_event.wait(FAILURE_CHECK_INTERVAL)

            elif is_online and consecutive_failures >= FAILURE_THRESHOLD:
                # ── Confirmed offline ───────────────────────────────────
                is_online = False
                logger.error(f"{name} ({address}) is OFFLINE")
                send_pushover(
                    f"{name} - Offline",
                    f"{name} ({address}) is offline after "
                    f"{FAILURE_THRESHOLD} consecutive failed checks.",
                    priority=1,
                )
                last_offline_alert = time.time()
                stop_event.wait(PING_FAIL_INTERVAL)

            else:
                # ── Still offline, periodic re-alert ────────────────────
                now = time.time()
                if (
                    ALERT_OFFLINE_INTERVAL > 0
                    and now - last_offline_alert >= ALERT_OFFLINE_INTERVAL
                ):
                    logger.warning(f"{name} ({address}) is still offline")
                    send_pushover(
                        f"{name} - Still Offline",
                        f"{name} ({address}) remains offline.",
                        priority=0,
                    )
                    last_offline_alert = now

                stop_event.wait(PING_FAIL_INTERVAL)


# ── CSV loader ─────────────────────────────────────────────────────────────

def load_targets(csv_path):
    """Load monitoring targets from a CSV file.

    Expected format: address,name[,type]
    Lines starting with # are treated as comments.
    """
    targets = []
    with open(csv_path, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].strip().startswith("#"):
                continue
            address = row[0].strip()
            name = row[1].strip() if len(row) > 1 and row[1].strip() else address
            check_type = (
                row[2].strip().lower() if len(row) > 2 and row[2].strip() else PING_TYPE
            )
            if check_type not in PING_FUNCTIONS:
                logger.warning(
                    f'Invalid check type "{check_type}" for {address}, '
                    f"defaulting to {PING_TYPE}"
                )
                check_type = PING_TYPE
            targets.append((address, name, check_type))
    return targets


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    logger.info("Pinger starting up")
    logger.info(
        f"Config: interval={PING_INTERVAL}s, fail_interval={PING_FAIL_INTERVAL}s, "
        f"type={PING_TYPE}, threshold={FAILURE_THRESHOLD}, "
        f"fail_check={FAILURE_CHECK_INTERVAL}s, "
        f"offline_alert={ALERT_OFFLINE_INTERVAL}s, "
        f"online_alert={ALERT_ONLINE_INTERVAL}s"
    )

    targets = load_targets(CSV_PATH)
    if not targets:
        logger.error("No targets found in CSV file")
        sys.exit(1)

    logger.info(f"Loaded {len(targets)} target(s)")

    # Start heartbeat server if any targets use heartbeat type
    has_heartbeat = any(t[2] == "heartbeat" for t in targets)
    if has_heartbeat:
        hb_thread = threading.Thread(target=start_heartbeat_server, daemon=True)
        hb_thread.start()

    stop_event = threading.Event()

    def handle_shutdown(signum, frame):
        logger.info("Shutdown signal received")
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    threads = []
    for address, name, check_type in targets:
        t = threading.Thread(
            target=monitor_target,
            args=(address, name, check_type, stop_event),
            daemon=True,
        )
        t.start()
        threads.append(t)

    stop_event.wait()

    for t in threads:
        t.join(timeout=5)

    logger.info("Pinger shut down")


if __name__ == "__main__":
    main()
