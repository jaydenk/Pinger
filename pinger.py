#!/usr/bin/env python3
"""Pinger - Lightweight network monitoring with Pushover alerts."""

import csv
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

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


# ── Per-target monitor ─────────────────────────────────────────────────────

def monitor_target(address, name, check_type, stop_event):
    """State machine that monitors a single target and sends alerts."""
    ping_fn = ping_http if check_type == "http" else ping_icmp

    is_online = True
    consecutive_failures = 0
    last_offline_alert = 0.0
    last_online_alert = 0.0

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
            if check_type not in ("icmp", "http"):
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
