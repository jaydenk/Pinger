# Pinger

Lightweight network monitoring tool that checks host availability via ICMP or HTTP and sends alerts through [Pushover](https://pushover.net/).

## Quick Start

1. Copy `env.example` to `.env` and fill in your Pushover credentials.
2. Edit `targets.csv` with the hosts you want to monitor.
3. Run with Docker Compose:

```bash
docker compose up -d
```

## Environment Variables

### Required

| Variable | Description |
|---|---|
| `PUSHOVER_USER_KEY` | Your Pushover user key. Without this, no notifications are sent. |
| `PUSHOVER_API_TOKEN` | Your Pushover application API token. Without this, no notifications are sent. |

### Optional

| Variable | Default | Description |
|---|---|---|
| `CSV_PATH` | `./targets.csv` | Host path to the CSV file containing monitoring targets. Mounted into the container at `/app/targets.csv`. |
| `PING_TYPE` | `icmp` | Default check type for targets that don't specify one. Either `icmp` or `http`. |
| `PING_INTERVAL` | `120` | Seconds between checks when a target is online. |
| `PING_FAIL_INTERVAL` | `60` | Seconds between checks after a target is confirmed offline. |
| `FAILURE_THRESHOLD` | `12` | Number of consecutive failed checks before a target is considered offline. |
| `FAILURE_CHECK_INTERVAL` | `5` | Seconds between checks during the failure confirmation phase (before the threshold is reached). |
| `ALERT_OFFLINE_INTERVAL` | `1800` | Seconds between repeated offline alerts. Set to `0` to only alert on the initial failure. |
| `ALERT_ONLINE_INTERVAL` | `0` | Seconds between periodic online status alerts. Set to `0` to only alert on recovery (default). |

### How Failure Detection Works

When a check fails, Pinger enters a rapid confirmation phase — it re-checks every `FAILURE_CHECK_INTERVAL` seconds (default 5s) up to `FAILURE_THRESHOLD` times (default 12). This means a target must be unreachable for roughly 60 seconds before it is declared offline and an alert is sent. Once offline, checks slow down to every `PING_FAIL_INTERVAL` seconds.

## Targets CSV

The file at `CSV_PATH` defines what to monitor. Format:

```
address,name,type
```

- **address** — IP address or hostname (for HTTP checks, can be a full URL).
- **name** — Friendly display name used in alerts. Falls back to the address if omitted.
- **type** *(optional)* — `icmp` or `http`. Falls back to the `PING_TYPE` environment variable if omitted.

Lines starting with `#` are treated as comments.

Example:

```csv
8.8.8.8,Google DNS
1.1.1.1,Cloudflare DNS
https://example.com,Example Site,http
192.168.1.1,Router,icmp
```
