"""
ti_loader — populates the threat-intel DynamoDB blacklist from an open-source
IP feed (abuse.ch Feodo Tracker botnet C2 blocklist).

Triggered two ways:
  - EventBridge schedule (rate(12 hours)) keeps the feed fresh.
  - aws_lambda_invocation at terraform apply seeds the table on first deploy.

The feed is plain text, one IPv4 per line, '#'-comment lines ignored. A small
static SEED_IPS set is always written too (tagged source="seed-demo") so the
table is never empty and a smoke test has a deterministic, safe-to-probe target
(192.0.2.0/24 is TEST-NET-1 per RFC 5737 — unroutable, never a real host).

Stdlib + boto3. Runs on python3.13.
"""
from __future__ import annotations

import ipaddress
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import boto3

DDB_TABLE = os.environ["DDB_TABLE"]
FEED_URL = os.environ.get(
    "FEED_URL", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
)
FEED_SOURCE = os.environ.get("FEED_SOURCE", "abuse.ch/feodo")
TTL_DAYS = int(os.environ.get("TTL_DAYS", "14"))

# deterministic, safe demo entries — TEST-NET-1, unroutable. lets smoke tests
# trigger a "node → blacklisted IP" hit without touching a real malicious host.
SEED_IPS = [ip.strip() for ip in os.environ.get(
    "SEED_IPS", "192.0.2.66,192.0.2.123"
).split(",") if ip.strip()]

ddb = boto3.resource("dynamodb").Table(DDB_TABLE)


def fetch_feed(url: str) -> list[str]:
    """Fetch + parse the feed. Returns [] on any network/HTTP error so a feed
    outage degrades to 'seed only' rather than failing the whole load."""
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "cloudguard-dns-ti-loader/1.0"}
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"ti_loader: feed fetch failed ({exc!r}) — seeding demo IPs only")
        return []

    ips = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # .txt is one IP per line; tolerate a .csv variant by taking col 0.
        candidate = line.split(",")[0].strip().strip('"')
        try:
            if ipaddress.ip_address(candidate).version == 4:
                ips.append(candidate)
        except ValueError:
            continue
    return ips


def lambda_handler(event, context):
    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    ttl = int(time.time()) + TTL_DAYS * 86400

    feed_ips = fetch_feed(FEED_URL)

    rows = {ip: FEED_SOURCE for ip in feed_ips}
    for ip in SEED_IPS:        # seed entries never expire-out of a fresh load
        rows.setdefault(ip, "seed-demo")

    written = 0
    with ddb.batch_writer(overwrite_by_pkeys=["ip"]) as batch:
        for ip, source in rows.items():
            batch.put_item(Item={
                "ip": ip,
                "source": source,
                "feed_url": FEED_URL,
                "last_seen": now_iso,
                "ttl": ttl,
            })
            written += 1

    print(
        f"ti_loader: feed={len(feed_ips)} seed={len(SEED_IPS)} "
        f"written={written} source={FEED_SOURCE}"
    )
    return {
        "feed_count": len(feed_ips),
        "seed_count": len(SEED_IPS),
        "written": written,
        "source": FEED_SOURCE,
    }
