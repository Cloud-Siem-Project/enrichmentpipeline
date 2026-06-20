"""
flow_detector — CWL subscription target for /cloudguard-dns/<env>/vpc-flow.

For each VPC flow-log record, check srcaddr + dstaddr against the threat-intel
DynamoDB blacklist. On a hit (any ENI in the VPC talking to/from a known-bad
IP — your EC2 nodes today, and any future VPC-attached lambda/fargate task),
publish a HIGH-severity event to the custom EventBridge bus. The existing
pipeline then persists it (DDB + S3), alerts (SNS), and blocks the bad IP
(WAFv2 IPSet) — no other wiring needed.

The blacklist is scanned into an in-memory set once per cold start and cached
for BLACKLIST_TTL_SECS, so we don't do a DDB read per flow record.

Stdlib + boto3. python3.13.
"""
from __future__ import annotations

import base64
import gzip
import json
import os
import time

import boto3

DDB_TABLE = os.environ["DDB_TABLE"]
EB_BUS_NAME = os.environ["EB_BUS_NAME"]
EB_SOURCE = "cloudguard-dns.flow-detector"
BLACKLIST_TTL_SECS = int(os.environ.get("BLACKLIST_TTL_SECS", "300"))

ddb = boto3.client("dynamodb")
events_client = boto3.client("events")

# VPC flow-log DEFAULT format (version 2), space-separated:
#  version account-id interface-id srcaddr dstaddr srcport dstport
#  protocol packets bytes start end action log-status
F_IFACE = 2
F_SRCADDR = 3
F_DSTADDR = 4
F_SRCPORT = 5
F_DSTPORT = 6
F_PROTO = 7
F_ACTION = 12
MIN_FIELDS = 14

PROTO_NAMES = {"6": "TCP", "17": "UDP", "1": "ICMP"}
HTTP_PORTS = {"80", "443", "8080", "8443"}

# module-global cache, survives warm invocations
_blacklist: set[str] = set()
_loaded_at = 0.0


def load_blacklist(force: bool = False) -> set[str]:
    global _blacklist, _loaded_at
    now = time.time()
    if not force and _blacklist and (now - _loaded_at) < BLACKLIST_TTL_SECS:
        return _blacklist

    ips: set[str] = set()
    paginator = ddb.get_paginator("scan")
    for page in paginator.paginate(TableName=DDB_TABLE, ProjectionExpression="ip"):
        for item in page.get("Items", []):
            v = item.get("ip", {}).get("S")
            if v:
                ips.add(v)

    _blacklist = ips
    _loaded_at = now
    return _blacklist


def decode_cwl_payload(event: dict) -> dict:
    """CWL subscription events: gzip + base64 under .awslogs.data."""
    raw = event["awslogs"]["data"]
    return json.loads(gzip.decompress(base64.b64decode(raw)))


def lambda_handler(event, context):
    blacklist = load_blacklist()
    if not blacklist:
        return {"hits": 0, "note": "empty blacklist"}

    payload = decode_cwl_payload(event)
    published = 0

    for le in payload.get("logEvents", []):
        fields = le.get("message", "").split()
        if len(fields) < MIN_FIELDS:
            continue

        src = fields[F_SRCADDR]
        dst = fields[F_DSTADDR]

        # egress (node → bad IP) takes precedence over ingress.
        if dst in blacklist:
            hit_ip, direction = dst, "egress"
        elif src in blacklist:
            hit_ip, direction = src, "ingress"
        else:
            continue

        proto = PROTO_NAMES.get(fields[F_PROTO], fields[F_PROTO])
        dport = fields[F_DSTPORT]
        conn_type = "HTTP/S" if dport in HTTP_PORTS else proto

        detail = {
            "severity": "HIGH",
            "score": 10,
            # block_ip reads `blacklisted_ip` first → we block the bad host,
            # never our own node, regardless of direction.
            "blacklisted_ip": hit_ip,
            "src_addr": src,
            "dst_addr": dst,
            "src_port": fields[F_SRCPORT],
            "dst_port": dport,
            "protocol": proto,
            "conn_type": conn_type,
            "direction": direction,
            "action": fields[F_ACTION],
            "interface_id": fields[F_IFACE],
            "log_timestamp": le.get("timestamp"),
            "intel_source": "abuse.ch/feodo",
            "signals": [
                f"threat_intel_hit:{hit_ip}",
                f"direction:{direction}",
                f"proto:{conn_type}:{dport}",
            ],
        }

        events_client.put_events(Entries=[{
            "Source": EB_SOURCE,
            "DetailType": "flow.threat-intel-hit",
            "Detail": json.dumps(detail),
            "EventBusName": EB_BUS_NAME,
        }])
        published += 1

    if published:
        print(f"flow_detector: published={published} blacklist_size={len(blacklist)}")
    return {"hits": published, "blacklist_size": len(blacklist)}
