"""
dns_detector — CWL subscription target for /cloudguard-dns/<env>/route53-resolver.

For each DNS query record:
  - Compute Shannon entropy on the leftmost label
  - Score the TLD against a static "suspicious" list
  - Score label length (DNS tunneling often uses long subdomains)
  - Combine into a severity (LOW / MED / HIGH)
  - Publish a scored event to the custom EventBridge bus

Stdlib only. Runs on python3.13 lambda runtime (PEP 604 syntax fine there).
"""
from __future__ import annotations

import base64
import gzip
import json
import math
import os
from collections import Counter

import boto3

EB_BUS_NAME = os.environ["EB_BUS_NAME"]
EB_SOURCE = "cloudguard-dns.dns-detector"

events_client = boto3.client("events")

# TLDs commonly abused by commodity malware + DGAs (non-exhaustive).
# kept here as a constant so we can iterate later without re-deploying anything else.
SUSPICIOUS_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "ru", "cn", "su",
    "click", "loan", "work", "country", "stream", "download", "zip"
}

# Length thresholds for the leftmost label. DNS tunneling shoves data
# into long subdomains; "normal" sites rarely exceed 30 chars.
LABEL_LEN_MED = 30
LABEL_LEN_HIGH = 50

# Entropy thresholds. English-ish domains usually <3.5 bits/char.
# DGA-generated noise tends to 3.8+.
ENTROPY_MED = 3.5
ENTROPY_HIGH = 4.0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def score_query(qname: str) -> dict:
    """Returns {severity, score, signals[]} for one DNS query name."""
    qname_clean = qname.rstrip(".")
    parts = qname_clean.split(".")
    if len(parts) < 2:
        return {"severity": "LOW", "score": 0, "signals": []}

    label = parts[0]
    tld = parts[-1].lower()

    entropy = shannon_entropy(label)
    length = len(label)

    signals: list[str] = []
    score = 0

    if tld in SUSPICIOUS_TLDS:
        signals.append(f"suspicious_tld:{tld}")
        score += 2

    if length >= LABEL_LEN_HIGH:
        signals.append(f"label_len_high:{length}")
        score += 3
    elif length >= LABEL_LEN_MED:
        signals.append(f"label_len_med:{length}")
        score += 1

    if entropy >= ENTROPY_HIGH:
        signals.append(f"entropy_high:{entropy:.2f}")
        score += 3
    elif entropy >= ENTROPY_MED:
        signals.append(f"entropy_med:{entropy:.2f}")
        score += 1

    if score >= 5:
        severity = "HIGH"
    elif score >= 2:
        severity = "MED"
    else:
        severity = "LOW"

    return {
        "severity": severity,
        "score": score,
        "signals": signals,
        "entropy": round(entropy, 3),
        "label_length": length,
        "tld": tld,
    }


def decode_cwl_payload(event: dict) -> dict:
    """CWL subscription events come gzipped + base64-encoded under .awslogs.data."""
    raw = event["awslogs"]["data"]
    compressed = base64.b64decode(raw)
    decompressed = gzip.decompress(compressed)
    return json.loads(decompressed)


def parse_query_record(message: str) -> dict | None:
    """
    Route53 resolver query logs are JSON. Example fields:
      query_name, query_type, query_class, srcaddr, srcport, vpc_id, account_id, ...
    """
    try:
        return json.loads(message)
    except json.JSONDecodeError:
        return None


def lambda_handler(event, context):
    payload = decode_cwl_payload(event)
    log_events = payload.get("logEvents", [])

    published = 0
    suppressed = 0

    for le in log_events:
        rec = parse_query_record(le.get("message", ""))
        if not rec:
            continue

        qname = rec.get("query_name", "")
        if not qname:
            continue

        scoring = score_query(qname)

        # Suppress LOW-severity to keep the bus signal-to-noise high. We still
        # have the raw log in CWL if we ever need to backfill.
        if scoring["severity"] == "LOW":
            suppressed += 1
            continue

        detail = {
            "query_name": qname,
            "query_type": rec.get("query_type"),
            "src_addr": rec.get("srcaddr"),
            "vpc_id": rec.get("vpc_id"),
            "account_id": rec.get("account_id"),
            "log_timestamp": le.get("timestamp"),
            **scoring,
        }

        events_client.put_events(
            Entries=[{
                "Source": EB_SOURCE,
                "DetailType": "dns.scored",
                "Detail": json.dumps(detail),
                "EventBusName": EB_BUS_NAME,
            }]
        )
        published += 1

    return {"published": published, "suppressed": suppressed}
