"""
Seçilen bir domain/URL için sahte bir dns.scored eventi EventBridge'e gönderir.
Step Functions tetiklenir → persist Lambda DynamoDB'ye yazar → Dashboard'da görünür.

Kullanım:
  python inject_mock_event.py --domain malicious.xyz --severity HIGH --bus cloudguard-dns-bus
  python inject_mock_event.py --domain google.com   --severity MED  --bus cloudguard-dns-bus
"""
from __future__ import annotations

import argparse
import json
import math
import uuid
from collections import Counter
from datetime import datetime, timezone

import boto3


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def build_detail(domain: str, severity: str) -> dict:
    domain_clean = domain.rstrip(".")
    parts = domain_clean.split(".")
    label = parts[0] if parts else domain_clean
    tld = parts[-1].lower() if len(parts) > 1 else ""
    entropy = shannon_entropy(label)

    return {
        "query_name": domain_clean,
        "query_type": "A",
        "src_addr": "10.0.1.99",
        "vpc_id": "vpc-mock0001",
        "account_id": "000000000000",
        "severity": severity.upper(),
        "score": {"HIGH": 5, "MED": 2, "LOW": 0}.get(severity.upper(), 2),
        "signals": ["mock_inject"],
        "entropy": round(entropy, 3),
        "label_length": len(label),
        "tld": tld,
        "log_timestamp": int(datetime.now(timezone.utc).timestamp() * 1000),
    }


def main():
    parser = argparse.ArgumentParser(description="Mock DNS event injector")
    parser.add_argument("--domain",   required=True,  help="Sorgu yapılacak domain, ör: malicious.xyz")
    parser.add_argument("--severity", default="MED",  help="LOW | MED | HIGH  (varsayılan: MED)")
    parser.add_argument("--bus",      required=True,  help="EventBridge bus adı, ör: cloudguard-dns-bus")
    parser.add_argument("--region",   default="eu-central-1")
    args = parser.parse_args()

    detail = build_detail(args.domain, args.severity)

    client = boto3.client("events", region_name=args.region)
    resp = client.put_events(Entries=[{
        "Source":       "cloudguard-dns.dns-detector",
        "DetailType":   "dns.scored",
        "EventBusName": args.bus,
        "Detail":       json.dumps(detail),
    }])

    failed = resp.get("FailedEntryCount", 0)
    if failed:
        print(f"HATA: {failed} entry gönderilemedi")
        print(json.dumps(resp["Entries"], indent=2))
    else:
        print(f"Gönderildi!")
        print(f"  Domain  : {args.domain}")
        print(f"  Severity: {args.severity.upper()}")
        print(f"  Bus     : {args.bus}")
        print(f"  Detail  : {json.dumps(detail, indent=4)}")
        print()
        print("Dashboard'da birkaç saniye içinde görünmeli → GET /api/events")


if __name__ == "__main__":
    main()
