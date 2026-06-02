#!/usr/bin/env python3
"""
mock_dns_query.py — One-off helper to build AWS Lambda Test tab payloads
for dns_detector/lambda_function.py.

DOES NOT call AWS — hiçbir şey deploy etmez, hiçbir şeye istek atmaz.

Kullanım:
  python3 mock_dns_query.py --dry-run
  python3 mock_dns_query.py --dry-run malicious.xyz google.com
  python3 mock_dns_query.py --print-payload
  python3 mock_dns_query.py --print-payload xKj9mQpRtVwBcDe.tk
"""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import math
import sys
import time
import uuid
from collections import Counter

# ── score_query + shannon_entropy — lambda_function.py'den birebir kopyalandı ─
# (boto3 gerektirmeden local çalışabilmesi için import yerine inline tutuyoruz)

SUSPICIOUS_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "ru", "cn", "su",
    "click", "loan", "work", "country", "stream", "download",
}
LABEL_LEN_MED = 30
LABEL_LEN_HIGH = 50
ENTROPY_MED    = 3.5
ENTROPY_HIGH   = 4.0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def score_query(qname: str) -> dict:
    qname_clean = qname.rstrip(".")
    parts = qname_clean.split(".")
    if len(parts) < 2:
        return {"severity": "LOW", "score": 0, "signals": [],
                "entropy": 0.0, "label_length": 0, "tld": ""}

    label   = parts[0]
    tld     = parts[-1].lower()
    entropy = shannon_entropy(label)
    length  = len(label)
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

    severity = "HIGH" if score >= 5 else ("MED" if score >= 2 else "LOW")
    return {"severity": severity, "score": score, "signals": signals,
            "entropy": round(entropy, 3), "label_length": length, "tld": tld}

# ── varsayılan domain örnekleri ────────────────────────────────────────────────
DEFAULT_DOMAINS = [
    "google.com",                           # LOW  — sıradan, temiz domain
    "update.xyz",                           # MED  — şüpheli TLD (.xyz) → +2
    "aHR0cHM6Ly9ldmlsLmNvbS9zdGVhbA.tk",  # HIGH — şüpheli TLD + uzun label + yüksek entropi
]

MOCK_SRCADDR    = "10.0.1.99"
MOCK_VPC_ID     = "vpc-mock0001"
MOCK_ACCOUNT_ID = "000000000000"

# ── ANSI renk sabitleri ────────────────────────────────────────────────────────
_COLOR = {"HIGH": "\033[91m", "MED": "\033[93m", "LOW": "\033[92m"}
_RESET = "\033[0m"


# ── CWL payload builder ────────────────────────────────────────────────────────

def _build_cwl_event(domains: list[str]) -> dict:
    """
    decode_cwl_payload'ın çözebileceği formatta bir CloudWatch Logs
    subscription event'i üretir: {"awslogs": {"data": <gzip+base64>}}
    """
    ts_ms = int(time.time() * 1000)
    log_events = [
        {
            "id": str(uuid.uuid4()),
            "timestamp": ts_ms,
            "message": json.dumps({
                "query_name":  domain,
                "query_type":  "A",
                "srcaddr":     MOCK_SRCADDR,
                "vpc_id":      MOCK_VPC_ID,
                "account_id":  MOCK_ACCOUNT_ID,
            }),
        }
        for domain in domains
    ]

    cwl_json = {
        "messageType":         "DATA_MESSAGE",
        "owner":               MOCK_ACCOUNT_ID,
        "logGroup":            "/cloudguard-dns/dev/route53-resolver",
        "logStream":           "mock-stream",
        "subscriptionFilters": ["mock-filter"],
        "logEvents":           log_events,
    }

    compressed = gzip.compress(json.dumps(cwl_json).encode("utf-8"))
    encoded    = base64.b64encode(compressed).decode("utf-8")
    return {"awslogs": {"data": encoded}}


# ── modlar ─────────────────────────────────────────────────────────────────────

def cmd_dry_run(domains: list[str]) -> None:
    print(f"\n{'Domain':<50}  {'Sev':<5}  {'Score':<6}  Sinyaller")
    print("-" * 95)
    for domain in domains:
        r      = score_query(domain)
        sev    = r["severity"]
        color  = _COLOR.get(sev, "")
        sigs   = ", ".join(r["signals"]) or "—"
        print(
            f"{domain:<50}  "
            f"{color}{sev:<5}{_RESET}  "
            f"{r['score']:<6}  "
            f"{sigs}  "
            f"(entropy={r['entropy']}, label_len={r['label_length']})"
        )
    print()


def cmd_print_payload(domains: list[str]) -> None:
    payload = _build_cwl_event(domains)
    print(json.dumps(payload, indent=2))


# ── main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="dns_detector Lambda için mock CWL test payload'ı üretir."
    )
    parser.add_argument(
        "domains",
        nargs="*",
        default=DEFAULT_DOMAINS,
        metavar="DOMAIN",
        help="Test edilecek domain isimleri (boş bırakılırsa LOW/MED/HIGH örnekleri kullanılır)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Her domain için score_query sonucunu göster (AWS çağrısı yok)",
    )
    parser.add_argument(
        "--print-payload",
        action="store_true",
        help="AWS Lambda Test sekmesine yapıştırılabilir gzip+base64 JSON'u yazdır",
    )
    args = parser.parse_args()

    if not args.dry_run and not args.print_payload:
        parser.print_help()
        sys.exit(0)

    if args.dry_run:
        cmd_dry_run(args.domains)

    if args.print_payload:
        cmd_print_payload(args.domains)


if __name__ == "__main__":
    main()
