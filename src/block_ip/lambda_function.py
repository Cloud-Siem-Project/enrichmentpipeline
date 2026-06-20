"""
block_ip — SFN target. Adds the offending IP to a WAFv2 IPSet so future
edge traffic can be blocked (once the IPSet is attached to a WebACL).

Input shape (passed by SFN from the dns.scored event detail):
    {
      "detail": {
        "src_addr": "1.2.3.4",
        "query_name": "...",
        "severity": "HIGH"
      },
      ...
    }

WAFv2 UpdateIPSet requires the current LockToken (optimistic concurrency).
This lambda fetches it, appends "<ip>/32" if not already present, and writes
back. If the write loses the race it raises — SFN's retry policy will pick
it up.
"""
from __future__ import annotations

import ipaddress
import os

import boto3

IPSET_NAME = os.environ["IPSET_NAME"]
IPSET_ID = os.environ["IPSET_ID"]
IPSET_SCOPE = os.environ.get("IPSET_SCOPE", "REGIONAL")

wafv2 = boto3.client("wafv2")


def coerce_to_cidr(addr: str) -> str | None:
    """Accept '1.2.3.4' or '1.2.3.4/32'. Return canonical /32, or None."""
    try:
        ip = ipaddress.ip_network(addr.strip(), strict=False)
    except (ValueError, TypeError):
        return None
    if ip.version != 4:
        return None  # WAFv2 has separate v6 IPSets; v4 only here.
    return str(ip) if "/" in addr else f"{ip.network_address}/32"


def lambda_handler(event, context):
    detail = event.get("detail", {}) if isinstance(event, dict) else {}
    # threat-intel hits carry the offending host in `blacklisted_ip` — block that,
    # not our own node's src. dns.scored events have no such field and fall back
    # to src_addr (unchanged behavior).
    raw = detail.get("blacklisted_ip") or detail.get("src_addr") or detail.get("srcaddr")
    cidr = coerce_to_cidr(raw or "")

    if not cidr:
        return {"skipped": True, "reason": f"no valid src ip: {raw!r}"}

    # WAFv2 rejects private/loopback in some configs, but the IPSet itself
    # accepts them. We add anyway — the WebACL attachment (future) is where
    # filtering matters.
    current = wafv2.get_ip_set(Name=IPSET_NAME, Id=IPSET_ID, Scope=IPSET_SCOPE)
    addrs = list(current["IPSet"]["Addresses"])
    lock_token = current["LockToken"]

    if cidr in addrs:
        return {"added": False, "cidr": cidr, "size": len(addrs), "reason": "already present"}

    addrs.append(cidr)
    wafv2.update_ip_set(
        Name=IPSET_NAME,
        Id=IPSET_ID,
        Scope=IPSET_SCOPE,
        Addresses=addrs,
        LockToken=lock_token,
    )

    return {"added": True, "cidr": cidr, "size": len(addrs)}
