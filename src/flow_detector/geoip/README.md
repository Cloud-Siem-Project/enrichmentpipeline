# GeoIP / ASN data

Bundled databases used by flow_detector to enrich public source IPs:

- `dbip-country.mmdb` — DB-IP IP-to-Country Lite
- `dbip-asn.mmdb`     — DB-IP IP-to-ASN Lite

Source: https://db-ip.com/db/lite.php — licensed CC BY 4.0 (© db-ip.com).
Snapshot: 2026-06. Refresh monthly from the same URLs and re-`terraform apply`.

The reader is a vendored pure-python copy of `maxminddb` (../maxminddb/, MIT),
with the C extension stripped so the lambda zip needs no compiled deps.
