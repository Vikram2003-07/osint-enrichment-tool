#!/usr/bin/env python3
"""
osint_enrichment.py
===================
OSINT Enrichment Automation Tool — main entry point.

Usage
-----
    python osint_enrichment.py                        # default: iocs.txt
    python osint_enrichment.py -f my_indicators.txt
    python osint_enrichment.py -f iocs.csv --threshold 70
    python osint_enrichment.py --help
"""

import argparse
import csv
import os
import sys
import time

from dotenv import load_dotenv

from api_clients import (
    VirusTotalClient,
    AbuseIPDBClient,
    GeoIPClient,
    is_ip_address,
)
from scorer import calculate_risk_score, is_true_positive, severity_label
from reporter import (
    print_banner,
    print_ioc_result,
    print_summary_table,
    export_csv,
)


# ────────────────────────────────────────────────────────────────────
#  IOC loader — supports .txt (one per line) and .csv (column "ioc")
# ────────────────────────────────────────────────────────────────────
def load_iocs(filepath: str) -> list:
    """Read IOCs from a .txt or .csv file and return a deduplicated list."""
    iocs = []

    if not os.path.isfile(filepath):
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    ext = os.path.splitext(filepath)[1].lower()

    if ext == ".csv":
        with open(filepath, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Accept column header "ioc", "ip", "url", or "indicator"
                for col in ("ioc", "ip", "url", "indicator"):
                    if col in row and row[col].strip():
                        iocs.append(row[col].strip())
                        break
    else:
        # Plain text — one IOC per line
        with open(filepath, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    iocs.append(stripped)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for i in iocs:
        if i not in seen:
            seen.add(i)
            unique.append(i)

    return unique


# ────────────────────────────────────────────────────────────────────
#  CLI argument parser
# ────────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="OSINT Enrichment Automation Tool — "
                    "Bulk IOC reputation lookup & risk scoring."
    )
    parser.add_argument(
        "-f", "--file",
        default="iocs.txt",
        help="Path to IOC input file (.txt or .csv). Default: iocs.txt",
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=None,
        help="Risk score threshold for true‑positive flagging (0‑100). "
             "Overrides the value in .env.",
    )
    parser.add_argument(
        "-o", "--output",
        default=".",
        help="Directory for the CSV report. Default: current directory.",
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        help="Skip CSV export; print to terminal only.",
    )
    return parser.parse_args()


# ────────────────────────────────────────────────────────────────────
#  Main pipeline
# ────────────────────────────────────────────────────────────────────
def main():
    # 1. Load environment & CLI args
    load_dotenv()
    args = parse_args()

    vt_key    = os.getenv("VIRUSTOTAL_API_KEY", "")
    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
    geo_key   = os.getenv("IPGEO_API_KEY", "")
    threshold = args.threshold or int(os.getenv("RISK_THRESHOLD", 50))

    # Validate keys
    missing = []
    if not vt_key:
        missing.append("VIRUSTOTAL_API_KEY")
    if not abuse_key:
        missing.append("ABUSEIPDB_API_KEY")
    if not geo_key:
        missing.append("IPGEO_API_KEY")
    if missing:
        print(f"[!] Missing API keys in .env: {', '.join(missing)}")
        sys.exit(1)

    # 2. Initialise API clients
    vt_client    = VirusTotalClient(vt_key)
    abuse_client = AbuseIPDBClient(abuse_key)
    geo_client   = GeoIPClient(geo_key)

    # 3. Load IOCs
    iocs = load_iocs(args.file)
    if not iocs:
        print("[!] No IOCs found in the input file.")
        sys.exit(1)

    # 4. Show banner
    print_banner()
    print(f"  ⏳ Loaded {len(iocs)} IOC(s) from {args.file}")
    print(f"  🎯 True‑Positive threshold: {threshold}/100\n")

    # 5. Enrich each IOC
    results = []
    for idx, ioc in enumerate(iocs, 1):
        print(f"  [{idx}/{len(iocs)}] Querying: {ioc} …")

        vt_data    = vt_client.lookup(ioc)
        abuse_data = abuse_client.lookup(ioc)
        geo_data   = geo_client.lookup(ioc)

        score    = calculate_risk_score(vt_data, abuse_data)
        sev      = severity_label(score)
        tp_flag  = is_true_positive(score, threshold)

        print_ioc_result(ioc, vt_data, abuse_data, geo_data,
                         score, sev, tp_flag)

        results.append({
            "ioc":               ioc,
            "vt":                vt_data,
            "abuse":             abuse_data,
            "geo":               geo_data,
            "score":             score,
            "severity":          sev,
            "is_true_positive":  tp_flag,
        })

        # Respect free‑tier rate limits (VT = 4 req/min)
        if idx < len(iocs):
            time.sleep(15)

    # 6. Summary & export
    print_summary_table(results)

    if not args.no_csv:
        export_csv(results, args.output)

    print(f"\n  ✅ Done — {len(results)} IOC(s) enriched.\n")


if __name__ == "__main__":
    main()