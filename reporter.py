"""
reporter.py
-----------
Pretty‑print results to the terminal and export a CSV report.
"""

import csv
import os
from datetime import datetime

from colorama import Fore, Style, init as colorama_init
from prettytable import PrettyTable

colorama_init(autoreset=True)


# ── Colour helpers ──────────────────────────────────────────────────
def _colour_score(score: int) -> str:
    if score >= 80:
        return f"{Fore.RED}{Style.BRIGHT}{score}{Style.RESET_ALL}"
    if score >= 60:
        return f"{Fore.LIGHTYELLOW_EX}{score}{Style.RESET_ALL}"
    if score >= 40:
        return f"{Fore.YELLOW}{score}{Style.RESET_ALL}"
    return f"{Fore.GREEN}{score}{Style.RESET_ALL}"


def _colour_verdict(is_tp: bool) -> str:
    if is_tp:
        return f"{Fore.RED}{Style.BRIGHT}⚠  TRUE POSITIVE{Style.RESET_ALL}"
    return f"{Fore.GREEN}✔  Benign{Style.RESET_ALL}"


# ── Terminal Banner ─────────────────────────────────────────────────
def print_banner():
    banner = rf"""
{Fore.CYAN}{Style.BRIGHT}
  ╔═══════════════════════════════════════════════════════════╗
  ║          OSINT  ENRICHMENT  AUTOMATION  TOOL              ║
  ║          ──────────────────────────────────               ║
  ║   Automate IOC lookups · Risk Scoring · True Positive     ║
  ║   Flagging across VirusTotal, AbuseIPDB & GeoIP           ║
  ╚═══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)


# ── Per‑IOC detail block ────────────────────────────────────────────
def print_ioc_result(ioc: str, vt: dict, abuse: dict, geo: dict,
                     score: int, severity: str, is_tp: bool):
    """Print a rich detail card for one IOC."""
    print(f"\n{'═' * 62}")
    print(f"  IOC : {Fore.WHITE}{Style.BRIGHT}{ioc}{Style.RESET_ALL}")
    print(f"{'─' * 62}")

    # Geo
    print(f"  📍 Location    : {geo['city']}, {geo['country']}")
    print(f"  🌐 ISP / Org   : {geo['isp']} / {geo['org']}")

    # VirusTotal
    print(f"  🛡  VT Malicious  : {vt['malicious']}")
    print(f"  🛡  VT Suspicious : {vt['suspicious']}")
    print(f"  🛡  VT Harmless   : {vt['harmless']}")
    print(f"  🛡  VT Reputation : {vt['reputation']}")

    # AbuseIPDB
    print(f"  🔴 Abuse Score    : {abuse['abuse_confidence']}%")
    print(f"  📝 Total Reports  : {abuse['total_reports']}")

    # Composite
    print(f"  ⚡ Risk Score     : {_colour_score(score)} / 100")
    print(f"  🏷  Severity      : {severity}")
    print(f"  🚩 Verdict        : {_colour_verdict(is_tp)}")

    # Errors
    for label, src in [("VT", vt), ("Abuse", abuse), ("Geo", geo)]:
        if src.get("error"):
            print(f"  ⚠  {label} Error: {Fore.YELLOW}{src['error']}{Style.RESET_ALL}")

    print(f"{'═' * 62}")


# ── Summary table ───────────────────────────────────────────────────
def print_summary_table(results: list):
    """Print a compact summary table at the end of the run."""
    table = PrettyTable()
    table.field_names = [
        "IOC", "Country", "VT Mal", "Abuse %",
        "Risk Score", "Severity", "Verdict"
    ]
    table.align = "l"

    for r in results:
        verdict = "TRUE POS" if r["is_true_positive"] else "Benign"
        table.add_row([
            r["ioc"],
            r["geo"]["country"],
            r["vt"]["malicious"],
            r["abuse"]["abuse_confidence"],
            r["score"],
            r["severity"],
            verdict,
        ])

    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 62}")
    print("  📊  SUMMARY REPORT")
    print(f"{'=' * 62}{Style.RESET_ALL}")
    print(table)

    # Stats
    total = len(results)
    tp = sum(1 for r in results if r["is_true_positive"])
    print(f"\n  Total IOCs analysed : {total}")
    print(f"  True Positives      : {Fore.RED}{tp}{Style.RESET_ALL}")
    print(f"  Benign              : {Fore.GREEN}{total - tp}{Style.RESET_ALL}")


# ── CSV Export ──────────────────────────────────────────────────────
def export_csv(results: list, output_dir: str = ".") -> str:
    """Write results to a timestamped CSV and return the file path."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"output_report_{timestamp}.csv")

    fieldnames = [
        "ioc", "country", "city", "isp", "org",
        "vt_malicious", "vt_suspicious", "vt_harmless", "vt_reputation",
        "abuse_confidence", "abuse_total_reports",
        "risk_score", "severity", "verdict",
    ]

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "ioc":                  r["ioc"],
                "country":              r["geo"]["country"],
                "city":                 r["geo"]["city"],
                "isp":                  r["geo"]["isp"],
                "org":                  r["geo"]["org"],
                "vt_malicious":         r["vt"]["malicious"],
                "vt_suspicious":        r["vt"]["suspicious"],
                "vt_harmless":          r["vt"]["harmless"],
                "vt_reputation":        r["vt"]["reputation"],
                "abuse_confidence":     r["abuse"]["abuse_confidence"],
                "abuse_total_reports":  r["abuse"]["total_reports"],
                "risk_score":           r["score"],
                "severity":             r["severity"],
                "verdict":              "TRUE POSITIVE" if r["is_true_positive"] else "Benign",
            })

    print(f"\n  📁 CSV report saved → {Fore.CYAN}{filename}{Style.RESET_ALL}")
    return filename