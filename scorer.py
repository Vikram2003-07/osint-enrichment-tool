"""
scorer.py
---------
Combines results from every API into a single 0‑100 risk score
and decides whether the IOC is a TRUE POSITIVE.

Scoring weights (tunable):
  VirusTotal malicious ratio  → 40 %
  VirusTotal suspicious ratio → 10 %
  AbuseIPDB confidence score  → 40 %
  VT community reputation     → 10 %
"""


def calculate_risk_score(vt: dict, abuse: dict) -> int:
    """
    Parameters
    ----------
    vt    : dict returned by VirusTotalClient.lookup()
    abuse : dict returned by AbuseIPDBClient.lookup()

    Returns
    -------
    int : 0‑100 composite risk score
    """

    # ── VirusTotal malicious ratio (0‑100) ──────────────────────────
    total_engines = (
        vt["malicious"] + vt["suspicious"]
        + vt["harmless"] + vt["undetected"]
    )
    if total_engines > 0:
        vt_mal_ratio = (vt["malicious"] / total_engines) * 100
        vt_sus_ratio = (vt["suspicious"] / total_engines) * 100
    else:
        vt_mal_ratio = 0.0
        vt_sus_ratio = 0.0

    # ── VT community reputation (ranges roughly –100 … +100) ───────
    # Negative reputation = bad → we invert and clamp to 0‑100
    rep = vt.get("reputation", 0)
    vt_rep_score = max(0, min(100, 50 - rep))  # rep ‑50 → score 100

    # ── AbuseIPDB confidence (already 0‑100) ────────────────────────
    abuse_score = abuse.get("abuse_confidence", 0)

    # ── Weighted combination ────────────────────────────────────────
    composite = (
        vt_mal_ratio * 0.40
        + vt_sus_ratio * 0.10
        + abuse_score * 0.40
        + vt_rep_score * 0.10
    )

    return int(min(100, max(0, round(composite))))


def is_true_positive(score: int, threshold: int) -> bool:
    """Flag as True Positive when the score meets or exceeds the threshold."""
    return score >= threshold


def severity_label(score: int) -> str:
    """Human‑readable severity band."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"