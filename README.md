# 🔍 OSINT Enrichment Automation Tool

> Turn a **20-minute manual IOC lookup** into a **5-second automated** workflow.

## Features

| Feature | Description |
|---|---|
| Multi-API Enrichment | VirusTotal + AbuseIPDB + IP Geolocation |
| Risk Scoring Engine | Weighted composite score (0–100) |
| True Positive Flagging | Configurable threshold |
| CSV Export | Timestamped reports for ticket attachment |
| IP + URL Support | Handles both IOC types |
| Rate Limit Handling | Built-in delays + retry logic |

## Quick Start

```bash
# 1. Clone & enter
git clone <repo-url>
cd osint-enrichment

# 2. Virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Add API keys to .env
cp .env.example .env         # then edit

# 5. Add IOCs to iocs.txt (one per line)

# 6. Run
python osint_enrichment.py
python osint_enrichment.py -f custom_list.csv --threshold 70