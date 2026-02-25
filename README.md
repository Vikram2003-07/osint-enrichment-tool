# 🔍 OSINT Enrichment Automation Tool

> Turn a **20-minute manual IOC lookup** into a **5-second automated** workflow.

Automate threat intelligence enrichment by querying multiple OSINT APIs (VirusTotal, AbuseIPDB, IPGeolocation) to get reputation scores, geographic location, and abuse data for Indicators of Compromise (IOCs) like IP addresses and URLs/domains.

## Sample Output
```plaintext
══════════════════════════════════════════════════════════════
IOC : 185.220.101.34
──────────────────────────────────────────────────────────────
  📍 Location    : Nuremberg, Germany
  🌐 ISP / Org   : Hetzner / Tor Exit Node
  🛡  VT Malicious  : 14
  🔴 Abuse Score    : 100%
  ⚡ Risk Score     : 86 / 100
  🏷  Severity      : CRITICAL
  🚩 Verdict        : ⚠  TRUE POSITIVE
══════════════════════════════════════════════════════════════
```

## ✨ Features

| Feature | Description |
|---------|-------------|
| **🔗 Multi-API Enrichment** | Queries VirusTotal, AbuseIPDB, and IPGeolocation in parallel |
| **⚡ Risk Scoring Engine** | Weighted composite score (0-100) combining all data sources |
| **🚩 True Positive Flagging** | Configurable threshold to flag high-risk IOCs |
| **📊 CSV Export** | Timestamped reports for ticket attachment and auditing |
| **♾️ IP + URL Support** | Handles both IP addresses and URLs/domains |
| **📈 Rate Limit Handling** | Built-in delays and retry logic for API limits |
| **🎨 Colorized Output** | Terminal-friendly color-coded results |

## 📋 Requirements

### API Keys (Required)

You need free API keys from these services:

| Service | Free Tier | Signup URL |
|---------|-----------|------------|
| **VirusTotal** | 4 requests/min, 500/day | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **AbuseIPDB** | 1,000 checks/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| **IPGeolocation** | 1,000 queries/day | [ipgeolocation.io](https://ipgeolocation.io/signup/free) |

### Environment

- **Python**: 3.8 or higher
- **OS**: Windows, macOS, or Linux

## 🚀 Quick Start

```bash
# 1. Clone & enter the project
git clone <repo-url>
cd osint-enrichment

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

# 4. Install dependencies
pip install -r requirements.txt

# 5. Edit .env with your API keys
#    See Configuration section below

# 6. Add IOCs to enrich
#    Edit iocs.txt (one IOC per line)

# 7. Run the tool
python osint_enrichment.py
```

## ⚙️ Configuration

### Environment Variables (`.env` file)

```env
# API Keys (all required)
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
IPGEO_API_KEY=your_ipgeolocation_api_key

# Risk threshold (0-100) — IOCs >= this score are flagged as TRUE POSITIVE
RISK_THRESHOLD=50
```

### Input File Format

**Plain text** (`iocs.txt`) — one IOC per line:
```
8.8.8.8
1.1.1.1
https://malicious-example.com/phish
185.220.101.34
```

**CSV file** — column headers: `ioc`, `ip`, `url`, or `indicator`:
```csv
ioc,notes
8.8.8.8,Google DNS
1.1.1.1,Cloudflare DNS
https://evil.com,Known malware
```

## 📖 Usage

### Basic Usage

```bash
# Use default iocs.txt
python osint_enrichment.py

# Specify custom input file
python osint_enrichment.py -f my_indicators.txt

# Use CSV input
python osint_enrichment.py -f iocs.csv

# Override threshold
python osint_enrichment.py -f iocs.txt --threshold 70

# Skip CSV export (terminal only)
python osint_enrichment.py -f iocs.txt --no-csv

# Specify output directory
python osint_enrichment.py -f iocs.txt -o ./reports
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f`, `--file` | Input file (`.txt` or `.csv`) | `iocs.txt` |
| `-t`, `--threshold` | Risk score threshold (0-100) | `.env` value (50) |
| `-o`, `--output` | Output directory for CSV | Current directory |
| `--no-csv` | Skip CSV export | False |

## 📊 Risk Scoring

The tool calculates a composite risk score (0-100) using weighted factors:

| Factor | Weight | Source |
|--------|--------|--------|
| VirusTotal malicious ratio | 40% | Number of engines flagging as malicious |
| AbuseIPDB confidence score | 40% | Abuse confidence percentage |
| VirusTotal suspicious ratio | 10% | Number of engines flagging as suspicious |
| VirusTotal reputation | 10% | Community reputation score |

### Severity Labels

| Score Range | Label | Color |
|-------------|-------|-------|
| 80-100 | CRITICAL | Red |
| 60-79 | HIGH | Yellow |
| 40-59 | MEDIUM | Orange |
| 20-39 | LOW | Green |
| 0-19 | INFO | Green |

### True Positive Flagging

When the risk score meets or exceeds the threshold, the IOC is flagged as a **TRUE POSITIVE**, indicating it likely represents a genuine threat.

## 📁 Project Structure

```
osint-enrichment/
├── osint_enrichment.py   # Main entry point
├── api_clients.py        # API client implementations
├── scorer.py             # Risk scoring logic
├── reporter.py           # Output formatting & CSV export
├── requirements.txt      # Python dependencies
├── iocs.txt              # Sample IOC input file
├── .env                  # API configuration (not committed)
├── .gitignore            # Git ignore rules
└── README.md             # This file
```

## 📝 Dependencies

- **requests** — HTTP library for API calls
- **python-dotenv** — Environment variable management
- **colorama** — Terminal color output
- **prettytable** — Formatted tables in terminal

## 🔧 Troubleshooting

### Rate Limiting

If you encounter rate limit errors:
- The tool automatically waits 15 seconds between requests (VirusTotal free tier limit)
- For large IOC lists, consider splitting into batches

### API Errors

Check the terminal output for API-specific errors:
- Invalid API keys will show authentication errors
- Network issues will show connection errors

### CSV Output

CSV files are saved with timestamps: `output_report_YYYYMMDD_HHMMSS.csv`

## 📄 License

This project is provided as-is for threat intelligence enrichment. Use responsibly and in accordance with each API provider's terms of service.

## 🔗 References

- [VirusTotal API v3 Documentation](https://developers.virustotal.com/reference)
- [AbuseIPDB API v2 Documentation](https://docs.abuseipdb.com/)
- [IPGeolocation API Documentation](https://ipgeolocation.io/documentation.html)
