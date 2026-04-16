# netbox-vuln-manager

A NetBox 4.x plugin for CVE and non-CVE vulnerability management. Ingests findings from CrowdStrike Falcon Spotlight, SecurityScorecard, and Nexpose CSV exports, links them to NetBox assets, and enriches vulnerabilities with live data from NVD, CISA KEV, and EPSS.

---

## What it does

- **Tracks vulnerabilities** — CVEs and non-CVE findings with CVSS v2/v3, CWE, affected versions, references, and descriptions
- **Links findings to assets** — Device, VirtualMachine, or IPAddress via generic foreign key; matches by IP and/or hostname
- **Risk scoring** — base, temporal, and environmental scores with an audit trail (never overwrites analyst notes on re-sync)
- **Multiple data sources** — CrowdStrike Spotlight (API), SecurityScorecard (API), Nexpose (CSV)
- **CVE enrichment** — pulls CVSS, CWE, vendor/product, and references from NIST NVD; marks known-exploited from CISA KEV; adds exploitation likelihood from FIRST.org EPSS
- **Stale finding lifecycle** — findings not updated by source within a configurable window are automatically resolved

---

## Requirements

- NetBox 4.0 or later
- Python 3.10+
- `requests` (installed automatically)
- `crowdstrike-falconpy` — only if using CrowdStrike as a source (optional)

---

## Installation

### 1. Install the package

Install into the same Python environment that runs NetBox (usually the virtual environment at `/opt/netbox/venv`):

```bash
# From PyPI (once published)
source /opt/netbox/venv/bin/activate
pip install netbox-vuln-manager

# Or from a local clone
source /opt/netbox/venv/bin/activate
pip install /path/to/netbox-vuln-manager
```

To also install the optional CrowdStrike SDK:

```bash
pip install "netbox-vuln-manager[crowdstrike]"
```

### 2. Enable the plugin in NetBox

Edit NetBox's `configuration.py` (typically `/opt/netbox/netbox/netbox/configuration.py`):

```python
PLUGINS = [
    "netbox_vuln_manager",
]
```

### 3. Configure the plugin (optional)

Add a `PLUGINS_CONFIG` block to `configuration.py`. All keys are optional — defaults are shown:

```python
PLUGINS_CONFIG = {
    "netbox_vuln_manager": {
        # Create a bare IPAddress stub in NetBox for assets not found by any match.
        # False (default) means unknown assets produce a warning and are skipped.
        "auto_create_assets": False,

        # How to match vulnerability report assets to NetBox objects.
        # "ip" (default) | "hostname" | "both"
        "asset_match_strategy": "ip",

        # Days after last sync with no update before a finding is auto-resolved.
        "stale_finding_days": 30,

        # HTTP/HTTPS proxy for all outbound API calls (NVD, CISA, EPSS, CrowdStrike…)
        # "http_proxy": "http://proxy.example.com:3128",

        # NVD API key — increases rate limit from 5 to 50 req/30 s.
        # Register for free at https://nvd.nist.gov/developers/request-an-api-key
        # "nvd_api_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    }
}
```

### 4. Run database migrations

```bash
source /opt/netbox/venv/bin/activate
cd /opt/netbox/netbox
python manage.py migrate netbox_vuln_manager
```

### 5. Restart NetBox

```bash
sudo systemctl restart netbox netbox-rq
```

The plugin's menu items appear under **Plugins → Vulnerability Manager** in the NetBox UI.

---

## Data sources

Sources are configured inside NetBox under **Plugins → Vulnerability Manager → Sources**. Each source stores its credentials in an encrypted-at-rest JSON config field.

### CrowdStrike Falcon Spotlight

```json
{
    "client_id":     "your-client-id",
    "client_secret": "your-client-secret",
    "base_url":      "https://api.crowdstrike.com"
}
```

The sync imports CVE findings from the Spotlight Vulnerabilities API and maps host data to NetBox Devices.

### SecurityScorecard

```json
{
    "api_key": "your-ssc-api-key",
    "domain":  "example.com"
}
```

Fetches per-factor issues (network security, patching cadence, etc.) and extracts any CVE references.

### Nexpose / CSV

```json
{
    "file_path":   "/import/nexpose_export.csv",
    "column_map": {}
}
```

Reads a Nexpose CSV export. The default column mapping covers the standard Nexpose export format; override individual columns via `column_map` if your export differs.

---

## Running a sync

```bash
# Sync all enabled sources
python manage.py sync_vulnerabilities

# Sync a specific source by name
python manage.py sync_vulnerabilities --source "CrowdStrike Prod"

# See what would change without writing to the database
python manage.py sync_vulnerabilities --dry-run
```

---

## CVE enrichment

The `enrich_cves` command enriches existing Vulnerability records with live data from three external feeds. It does not create new records — only updates ones that already exist in NetBox.

```bash
# Enrich all CVEs from all three feeds (NVD, CISA KEV, EPSS)
python manage.py enrich_cves

# Incremental NVD update — only CVEs modified in the last 24 hours
python manage.py enrich_cves --feed nvd --days-back 1

# Full NVD refresh — re-fetch all CVEs regardless of last-modified
python manage.py enrich_cves --feed nvd --full

# Only update KEV and EPSS (skip NVD)
python manage.py enrich_cves --feed kev --feed epss

# See what would change without writing anything
python manage.py enrich_cves --dry-run
```

### What each feed provides

| Feed | Fields updated |
|---|---|
| **NVD** (NIST) | `cvss_v3_score`, `cvss_v3_vector`, `cvss_v2_score`, `cwe_id`, `affected_vendor`, `affected_product`, `description`, `references`, `published_date`, `modified_date`, `nvd_last_modified` |
| **CISA KEV** | `kev_listed`, `kev_added_date`, `kev_due_date`, `kev_ransomware_use` |
| **EPSS** (FIRST.org) | `epss_score`, `epss_percentile`, `epss_date` |

### Scheduling enrichment

Add a cron entry to run enrichment automatically:

```
# /etc/cron.d/netbox-enrich-cves

# Daily incremental update at 03:00
0 3 * * * netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py \
    enrich_cves --days-back 1 >> /var/log/netbox/enrich_cves.log 2>&1

# Weekly full NVD refresh (Sunday 04:00) — catches any gaps from API outages
0 4 * * 0 netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py \
    enrich_cves --feed nvd --full >> /var/log/netbox/enrich_cves.log 2>&1
```

---

## REST API

All objects are accessible under `/api/plugins/vulns/`. The API follows standard NetBox conventions and is browsable at `/api/plugins/vulns/` when logged in.

```
GET  /api/plugins/vulns/vulnerabilities/
GET  /api/plugins/vulns/findings/
GET  /api/plugins/vulns/sources/
```

---

## Project structure

```
netbox-vuln-manager/
├── netbox_vuln_manager/
│   ├── __init__.py             PluginConfig
│   ├── choices.py              SeverityChoices, FindingStatusChoices, SourceTypeChoices, …
│   ├── models/
│   │   ├── vulnerability.py    Vulnerability (CVE/non-CVE, with NVD/KEV/EPSS fields)
│   │   ├── finding.py          VulnerabilityFinding (generic FK to any asset)
│   │   ├── source.py           VulnerabilitySource (credentials, sync state)
│   │   └── risk.py             RiskScore, SyncLog
│   ├── sources/
│   │   ├── base.py             BaseVulnerabilitySource, NormalisedFinding
│   │   ├── crowdstrike.py      CrowdStrike Falcon Spotlight
│   │   ├── securityscorecard.py SecurityScorecard API
│   │   ├── csv_handler.py      Nexpose CSV / generic CSV
│   │   ├── nvd.py              NVD API v2 enricher
│   │   ├── kev.py              CISA KEV feed enricher
│   │   └── epss.py             FIRST.org EPSS enricher
│   ├── management/commands/
│   │   ├── sync_vulnerabilities.py
│   │   └── enrich_cves.py
│   ├── migrations/
│   ├── tables/
│   ├── forms/
│   ├── filtersets.py
│   ├── views/
│   ├── api/
│   ├── navigation.py
│   └── templates/
└── pyproject.toml
```

---

## Notes

- The plugin never deletes findings automatically. Stale findings are **resolved** (status changed), not removed.
- Analyst-written fields (`notes`, `remediation`) are never overwritten by a sync — only the source-controlled fields are updated.
- The CrowdStrike source tries the `falconpy` SDK first and falls back to direct REST if the SDK is not installed.
- With no NVD API key the NVD enricher is rate-limited to 5 requests per 30 seconds. A free key increases this to 50 requests per 30 seconds and is strongly recommended for the full refresh mode.
