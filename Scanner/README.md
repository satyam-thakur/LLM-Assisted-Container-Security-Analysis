# Scanner Result Combiner & Analyzer

Comprehensive tool to merge and analyze container vulnerability scan results from multiple scanners (Trivy and Grype).

Inspired by the UBCIS (Unified Benchmark for Container Image Scanners) approach to normalizing and merging scanner outputs.

## Features

- ✅ **Multi-scanner support**: Combines Trivy and Grype JSON reports
- ✅ **Smart deduplication**: Merges vulnerabilities by (CVE, Package, Image) key
- ✅ **Severity normalization**: Standardizes severity levels across scanners
- ✅ **Detection tracking**: Shows which scanners found each vulnerability
- ✅ **Multiple output formats**: JSON, CSV, and detailed TXT analysis reports
- ✅ **Per-image analysis**: Generates separate reports for each container image
- ✅ **Comprehensive analysis**: Scanner comparison, discrepancy analysis, fixability stats

## Quick Start

### Prerequisites

- Python 3.6+
- Scanner reports in JSON format from Trivy and/or Grype

### Usage

```powershell
# From the Scanner directory
cd C:\Users\SATYAM\Documents\Research\ContainerSecurity\LLM-Assisted-Container-Security-Analysis\Scanner

# Step 1: Combine scanner results (1 file per image)
python combine_scanner_results.py

# Step 2: Analyze combined results
python analyze_results.py
```

### Expected Directory Structure

```
LLM-Assisted-Container-Security-Analysis/
├── GithubActions/
│   ├── TrivyScan/
│   │   ├── trivy-scan-report-*.json
│   │   └── ...
│   └── GrypeScan/
│       ├── grype-scan-report-*.json
│       └── ...
└── Scanner/
    ├── combine_scanner_results.py
    ├── analyze_results.py
    ├── combined_results/          # Created by combine_scanner_results.py
    │   ├── <image1>_combined.json  # One file per image
    │   ├── <image1>_combined.csv
    │   ├── <image2>_combined.json
    │   └── <image2>_combined.csv
    └── analyzed_results/          # Created by analyze_results.py
        ├── <image1>_analysis.txt   # Detailed analysis per image
        └── <image2>_analysis.txt
```

## How It Works

### 1. Parse Scanner Reports

**Trivy Format:**
```json
{
  "Results": [{
    "Vulnerabilities": [{
      "VulnerabilityID": "CVE-2021-36159",
      "PkgName": "apk-tools",
      "InstalledVersion": "2.10.5-r0",
      "Severity": "CRITICAL"
    }]
  }]
}
```

**Grype Format:**
```json
{
  "matches": [{
    "vulnerability": {
      "id": "CVE-2021-36159",
      "severity": "Critical"
    },
    "artifact": {
      "name": "apk-tools",
      "version": "2.10.5-r0"
    }
  }]
}
```

### 2. Normalize to Common Schema

Both are converted to:
```json
{
  "cve_id": "CVE-2021-36159",
  "package_name": "apk-tools",
  "installed_version": "2.10.5-r0",
  "fixed_version": "2.10.7-r0",
  "severity": "CRITICAL",
  "image": "hyperledger/fabric-peer:2.1",
  "scanner": "trivy"
}
```

### 3. Merge and Deduplicate

- **Key**: `(CVE, Package, Image)`
- **Merge strategy**:
  - Track all scanners that detected the vulnerability
  - Use highest severity if scanners disagree
  - Prefer fixed version info when available

### 4. Generate Reports

**Per-Image JSON Output** (`<image>_combined.json`):
- One file per container image
- Full vulnerability details
- Detection metadata

**Per-Image CSV Output** (`<image>_combined.csv`):
- One file per container image
- Flat table format
- Easy to import into Excel/spreadsheets

**Detailed Analysis Reports** (`<image>_analysis.txt`):
- Comprehensive text-based analysis
- Scanner coverage and discrepancy analysis
- Severity distribution
- Top vulnerable packages
- Fixability statistics
- Critical/High vulnerability details
- Scanner-specific comparison

## Output Examples

### Combine Script Summary

```
============================================================
Container Security Scanner Result Combiner
============================================================

Parsing Trivy reports...
Found 2 Trivy report(s)
  - trivy-scan-report-hyperledger_fabric-peer_2.1.json
  - trivy-scan-report-hyperledger_fabric-peer_3.1.json

Parsing Grype reports...
Found 2 Grype report(s)
  - grype-scan-report-hyperledger_fabric-peer_2.1.json
  - grype-scan-report-hyperledger_fabric-peer_3.1.json

Total vulnerabilities found: 202
Unique vulnerabilities after merge: 171

Vulnerabilities by severity:
  CRITICAL: 13
  HIGH: 98
  MEDIUM: 42
  LOW: 18

Saving reports (1 file per image)...
Generated 2 JSON and 2 CSV reports
```

### Analysis Report Sample

```
================================================================================
CONTAINER SECURITY VULNERABILITY ANALYSIS REPORT
================================================================================

Generated: 2025-10-29 10:32:58
Image: hyperledger/fabric-peer:2.1
Total Vulnerabilities: 153
Scanners Used: trivy, grype

================================================================================
SCANNER COVERAGE ANALYSIS
================================================================================

Total unique vulnerabilities: 153

Scanner Detection Statistics:
  Both Scanners (Agreement): 31 (20.3%)
  Only Trivy:                50 (32.7%)
  Only Grype:                72 (47.1%)

Discrepancy Analysis:
  Scanner Agreement Rate: 20.3%
  Scanner Discrepancy Rate: 79.7%
  Trivy-exclusive findings: 50
  Grype-exclusive findings: 72

================================================================================
SEVERITY DISTRIBUTION
================================================================================

Vulnerability Breakdown by Severity:
  CRITICAL    :   13 (  8.5%)
  HIGH        :   98 ( 64.1%)
  MEDIUM      :   36 ( 23.5%)
  LOW         :    6 (  3.9%)

================================================================================
TOP 10 MOST VULNERABLE PACKAGES
================================================================================

Package                             Count    Critical   High    
--------------------------------------------------------------------------------
stdlib                              50       4          46      
libcrypto1.1                        32       2          13      
libssl1.1                           32       2          13      
busybox                             15       1          11      

================================================================================
FIXABLE VULNERABILITIES ANALYSIS
================================================================================

Overall Fix Availability:
  Total vulnerabilities: 153
  Fixable: 93 (60.8%)
  Not fixable: 60 (39.2%)

Fix Availability by Severity:
  CRITICAL    :   8/13  fixable ( 61.5%)
  HIGH        :  73/98  fixable ( 74.5%)
  MEDIUM      :  10/36  fixable ( 27.8%)
  LOW         :   2/6   fixable ( 33.3%)
```

### Sample CSV Row

| image | cve_id | package_name | installed_version | fixed_version | severity | detected_by |
|-------|--------|--------------|-------------------|---------------|----------|-------------|
| hyperledger/fabric-peer:2.1 | CVE-2021-36159 | apk-tools | 2.10.5-r0 | 2.10.7-r0 | CRITICAL | trivy, grype |

## Analysis Features

### Scanner Coverage Analysis
- Number of vulnerabilities detected by each scanner
- Scanner agreement rate (vulnerabilities found by both)
- Scanner discrepancy rate (unique findings per scanner)
- Identifies which scanner is more/less sensitive

### Severity Distribution
- Breakdown of vulnerabilities by severity level
- Percentage distribution across CRITICAL, HIGH, MEDIUM, LOW

### Top Vulnerable Packages
- Identifies packages with most vulnerabilities
- Shows critical and high severity counts per package
- Helps prioritize remediation efforts

### Fixability Analysis
- Overall fix availability statistics
- Fix availability breakdown by severity level
- Helps understand remediation feasibility

### Critical/High Severity Focus
- Detailed listing of critical and high vulnerabilities
- CVE IDs with affected packages
- Fixed versions (if available)
- Scanner detection information

### Detailed Scanner Comparison
- Trivy-exclusive vulnerabilities (with severity breakdown)
- Grype-exclusive vulnerabilities (with severity breakdown)
- Both scanners agreement (with severity breakdown)
- Helps understand scanner-specific behavior

## Key Differences from UBCIS

This implementation is **simplified** for quick merging:

| Feature | UBCIS | This Tool |
|---------|-------|-----------|
| Scanner orchestration | ✅ Full (configure, scan, destroy) | ❌ Post-scan only |
| Plugin system | ✅ Dynamic plugin loading | ❌ Hardcoded parsers |
| VM/Docker setup | ✅ Vagrant + Docker Compose | ❌ Manual scanner setup |
| Ground truth validation | ✅ Known CVE lists | ❌ No validation |
| Package name mapping | ✅ Complex mapping trees | ✅ Simple normalization |
| Scoring/metrics | ✅ Precision/recall/F1 | ❌ No scoring |
| Parallel scanning | ✅ Multiprocessing | ❌ Sequential parsing only |
| Per-image reports | ❌ Combined only | ✅ Separate files per image |
| Analysis reports | ❌ Basic stats | ✅ Comprehensive .txt reports |
| Discrepancy analysis | ❌ Not included | ✅ Detailed comparison |

## Customization

### Add More Scanners

Add a parser function following this pattern:

```python
def parse_newscanner_report(file_path):
    vulns = []
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    # Extract vulnerabilities
    for item in data['some_structure']:
        vulns.append({
            'cve_id': item['cve'],
            'package_name': item['package'],
            'installed_version': item['version'],
            'fixed_version': item.get('fix', 'No fix available'),
            'severity': normalize_severity(item['severity']),
            'image': data['image_name'],
            'scanner': 'newscanner',
            'title': item.get('title', ''),
            'description': item.get('description', '')
        })
    
    return vulns
```

Then call it in `main()` similar to Trivy/Grype parsing.

## Troubleshooting

**Issue**: `FileNotFoundError: [Errno 2] No such file or directory`
- **Fix**: Ensure GithubActions/TrivyScan and GithubActions/GrypeScan directories exist with JSON reports

**Issue**: `json.decoder.JSONDecodeError`
- **Fix**: Check that scanner reports are valid JSON (not text-only reports)

**Issue**: Zero vulnerabilities found
- **Fix**: Verify JSON structure matches expected format (check line ~40-60 in combine_scanner_results.py)

**Issue**: No combined reports found when running analyze_results.py
- **Fix**: Run `combine_scanner_results.py` first to generate combined reports

**Issue**: Analysis report shows 0% agreement
- **Fix**: Normal if scanners have different vulnerability databases; check individual scanner outputs

## Related Projects

- **UBCIS**: Full benchmark suite for container scanner evaluation
  - Repository: `UBCIS/` in this workspace
  - Path: `C:\Users\SATYAM\Documents\Research\ContainerSecurity\UBCIS\`
  - Features: Scanner orchestration, ground truth validation, scoring

## License

Same as parent project (check repository root).
