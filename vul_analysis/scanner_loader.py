import json
from typing import Any, Dict, List, Tuple
import pandas as pd


def load_scanner_results(path: str) -> Dict[str, Any]:
    """Load the combined scanner JSON file (e.g., Trivy + Grype combined).

    Expected top-level keys include: image, total_vulnerabilities, scanners_used, vulnerabilities (list).
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def _norm(v: Any) -> str:
    return "" if v is None else str(v)


def _extract_vuln_id(rec: Dict[str, Any]) -> Tuple[str, str]:
    # Prefer CVE ID if present; else allow GHSA or other IDs in title/fields
    cve = _norm(rec.get("cve_id"))
    if cve:
        return cve, "cve"
    # Try common alternate fields
    for k in ("vuln_id", "id", "ghsa_id"):
        if _norm(rec.get(k)):
            return _norm(rec.get(k)), k
    # As a last resort, derive from title
    title = _norm(rec.get("title"))
    if title.startswith("CVE-"):
        token = title.split()[0].strip(",.:;")
        return token, "derived"
    return "", "unknown"


def build_vuln_frame(data: Dict[str, Any]) -> pd.DataFrame:
    """Normalize the vulnerability list into a DataFrame.

    Columns: vuln_id, id_source, package_name, installed_version, fixed_version, severity,
    scanner, title, description, image
    """
    image = _norm(data.get("image"))
    vulns: List[Dict[str, Any]] = data.get("vulnerabilities", []) or []
    rows: List[Dict[str, Any]] = []
    for rec in vulns:
        if not isinstance(rec, dict) or not rec:
            continue
        vuln_id, id_source = _extract_vuln_id(rec)
        if not vuln_id:
            continue
        rows.append(
            {
                "vuln_id": vuln_id,
                "id_source": id_source,
                "package_name": _norm(rec.get("package_name")),
                "installed_version": _norm(rec.get("installed_version")),
                "fixed_version": _norm(rec.get("fixed_version")),
                "severity": _norm(rec.get("severity")),
                "scanner": _norm(rec.get("scanner")),
                "title": _norm(rec.get("title")),
                "description": _norm(rec.get("description")),
                "image": image or _norm(rec.get("image")),
            }
        )
    if not rows:
        return pd.DataFrame(
            columns=[
                "vuln_id",
                "id_source",
                "package_name",
                "installed_version",
                "fixed_version",
                "severity",
                "scanner",
                "title",
                "description",
                "image",
            ]
        )
    df = pd.DataFrame(rows)
    # Deduplicate identical rows
    df = df.drop_duplicates()
    return df
