from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .config import configure_dspy, get_gemini_settings
from .prompts import LABEL_CHOICES, SYSTEM_INSTRUCTIONS, VEXSignature


@dataclass
class VEXResult:
    vuln_id: str
    package_name: str
    affected: bool
    label: str
    reason: str
    risk: str
    remediation: str
    raw_model_text: str


_JSON_OBJ_RE = re.compile(r"\{[\s\S]*\}")


def _safe_json_parse(text: str) -> Optional[Dict[str, Any]]:
    # Find first JSON object in the text; helps if the model adds stray text
    m = _JSON_OBJ_RE.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def _normalize_label(label: str) -> str:
    low = (label or "").strip().lower()
    for choice in LABEL_CHOICES:
        if low == choice:
            return choice
    # Map common near-misses
    aliases = {
        "not_present": "code_not_present",
        "not_reachable": "code_not_reachable",
        "unexploitable": "mitigated",
        "remediated": "fixed",
        "true_positive": "vulnerable",
        "benign": "false_positive",
    }
    return aliases.get(low, low or "false_positive")


class _DSPyPredictor:
    def __init__(self) -> None:
        import dspy  # type: ignore

        self._predict = dspy.Predict(VEXSignature)  # type: ignore[arg-type]

    def run_once(self, record: Dict[str, Any]) -> Tuple[str, str]:
        # Returns (raw_text, model_used)
        out = self._predict(
            cve_id=record.get("vuln_id", ""),
            package_name=record.get("package_name", ""),
            installed_version=record.get("installed_version", ""),
            fixed_version=record.get("fixed_version", ""),
            severity=record.get("severity", ""),
            title=record.get("title", ""),
            description=record.get("description", ""),
            image=record.get("image", ""),
            scanner=record.get("scanner", ""),
        )
        # out.output_json is the text content per Signature
        raw = getattr(out, "output_json", None) or str(out)
        return str(raw), "dspy"


class _GeminiFallback:
    def __init__(self) -> None:
        import google.generativeai as genai  # type: ignore

        api_key, model = get_gemini_settings()
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY not configured in environment or .env")
        genai.configure(api_key=api_key)
        self._model = genai.GenerativeModel(model)

    def run_once(self, record: Dict[str, Any]) -> Tuple[str, str]:
        user_prompt = f"""
{SYSTEM_INSTRUCTIONS}

Vulnerability:
- vuln_id: {record.get('vuln_id','')}
- package_name: {record.get('package_name','')}
- installed_version: {record.get('installed_version','')}
- fixed_version: {record.get('fixed_version','')}
- severity: {record.get('severity','')}
- title: {record.get('title','')}
- description: {record.get('description','')}
- image: {record.get('image','')}
- scanner: {record.get('scanner','')}

Return ONLY a strict JSON object.
""".strip()
        resp = self._model.generate_content(user_prompt)
        text = getattr(resp, "text", None) or getattr(resp, "candidates", None) or str(resp)
        if isinstance(text, list):
            # handle candidate objects
            text = "\n".join(str(x) for x in text)
        return str(text), "gemini"


def _choose_engine() -> Any:
    mode = configure_dspy()
    if mode == "dspy" and VEXSignature is not None:
        try:
            return _DSPyPredictor()
        except Exception:
            pass
    # Fallback to direct Gemini API
    return _GeminiFallback()


def assess_record(engine: Any, rec: Dict[str, Any]) -> VEXResult:
    raw_text, used = engine.run_once(rec)
    parsed = _safe_json_parse(raw_text) or {}
    affected = bool(parsed.get("affected", False))
    label = _normalize_label(str(parsed.get("label", "")))
    reason = str(parsed.get("reason", ""))
    risk = str(parsed.get("risk", "")) or ("high" if rec.get("severity", "").upper() in {"CRITICAL", "HIGH"} else "medium")
    remediation = str(parsed.get("remediation", ""))
    return VEXResult(
        vuln_id=str(rec.get("vuln_id", "")),
        package_name=str(rec.get("package_name", "")),
        affected=affected,
        label=label,
        reason=f"[{used}] " + reason if reason else f"[{used}] no detailed reason",
        risk=risk,
        remediation=remediation,
        raw_model_text=raw_text,
    )


def assess_batch(records: Iterable[Dict[str, Any]]) -> List[VEXResult]:
    engine = _choose_engine()
    results: List[VEXResult] = []
    for rec in records:
        try:
            results.append(assess_record(engine, rec))
        except Exception as e:  # noqa: BLE001
            results.append(
                VEXResult(
                    vuln_id=str(rec.get("vuln_id", "")),
                    package_name=str(rec.get("package_name", "")),
                    affected=False,
                    label="error",
                    reason=f"engine_error: {e}",
                    risk="unknown",
                    remediation="",
                    raw_model_text="",
                )
            )
    return results


def to_json(results: List[VEXResult]) -> List[Dict[str, Any]]:
    return [
        {
            "vuln_id": r.vuln_id,
            "package_name": r.package_name,
            "justification": {
                "affected": r.affected,
                "label": r.label,
                "reason": r.reason,
                "risk": r.risk,
                "remediation": r.remediation,
            },
            "raw_model_text": r.raw_model_text,
        }
        for r in results
    ]


def to_markdown(results: List[VEXResult]) -> str:
    # Simple consolidated markdown report
    lines: List[str] = ["# Vulnerability Assessment Report", ""]
    for r in results:
        lines.extend(
            [
                f"## {r.vuln_id} — {r.package_name}",
                f"- Affected: {r.affected}",
                f"- Label: {r.label}",
                f"- Risk: {r.risk}",
                "- Reason:",
                f"  {r.reason}",
                "- Remediation:",
                f"  {r.remediation or 'N/A'}",
                "",
            ]
        )
    return "\n".join(lines)
