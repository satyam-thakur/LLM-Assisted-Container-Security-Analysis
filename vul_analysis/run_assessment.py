from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Tuple

import pandas as pd

from .scanner_loader import build_vuln_frame, load_scanner_results
from .vex_reasoner import assess_batch, to_json, to_markdown


DEFAULT_INPUT = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "Scanner",
    "combined_results",
    "hyperledger_fabric-peer_1.1.0_combined.json",
)


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _output_paths(base_dir: str | None = None) -> Tuple[str, str]:
    base = base_dir or os.path.join(os.path.dirname(__file__), "outputs")
    _ensure_dir(base)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return (
        os.path.join(base, f"assessment_{ts}.json"),
        os.path.join(base, f"assessment_{ts}.md"),
    )


def assess(input_path: str = DEFAULT_INPUT, output_dir: str | None = None) -> Dict[str, Any]:
    data = load_scanner_results(input_path)
    df = build_vuln_frame(data)
    if df.empty:
        raise RuntimeError("No vulnerabilities found in the provided file.")

    # Optionally de-dup by (vuln_id, package_name) to reduce token and calls
    df_slice = df.sort_values(["vuln_id", "package_name"]).drop_duplicates([
        "vuln_id",
        "package_name",
        "installed_version",
        "scanner",
    ])

    records: List[Dict[str, Any]] = df_slice.to_dict(orient="records")
    results = assess_batch(records)

    json_out = to_json(results)
    md_out = to_markdown(results)

    json_path, md_path = _output_paths(output_dir)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "input": {
                    "image": data.get("image"),
                    "scanners_used": data.get("scanners_used"),
                    "total_vulnerabilities": data.get("total_vulnerabilities"),
                    "source_file": os.path.abspath(input_path),
                },
                "output": json_out,
            },
            f,
            indent=2,
        )

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_out)

    # Return a compact summary for notebook display
    df_out = pd.DataFrame(json_out)
    df_out[["affected", "label", "reason", "risk", "remediation"]] = pd.json_normalize(df_out["justification"])  # type: ignore[index]
    df_out.drop(columns=["justification"], inplace=True)

    return {
        "json_path": json_path,
        "md_path": md_path,
        "summary_df": df_out,
    }


if __name__ == "__main__":
    p = DEFAULT_INPUT
    if os.path.exists(p):
        result = assess(p)
        print("Saved:", result["json_path"], "\n", result["md_path"])  # noqa: T201
    else:
        raise SystemExit(f"Input file not found: {p}")
