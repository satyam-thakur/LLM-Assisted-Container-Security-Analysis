# Vulnerability Assessment (DSPy + Gemini)

This module performs a lightweight, explainable vulnerability assessment over a combined container scanner report (e.g., Trivy + Grype). It follows the spirit of the vulnerability-analysis-main quick start: parse input, run an AI reasoning step, and produce an auditable JSON plus a readable Markdown report.

Key features
- Parses `Scanner/combined_results/*.json` into a normalized table per vulnerability
- Uses DSPy-style programmatic prompting when available, falling back to direct Gemini calls
- Produces a VEX-like justification for each finding: affected, label, reason, risk, remediation
- Exports consolidated JSON and Markdown reports

Requirements
- Python 3.10+
- Install deps:
  - From this folder: `pip install -r requirements.txt`
- Configure environment (either system env or a local `.env` here):
  - `GEMINI_API_KEY=<your_key>`
  - `GEMINI_MODEL=gemini-1.5-flash` (default if unset)

Files
- `config.py` — loads `.env` and configures DSPy with Gemini when possible
- `scanner_loader.py` — loads and normalizes the combined scanner JSON
- `prompts.py` — label set and DSPy Signature (if DSPy available)
- `vex_reasoner.py` — core reasoning engine (DSPy or direct Gemini fallback)
- `run_assessment.py` — orchestration: load input, run assessment, save JSON/Markdown
- `Vulnerability_Assessment.ipynb` — notebook to run the pipeline end-to-end

Outputs
- JSON: `vul_analysis/outputs/assessment_<timestamp>.json`
- Markdown: `vul_analysis/outputs/assessment_<timestamp>.md`

Notebook quickstart
Open `Vulnerability_Assessment.ipynb` and run all cells. It will:
1) Install/load requirements if needed
2) Configure Gemini from `.env`
3) Load scanner JSON and run assessments
4) Display a summary table and write outputs

CLI quickstart (optional)
You can also run the script directly:
```bash
python -m vul_analysis.run_assessment
```

Notes
- This is a small, self-contained baseline. You can extend it with RAG, SBOM cross-checks, or vector DBs similar to your NVIDIA blueprint reference.
- Labels used: vulnerable | code_not_present | code_not_reachable | mitigated | fixed | false_positive
