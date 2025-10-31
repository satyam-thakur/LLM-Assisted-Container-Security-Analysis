# Vulnerability Assessment (DSPy + Gemini)

This module performs AI-powered vulnerability assessment on combined container scanner reports (Trivy + Grype). It analyzes vulnerabilities in context to determine real exploitability and produces VEX-style justifications.

## Key Features
- Parses `Scanner/combined_results/*.json` into normalized vulnerability records
- Uses DSPy-style programmatic prompting with Gemini LLM
- Produces VEX-like justification for each finding: affected, label, reason, risk, remediation
- Exports consolidated JSON and Markdown reports
- Fully self-contained Google Colab notebook available

## Quick Start - Google Colab (Recommended)

**Use the complete self-contained notebook:**
1. Open `Vulnerability_Assessment_Complete.ipynb` in Google Colab
2. Run all cells (Runtime → Run all)
3. Enter your GEMINI_API_KEY when prompted
4. Wait 10-30 minutes for results
5. Download JSON and Markdown reports

See `COLAB_NOTEBOOK_README.md` for detailed instructions.

## Requirements
- Python 3.10+
- GEMINI_API_KEY from [Google AI Studio](https://makersuite.google.com/app/apikey)
- Install deps: `pip install -r requirements.txt`

## Files
- `Vulnerability_Assessment_Complete.ipynb` — **Complete self-contained notebook for Google Colab**
- `COLAB_NOTEBOOK_README.md` — Detailed usage instructions for the Colab notebook
- `requirements.txt` — Dependencies for local development
- `.env` — Environment variables (GEMINI_API_KEY, GEMINI_MODEL)
- `README.md` — This file

## Outputs
- JSON: `outputs/assessment_<timestamp>.json` (structured VEX data)
- Markdown: `outputs/assessment_<timestamp>.md` (human-readable report)

## VEX Labels Used
- `vulnerable` — Exploitable as-deployed
- `code_not_present` — Package/code not in image
- `code_not_reachable` — Present but not reachable/exposed
- `mitigated` — Present but mitigations block exploit
- `fixed` — Fixed version present
- `false_positive` — Scanner likely wrong

## Architecture
The complete notebook includes all modules:
1. Configuration management
2. Scanner JSON loader and normalizer
3. Prompt templates and VEX labels
4. AI reasoning engine (DSPy + Gemini fallback)
5. Main assessment orchestration
6. Results display and statistics

## Notes
- All code is self-contained in the Colab notebook - no external Python files needed
- Automatically falls back to direct Gemini API if DSPy configuration fails
- Deduplicates vulnerabilities to reduce API calls and cost
- Can be extended with RAG, SBOM cross-checks, or vector databases
