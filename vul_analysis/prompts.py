from typing import List

LABEL_CHOICES: List[str] = [
    # Common VEX-style labels focused on exploitability in-context
    "vulnerable",              # exploitable as-deployed
    "code_not_present",       # package/code not present in image
    "code_not_reachable",     # present but not reachable/exposed
    "mitigated",              # present, but mitigations block exploit
    "fixed",                  # fixed version present
    "false_positive",         # scanner likely wrong
]

JSON_SCHEMA_EXAMPLE = {
    "affected": False,
    "label": "code_not_reachable",
    "reason": "Short justification (<= 120 words) tied to image + package context.",
    "risk": "low",  # one of: low|medium|high
    "remediation": "Concise action (<= 120 words) if applicable.",
}

SYSTEM_INSTRUCTIONS = f"""
You are a security expert performing container vulnerability validation.
Given a vulnerability record from scanners (e.g., Trivy/Grype) for a specific container image, decide if the vulnerability is exploitable in the current context.
Return ONLY a strict JSON object with the following keys: affected (boolean), label (one of {LABEL_CHOICES}), reason (<=120 words), risk (low|medium|high), remediation (<=120 words).
Be precise, reduce speculation, and ground your decision in the provided details.
"""

# Optional: DSPy Signature definition if available
try:
    import dspy

    class VEXSignature(dspy.Signature):
        """Given vulnerability details from scanners, decide exploitability and produce VEX classification.

        Return ONLY strict JSON for: affected, label, reason, risk, remediation.
        """
        cve_id = dspy.InputField(desc="CVE or Vulnerability ID")
        package_name = dspy.InputField()
        installed_version = dspy.InputField()
        fixed_version = dspy.InputField()
        severity = dspy.InputField()
        title = dspy.InputField()
        description = dspy.InputField()
        image = dspy.InputField()
        scanner = dspy.InputField()
        output_json = dspy.OutputField(desc="Strict JSON with keys: affected, label, reason, risk, remediation")
except Exception:  # noqa: BLE001
    VEXSignature = None  # type: ignore
