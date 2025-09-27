# LLM-Assisted-Container-Security-Analysis

LLM Assisted Container Security Analysis combines container scanners like **Grype**, **Syft**, and **Trivy** with Large Language Models to generate SBOMs, detect CVEs, and provide clear, context-rich insights. It enhances reports with human-friendly explanations, prioritization, and CI/CD integration for smarter vulnerability management.

---

## Table of Contents

- [Overview](#overview)
- [Core Workflow](#core-workflow)
- [Features](#features)
- [Tools & Technologies](#tools--technologies)
- [Sample Reports](#sample-reports)
- [LLM Integration](#llm-integration)
- [License](#license)

---

## Overview

This repository showcases an integrated security analysis pipeline for container images. It leverages open-source scanners and LLMs to automate vulnerability detection, SBOM generation, and provides actionable, prioritized remediation guidance.

---

## Core Workflow

1. **Container Scanning**
   - Images are scanned using [Grype](https://github.com/anchore/grype), [Syft](https://github.com/anchore/syft), and [Trivy](https://github.com/aquasecurity/trivy).
   - Scans detect vulnerabilities (CVEs), software bill of materials (SBOMs), and secrets.

2. **Report Generation**
   - Each tool outputs detailed reports (see `GithubActions/TrivyScan`, `GithubActions/GrypeScan`, `GithubActions/Syft_sbom`).
   - LLMs process raw scanner outputs, transforming technical data into clear summaries, explanations, and prioritized recommendations.

3. **LLM-Powered Analysis**
   - LLMs add human-friendly context, explain vulnerabilities, and suggest remediation steps.
   - Reports are enhanced with severity assessments, exploit probability, and risk scores.

4. **CI/CD Integration**
   - The system is designed to be integrated into CI/CD pipelines for automated security checks and compliance reporting.
   - Example: Scan results for Hyperledger Fabric images (orderer, couchdb, tools) are included for reference.

---

## Features

- **Multi-Scanner Support:** Automatic container analysis via Grype, Syft, and Trivy.
- **LLM Augmentation:** Vulnerability reports are enriched and explained via Large Language Models.
- **SBOM Generation:** Detailed SBOMs for all scanned images.
- **Prioritization:** Vulnerabilities are ranked by severity, exploit probability, and risk.
- **CI/CD Ready:** Integrates into DevOps to catch issues before deployment.

---


## Tools & Technologies

- **Grype**: Vulnerability scanner for container images and filesystems.
- **Syft**: SBOM (Software Bill of Materials) generator.
- **Trivy**: Comprehensive scanner for vulnerabilities, SBOM, and secrets.
- **LLMs**: Large Language Models for report analysis and explanation.

---

## Sample Reports

- **Trivy Scan Example**: `GithubActions/TrivyScan/trivy-scan-report-hyperledger_fabric-orderer_2.1.txt`
  - Summarizes vulnerabilities, severity, and links to CVE details.
- **Grype Scan Example**: `GithubActions/GrypeScan/grype-scan-report-hyperledger_fabric-orderer_2.1.txt`
  - Includes risk scores and exploit probability.
- **Syft SBOM Example**: `GithubActions/Syft_sbom/syft-sbom-report-hyperledger_fabric-couchdb_latest.txt`
  - Lists all discovered packages and layers in scanned images.

---

## LLM Integration

**Work in Progress**

- The LLM section is currently under active development.
- LLMs will be used to further analyze, summarize, and prioritize vulnerabilities found in scanned container images.
- Additional capabilities for risk scoring, remediation suggestions, and executive summaries are planned.


---

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

## How to Use

1. **Clone this repository**
2. **Run container scans** using provided sample scripts or via CI/CD.
3. **Review and interpret reports**—either directly or via the LLM output.
4. **Integrate into your pipeline** for automated, continuous security.

---

## Contact

Maintainer: [Satyam Thakur](https://github.com/satyam-thakur)

For questions or contributions, please open an Issue or Pull Request.
