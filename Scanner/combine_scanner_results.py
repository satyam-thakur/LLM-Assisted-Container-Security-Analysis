"""
Combine Scanner Results - Simple merger for Trivy and Grype scan outputs
Inspired by UBCIS parse.py approach

This script:
1. Reads Trivy and Grype JSON reports from GithubActions/
2. Normalizes vulnerability data to common schema
3. Merges results by (CVE, package) key
4. Outputs combined JSON and CSV reports
"""

import json
import os
import csv
from pathlib import Path
from collections import defaultdict


def normalize_severity(severity_str):
    """Normalize severity to standard levels"""
    if not severity_str:
        return "UNKNOWN"
    
    severity_upper = severity_str.upper()
    
    # Map to standard CVSS levels
    if severity_upper in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"]:
        return severity_upper
    
    return "UNKNOWN"


def parse_trivy_report(file_path):
    """
    Parse Trivy JSON report and extract vulnerabilities
    Returns: list of normalized vulnerability dictionaries
    """
    vulns = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Extract image name
        image_name = data.get('ArtifactName', 'unknown')
        
        # Trivy structure: Results[] -> Vulnerabilities[]
        results = data.get('Results', [])
        
        for result in results:
            vulnerabilities = result.get('Vulnerabilities')
            if not vulnerabilities:
                continue
            
            for vuln in vulnerabilities:
                vulns.append({
                    'cve_id': vuln.get('VulnerabilityID', ''),
                    'package_name': vuln.get('PkgName', ''),
                    'installed_version': vuln.get('InstalledVersion', ''),
                    'fixed_version': vuln.get('FixedVersion', 'No fix available'),
                    'severity': normalize_severity(vuln.get('Severity', '')),
                    'image': image_name,
                    'scanner': 'trivy',
                    'title': vuln.get('Title', ''),
                    'description': vuln.get('Description', '')
                })
    
    except Exception as e:
        print(f"Error parsing Trivy report {file_path}: {e}")
    
    return vulns


def parse_grype_report(file_path):
    """
    Parse Grype JSON report and extract vulnerabilities
    Returns: list of normalized vulnerability dictionaries
    """
    vulns = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Extract image name from source
        image_name = data.get('source', {}).get('target', {}).get('userInput', 'unknown')
        
        # Grype structure: matches[]
        matches = data.get('matches', [])
        
        for match in matches:
            vulnerability = match.get('vulnerability', {})
            artifact = match.get('artifact', {})
            
            vulns.append({
                'cve_id': vulnerability.get('id', ''),
                'package_name': artifact.get('name', ''),
                'installed_version': artifact.get('version', ''),
                'fixed_version': vulnerability.get('fix', {}).get('versions', ['No fix available'])[0] if vulnerability.get('fix', {}).get('versions') else 'No fix available',
                'severity': normalize_severity(vulnerability.get('severity', '')),
                'image': image_name,
                'scanner': 'grype',
                'title': '',
                'description': vulnerability.get('description', '')
            })
    
    except Exception as e:
        print(f"Error parsing Grype report {file_path}: {e}")
    
    return vulns


def merge_vulnerabilities(all_vulns):
    """
    Merge vulnerabilities from multiple scanners
    Groups by (CVE, package, image) and tracks which scanners detected each
    """
    merged = {}
    
    for vuln in all_vulns:
        # Create unique key
        key = (vuln['cve_id'], vuln['package_name'], vuln['image'])
        
        if key not in merged:
            # First occurrence
            merged[key] = {
                **vuln,
                'detected_by': [vuln['scanner']]
            }
        else:
            # Already exists - merge scanner info
            existing = merged[key]
            
            # Add scanner if not already listed
            if vuln['scanner'] not in existing['detected_by']:
                existing['detected_by'].append(vuln['scanner'])
            
            # Use more severe rating if different
            severity_order = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'NEGLIGIBLE': 1, 'UNKNOWN': 0}
            if severity_order.get(vuln['severity'], 0) > severity_order.get(existing['severity'], 0):
                existing['severity'] = vuln['severity']
            
            # Prefer fixed version that's not "No fix available"
            if existing['fixed_version'] == 'No fix available' and vuln['fixed_version'] != 'No fix available':
                existing['fixed_version'] = vuln['fixed_version']
    
    return list(merged.values())


def save_json_report_per_image(merged_vulns, output_dir):
    """Save merged results to separate JSON files per image"""
    # Group by image
    by_image = defaultdict(list)
    for vuln in merged_vulns:
        by_image[vuln['image']].append(vuln)
    
    saved_files = []
    for image, vulns in by_image.items():
        # Create safe filename from image name
        safe_name = image.replace(':', '_').replace('/', '_').replace('\\', '_')
        output_path = output_dir / f'{safe_name}_combined.json'
        
        output = {
            'image': image,
            'total_vulnerabilities': len(vulns),
            'scanners_used': ['trivy', 'grype'],
            'vulnerabilities': vulns
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)
        
        saved_files.append(output_path.name)
        print(f"  - {output_path.name}")
    
    return saved_files


def save_csv_report_per_image(merged_vulns, output_dir):
    """Save merged results to separate CSV files per image"""
    # Group by image
    by_image = defaultdict(list)
    for vuln in merged_vulns:
        by_image[vuln['image']].append(vuln)
    
    saved_files = []
    fieldnames = ['image', 'cve_id', 'package_name', 'installed_version', 'fixed_version', 
                  'severity', 'detected_by', 'title']
    
    for image, vulns in by_image.items():
        # Create safe filename from image name
        safe_name = image.replace(':', '_').replace('/', '_').replace('\\', '_')
        output_path = output_dir / f'{safe_name}_combined.csv'
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for vuln in vulns:
                writer.writerow({
                    'image': vuln['image'],
                    'cve_id': vuln['cve_id'],
                    'package_name': vuln['package_name'],
                    'installed_version': vuln['installed_version'],
                    'fixed_version': vuln['fixed_version'],
                    'severity': vuln['severity'],
                    'detected_by': ', '.join(vuln['detected_by']),
                    'title': vuln.get('title', '')
                })
        
        saved_files.append(output_path.name)
    
    return saved_files


def main():
    """Main execution function"""
    # Setup paths
    base_dir = Path(__file__).parent.parent
    github_actions_dir = base_dir / 'GithubActions'
    trivy_dir = github_actions_dir / 'TrivyScan'
    grype_dir = github_actions_dir / 'GrypeScan'
    output_dir = Path(__file__).parent / 'combined_results'
    
    # Create output directory
    output_dir.mkdir(exist_ok=True)
    
    print("=" * 60)
    print("Container Security Scanner Result Combiner")
    print("=" * 60)
    
    # Collect all vulnerabilities
    all_vulns = []
    
    # Parse Trivy reports
    print("\nParsing Trivy reports...")
    if trivy_dir.exists():
        trivy_files = list(trivy_dir.glob('*.json'))
        print(f"Found {len(trivy_files)} Trivy report(s)")
        
        for trivy_file in trivy_files:
            print(f"  - {trivy_file.name}")
            vulns = parse_trivy_report(trivy_file)
            all_vulns.extend(vulns)
    else:
        print(f"Trivy directory not found: {trivy_dir}")
    
    # Parse Grype reports
    print("\nParsing Grype reports...")
    if grype_dir.exists():
        grype_files = list(grype_dir.glob('*.json'))
        print(f"Found {len(grype_files)} Grype report(s)")
        
        for grype_file in grype_files:
            print(f"  - {grype_file.name}")
            vulns = parse_grype_report(grype_file)
            all_vulns.extend(vulns)
    else:
        print(f"Grype directory not found: {grype_dir}")
    
    print(f"\nTotal vulnerabilities found: {len(all_vulns)}")
    
    # Merge results
    print("\nMerging results...")
    merged_vulns = merge_vulnerabilities(all_vulns)
    print(f"Unique vulnerabilities after merge: {len(merged_vulns)}")
    
    # Count by severity
    severity_counts = defaultdict(int)
    for vuln in merged_vulns:
        severity_counts[vuln['severity']] += 1
    
    print("\nVulnerabilities by severity:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN']:
        if severity in severity_counts:
            print(f"  {severity}: {severity_counts[severity]}")
    
    # Save outputs - one file per image
    print("\nSaving reports (1 file per image)...")
    print("\nJSON reports:")
    json_files = save_json_report_per_image(merged_vulns, output_dir)
    
    print("\nCSV reports:")
    csv_files = save_csv_report_per_image(merged_vulns, output_dir)
    
    print("\n" + "=" * 60)
    print("Merge completed successfully!")
    print(f"Generated {len(json_files)} JSON and {len(csv_files)} CSV reports")
    print("=" * 60)


if __name__ == "__main__":
    main()
