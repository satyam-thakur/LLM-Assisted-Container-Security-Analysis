"""
Analyze Combined Scanner Results
Generates statistics and insights from the merged vulnerability data
Analyzes each image separately and saves results to .txt files
"""

import json
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime


def load_combined_report(report_path):
    """Load a combined JSON report for a single image"""
    with open(report_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def analyze_scanner_coverage(vulns, output_lines):
    """Analyze which scanners detected which vulnerabilities"""
    output_lines.append("=" * 80)
    output_lines.append("SCANNER COVERAGE ANALYSIS")
    output_lines.append("=" * 80)
    
    scanner_counts = Counter()
    both_scanners = 0
    only_trivy = 0
    only_grype = 0
    
    for vuln in vulns:
        detected_by = vuln['detected_by']
        
        if len(detected_by) == 2:
            both_scanners += 1
        elif 'trivy' in detected_by:
            only_trivy += 1
        elif 'grype' in detected_by:
            only_grype += 1
        
        for scanner in detected_by:
            scanner_counts[scanner] += 1
    
    total = len(vulns)
    output_lines.append(f"\nTotal unique vulnerabilities: {total}")
    
    output_lines.append("\nScanner Detection Statistics:")
    output_lines.append(f"  Both Scanners (Agreement): {both_scanners} ({both_scanners/total*100:.1f}%)")
    output_lines.append(f"  Only Trivy:                {only_trivy} ({only_trivy/total*100:.1f}%)")
    output_lines.append(f"  Only Grype:                {only_grype} ({only_grype/total*100:.1f}%)")
    
    output_lines.append(f"\nTotal Detections per Scanner:")
    for scanner, count in scanner_counts.most_common():
        output_lines.append(f"  {scanner.capitalize()}: {count}")
    
    # Discrepancy analysis
    output_lines.append(f"\nDiscrepancy Analysis:")
    discrepancy_rate = ((only_trivy + only_grype) / total * 100) if total > 0 else 0
    output_lines.append(f"  Scanner Agreement Rate: {both_scanners/total*100:.1f}%")
    output_lines.append(f"  Scanner Discrepancy Rate: {discrepancy_rate:.1f}%")
    output_lines.append(f"  Trivy-exclusive findings: {only_trivy}")
    output_lines.append(f"  Grype-exclusive findings: {only_grype}")
    
    return output_lines


def analyze_severity_distribution(vulns, output_lines):
    """Analyze vulnerabilities by severity"""
    output_lines.append("\n" + "=" * 80)
    output_lines.append("SEVERITY DISTRIBUTION")
    output_lines.append("=" * 80)
    
    severity_counts = Counter(v['severity'] for v in vulns)
    
    output_lines.append("\nVulnerability Breakdown by Severity:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN']:
        if severity in severity_counts:
            count = severity_counts[severity]
            pct = count / len(vulns) * 100
            output_lines.append(f"  {severity:<12}: {count:>4} ({pct:>5.1f}%)")
    
    return output_lines


def analyze_top_packages(vulns, output_lines, top_n=10):
    """Find packages with most vulnerabilities"""
    output_lines.append("\n" + "=" * 80)
    output_lines.append(f"TOP {top_n} MOST VULNERABLE PACKAGES")
    output_lines.append("=" * 80)
    
    package_vulns = defaultdict(list)
    
    for vuln in vulns:
        package_vulns[vuln['package_name']].append(vuln)
    
    # Sort by count
    sorted_packages = sorted(package_vulns.items(), key=lambda x: len(x[1]), reverse=True)
    
    output_lines.append(f"\n{'Package':<35} {'Count':<8} {'Critical':<10} {'High':<8}")
    output_lines.append("-" * 80)
    
    for package, pkg_vulns in sorted_packages[:top_n]:
        critical = sum(1 for v in pkg_vulns if v['severity'] == 'CRITICAL')
        high = sum(1 for v in pkg_vulns if v['severity'] == 'HIGH')
        output_lines.append(f"{package:<35} {len(pkg_vulns):<8} {critical:<10} {high:<8}")
    
    return output_lines


def analyze_fixable_vulns(vulns, output_lines):
    """Analyze how many vulnerabilities have fixes available"""
    output_lines.append("\n" + "=" * 80)
    output_lines.append("FIXABLE VULNERABILITIES ANALYSIS")
    output_lines.append("=" * 80)
    
    total = len(vulns)
    fixable = 0
    by_severity = defaultdict(lambda: {'total': 0, 'fixable': 0})
    
    for vuln in vulns:
        severity = vuln['severity']
        by_severity[severity]['total'] += 1
        
        if vuln['fixed_version'] != 'No fix available':
            fixable += 1
            by_severity[severity]['fixable'] += 1
    
    output_lines.append(f"\nOverall Fix Availability:")
    output_lines.append(f"  Total vulnerabilities: {total}")
    output_lines.append(f"  Fixable: {fixable} ({fixable/total*100:.1f}%)")
    output_lines.append(f"  Not fixable: {total - fixable} ({(total-fixable)/total*100:.1f}%)")
    
    output_lines.append(f"\nFix Availability by Severity:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN']:
        if severity in by_severity:
            stats = by_severity[severity]
            pct = stats['fixable']/stats['total']*100 if stats['total'] > 0 else 0
            output_lines.append(f"  {severity:<12}: {stats['fixable']:>3}/{stats['total']:<3} fixable ({pct:>5.1f}%)")
    
    return output_lines


def analyze_critical_high(vulns, output_lines):
    """Focus on critical and high severity vulnerabilities"""
    output_lines.append("\n" + "=" * 80)
    output_lines.append("CRITICAL & HIGH SEVERITY VULNERABILITIES")
    output_lines.append("=" * 80)
    
    critical_high = [v for v in vulns if v['severity'] in ['CRITICAL', 'HIGH']]
    
    output_lines.append(f"\nTotal Critical + High: {len(critical_high)}")
    
    if not critical_high:
        output_lines.append("  No critical or high severity vulnerabilities found!")
        return output_lines
    
    # Group by CVE
    cve_counts = Counter(v['cve_id'] for v in critical_high)
    
    output_lines.append(f"\nMost Common Critical/High CVEs:")
    for cve, count in cve_counts.most_common(15):
        # Find one instance to get details
        example = next(v for v in critical_high if v['cve_id'] == cve)
        output_lines.append(f"\n  {cve} ({example['severity']})")
        output_lines.append(f"    Package: {example['package_name']} {example['installed_version']}")
        output_lines.append(f"    Fixed in: {example['fixed_version']}")
        output_lines.append(f"    Detected by: {', '.join(example['detected_by'])}")
    
    return output_lines


def analyze_scanner_comparison(vulns, output_lines):
    """Detailed comparison of scanner-specific findings"""
    output_lines.append("\n" + "=" * 80)
    output_lines.append("DETAILED SCANNER COMPARISON")
    output_lines.append("=" * 80)
    
    trivy_only = [v for v in vulns if v['detected_by'] == ['trivy']]
    grype_only = [v for v in vulns if v['detected_by'] == ['grype']]
    both = [v for v in vulns if len(v['detected_by']) == 2]
    
    output_lines.append(f"\nTrivy-Only Vulnerabilities: {len(trivy_only)}")
    if trivy_only:
        trivy_severity = Counter(v['severity'] for v in trivy_only)
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE']:
            if severity in trivy_severity:
                output_lines.append(f"  {severity}: {trivy_severity[severity]}")
    
    output_lines.append(f"\nGrype-Only Vulnerabilities: {len(grype_only)}")
    if grype_only:
        grype_severity = Counter(v['severity'] for v in grype_only)
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE']:
            if severity in grype_severity:
                output_lines.append(f"  {severity}: {grype_severity[severity]}")
    
    output_lines.append(f"\nBoth Scanners Agreement: {len(both)}")
    if both:
        both_severity = Counter(v['severity'] for v in both)
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE']:
            if severity in both_severity:
                output_lines.append(f"  {severity}: {both_severity[severity]}")
    
    return output_lines


def analyze_image(report_path, output_dir):
    """Analyze a single image report and save to .txt file"""
    print(f"\nAnalyzing: {report_path.name}")
    
    # Load report
    data = load_combined_report(report_path)
    image_name = data['image']
    vulns = data['vulnerabilities']
    
    # Initialize output lines
    output_lines = []
    
    # Header
    output_lines.append("=" * 80)
    output_lines.append("CONTAINER SECURITY VULNERABILITY ANALYSIS REPORT")
    output_lines.append("=" * 80)
    output_lines.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    output_lines.append(f"Image: {image_name}")
    output_lines.append(f"Total Vulnerabilities: {len(vulns)}")
    output_lines.append(f"Scanners Used: {', '.join(data['scanners_used'])}")
    
    # Run all analyses
    analyze_scanner_coverage(vulns, output_lines)
    analyze_severity_distribution(vulns, output_lines)
    analyze_top_packages(vulns, output_lines)
    analyze_fixable_vulns(vulns, output_lines)
    analyze_critical_high(vulns, output_lines)
    analyze_scanner_comparison(vulns, output_lines)
    
    # Footer
    output_lines.append("\n" + "=" * 80)
    output_lines.append("END OF ANALYSIS REPORT")
    output_lines.append("=" * 80)
    
    # Save to file
    safe_name = image_name.replace(':', '_').replace('/', '_').replace('\\', '_')
    output_path = output_dir / f'{safe_name}_analysis.txt'
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))
    
    print(f"  → Analysis saved: {output_path.name}")
    return output_path


def main():
    """Main analysis function"""
    # Setup paths
    base_dir = Path(__file__).parent
    combined_dir = base_dir / 'combined_results'
    output_dir = base_dir / 'analyzed_results'
    
    # Create output directory
    output_dir.mkdir(exist_ok=True)
    
    if not combined_dir.exists():
        print(f"Error: Combined results directory not found at {combined_dir}")
        print("Run combine_scanner_results.py first!")
        return
    
    # Find all combined JSON reports
    json_files = list(combined_dir.glob('*_combined.json'))
    
    if not json_files:
        print(f"Error: No combined reports found in {combined_dir}")
        print("Run combine_scanner_results.py first!")
        return
    
    print("=" * 80)
    print("CONTAINER SECURITY ANALYSIS")
    print("=" * 80)
    print(f"\nFound {len(json_files)} image report(s) to analyze")
    
    # Analyze each image
    analyzed_files = []
    for json_file in json_files:
        output_path = analyze_image(json_file, output_dir)
        analyzed_files.append(output_path)
    
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE!")
    print("=" * 80)
    print(f"\nGenerated {len(analyzed_files)} analysis report(s)")
    print(f"Output directory: {output_dir}")
    print("\nAnalysis files:")
    for f in analyzed_files:
        print(f"  - {f.name}")


if __name__ == "__main__":
    main()
