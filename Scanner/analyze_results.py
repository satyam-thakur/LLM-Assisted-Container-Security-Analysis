"""
Analyze Combined Scanner Results
Generates statistics and insights from the merged vulnerability data
"""

import json
from pathlib import Path
from collections import defaultdict, Counter


def load_combined_report(report_path):
    """Load the combined JSON report"""
    with open(report_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def analyze_scanner_coverage(data):
    """Analyze which scanners detected which vulnerabilities"""
    print("\n" + "=" * 60)
    print("Scanner Coverage Analysis")
    print("=" * 60)
    
    scanner_counts = Counter()
    both_scanners = 0
    only_trivy = 0
    only_grype = 0
    
    for image, vulns in data['images'].items():
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
    
    print(f"\nTotal unique vulnerabilities: {data['total_vulnerabilities']}")
    print(f"\nVulnerabilities detected by:")
    print(f"  Both scanners: {both_scanners} ({both_scanners/data['total_vulnerabilities']*100:.1f}%)")
    print(f"  Only Trivy:    {only_trivy} ({only_trivy/data['total_vulnerabilities']*100:.1f}%)")
    print(f"  Only Grype:    {only_grype} ({only_grype/data['total_vulnerabilities']*100:.1f}%)")
    
    print(f"\nTotal detections per scanner:")
    for scanner, count in scanner_counts.most_common():
        print(f"  {scanner.capitalize()}: {count}")


def analyze_by_image(data):
    """Analyze vulnerabilities per image"""
    print("\n" + "=" * 60)
    print("Vulnerabilities by Image")
    print("=" * 60)
    
    for image, vulns in data['images'].items():
        severity_counts = Counter(v['severity'] for v in vulns)
        
        print(f"\n{image}")
        print(f"  Total: {len(vulns)}")
        print(f"  Breakdown:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE']:
            if severity in severity_counts:
                print(f"    {severity}: {severity_counts[severity]}")


def analyze_top_packages(data, top_n=10):
    """Find packages with most vulnerabilities"""
    print("\n" + "=" * 60)
    print(f"Top {top_n} Most Vulnerable Packages")
    print("=" * 60)
    
    package_vulns = defaultdict(list)
    
    for image, vulns in data['images'].items():
        for vuln in vulns:
            package_vulns[vuln['package_name']].append(vuln)
    
    # Sort by count
    sorted_packages = sorted(package_vulns.items(), key=lambda x: len(x[1]), reverse=True)
    
    print(f"\n{'Package':<30} {'Count':<8} {'Critical':<10} {'High':<8}")
    print("-" * 60)
    
    for package, vulns in sorted_packages[:top_n]:
        critical = sum(1 for v in vulns if v['severity'] == 'CRITICAL')
        high = sum(1 for v in vulns if v['severity'] == 'HIGH')
        print(f"{package:<30} {len(vulns):<8} {critical:<10} {high:<8}")


def analyze_fixable_vulns(data):
    """Analyze how many vulnerabilities have fixes available"""
    print("\n" + "=" * 60)
    print("Fixable Vulnerabilities Analysis")
    print("=" * 60)
    
    total = 0
    fixable = 0
    by_severity = defaultdict(lambda: {'total': 0, 'fixable': 0})
    
    for image, vulns in data['images'].items():
        for vuln in vulns:
            total += 1
            severity = vuln['severity']
            by_severity[severity]['total'] += 1
            
            if vuln['fixed_version'] != 'No fix available':
                fixable += 1
                by_severity[severity]['fixable'] += 1
    
    print(f"\nOverall:")
    print(f"  Total vulnerabilities: {total}")
    print(f"  Fixable: {fixable} ({fixable/total*100:.1f}%)")
    print(f"  Not fixable: {total - fixable} ({(total-fixable)/total*100:.1f}%)")
    
    print(f"\nBy Severity:")
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE']:
        if severity in by_severity:
            stats = by_severity[severity]
            pct = stats['fixable']/stats['total']*100 if stats['total'] > 0 else 0
            print(f"  {severity:<12} {stats['fixable']}/{stats['total']} fixable ({pct:.1f}%)")


def analyze_critical_high(data):
    """Focus on critical and high severity vulnerabilities"""
    print("\n" + "=" * 60)
    print("Critical & High Severity Vulnerabilities")
    print("=" * 60)
    
    critical_high = []
    
    for image, vulns in data['images'].items():
        for vuln in vulns:
            if vuln['severity'] in ['CRITICAL', 'HIGH']:
                critical_high.append(vuln)
    
    print(f"\nTotal Critical + High: {len(critical_high)}")
    
    # Group by CVE
    cve_counts = Counter(v['cve_id'] for v in critical_high)
    
    print(f"\nMost common Critical/High CVEs:")
    for cve, count in cve_counts.most_common(10):
        # Find one instance to get details
        example = next(v for v in critical_high if v['cve_id'] == cve)
        print(f"  {cve} ({example['severity']})")
        print(f"    Found in {count} image(s), Package: {example['package_name']}")


def main():
    """Main analysis function"""
    # Load report
    report_path = Path(__file__).parent / 'combined_results' / 'combined_report.json'
    
    if not report_path.exists():
        print(f"Error: Report not found at {report_path}")
        print("Run combine_scanner_results.py first!")
        return
    
    print("Loading combined report...")
    data = load_combined_report(report_path)
    
    # Run analyses
    analyze_scanner_coverage(data)
    analyze_by_image(data)
    analyze_top_packages(data)
    analyze_fixable_vulns(data)
    analyze_critical_high(data)
    
    print("\n" + "=" * 60)
    print("Analysis Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
