"""
WebSecure Analyzer - Utility Functions
Developed by: Kailas
Date: January 2026

Helper utilities for security analysis and reporting.
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path


class ReportGenerator:
    """Utility class for generating security reports"""
    
    @staticmethod
    def generate_html_summary(findings: List[Dict], target: str) -> str:
        """Generate HTML summary report"""
        severity_colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8'
        }
        
        severity_counts = {}
        for finding in findings:
            sev = finding.get('severity', 'info')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 8px; }}
        .finding {{ background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #ccc; }}
        .severity {{ padding: 5px 10px; color: white; border-radius: 4px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Security Assessment Report</h1>
        <p>Target: {target}</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>By: Kailas - WebSecure Analyzer v2.0</p>
    </div>
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Findings: {len(findings)}</p>
"""
        for sev, count in severity_counts.items():
            color = severity_colors.get(sev, '#6c757d')
            html += f'<span class="severity" style="background:{color}">{sev.upper()}: {count}</span> '
        
        html += """
    </div>
    <div class="findings">
        <h2>Detailed Findings</h2>
"""
        
        for idx, finding in enumerate(findings, 1):
            sev = finding.get('severity', 'info')
            color = severity_colors.get(sev, '#6c757d')
            html += f"""
        <div class="finding" style="border-left-color: {color}">
            <h3>Finding #{idx}</h3>
            <p><strong>Severity:</strong> <span class="severity" style="background:{color}">{sev.upper()}</span></p>
            <p><strong>Endpoint:</strong> {finding.get('endpoint', 'N/A')}</p>
            <p><strong>Description:</strong> {finding.get('description', 'N/A')}</p>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    @staticmethod
    def export_to_csv(findings: List[Dict], output_path: str):
        """Export findings to CSV format"""
        import csv
        
        if not findings:
            return
        
        keys = findings[0].keys()
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(findings)


class ScanValidator:
    """Validates scan results and deduplicates findings"""
    
    @staticmethod
    def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings based on endpoint and vulnerability type"""
        seen = set()
        unique_findings = []
        
        for finding in findings:
            key = f"{finding.get('endpoint')}:{finding.get('description')}"
            fingerprint = hashlib.md5(key.encode()).hexdigest()
            
            if fingerprint not in seen:
                seen.add(fingerprint)
                unique_findings.append(finding)
        
        return unique_findings
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate if URL is properly formatted"""
        from urllib.parse import urlparse
        
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False


class ConfigManager:
    """Manages configuration loading and validation"""
    
    def __init__(self, config_path: str = "config.json"):
        self.config_path = Path(config_path)
        self.config = self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                return json.load(f)
        return self.get_default_config()
    
    def get_default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            "scanner_settings": {
                "max_depth": 3,
                "max_pages": 100,
                "timeout": 30,
                "concurrent_workers": 5
            }
        }
    
    def get(self, key: str, default=None):
        """Get configuration value"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        
        return value if value is not None else default


class SecurityMetrics:
    """Calculate security metrics and statistics"""
    
    @staticmethod
    def calculate_risk_score(findings: List[Dict]) -> float:
        """Calculate overall risk score (0-100)"""
        if not findings:
            return 0.0
        
        severity_weights = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3,
            'info': 1
        }
        
        total_score = sum(
            severity_weights.get(f.get('severity', 'info'), 1)
            for f in findings
        )
        
        # Normalize to 0-100 scale
        max_possible = len(findings) * 25
        return min(100, (total_score / max_possible * 100) if max_possible > 0 else 0)
    
    @staticmethod
    def generate_compliance_report(findings: List[Dict]) -> Dict[str, Any]:
        """Generate compliance status report"""
        critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
        high_count = sum(1 for f in findings if f.get('severity') == 'high')
        
        compliance_status = 'PASS'
        if critical_count > 0:
            compliance_status = 'FAIL'
        elif high_count > 3:
            compliance_status = 'WARNING'
        
        return {
            'status': compliance_status,
            'critical_issues': critical_count,
            'high_issues': high_count,
            'requires_immediate_action': critical_count > 0,
            'recommendation': 'Fix critical and high severity issues before deployment'
        }


def format_timestamp(dt: datetime = None) -> str:
    """Format datetime for reports"""
    if dt is None:
        dt = datetime.now()
    return dt.strftime('%Y-%m-%d %H:%M:%S')


def create_scan_directory(base_path: str = "./scan_results") -> Path:
    """Create directory for scan results"""
    scan_dir = Path(base_path) / datetime.now().strftime('%Y%m%d_%H%M%S')
    scan_dir.mkdir(parents=True, exist_ok=True)
    return scan_dir


# Example usage
if __name__ == "__main__":
    print("WebSecure Analyzer Utilities")
    print("Developed by: Kailas")
    print("\nThis module provides helper functions for the analyzer.")
    print("Import these utilities in your scanning scripts.")
