#!/usr/bin/env python3
"""
Batch Scanner - Scan multiple targets
WebSecure Analyzer
Developed by: Kailas
Date: January 2026
"""

import asyncio
import subprocess
import sys
from datetime import datetime
from pathlib import Path
import json


class BatchScanner:
    """Utility for scanning multiple targets"""
    
    def __init__(self, targets_file: str = "targets.txt"):
        self.targets_file = Path(targets_file)
        self.results_dir = Path("batch_results") / datetime.now().strftime('%Y%m%d_%H%M%S')
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
    def load_targets(self):
        """Load targets from file"""
        if not self.targets_file.exists():
            print(f"❌ Target file not found: {self.targets_file}")
            print("\nCreate a 'targets.txt' file with one URL per line:")
            print("  https://example1.com")
            print("  https://example2.com")
            print("  https://example3.com")
            return []
        
        with open(self.targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        return targets
    
    def scan_target(self, target: str, index: int):
        """Scan a single target"""
        print(f"\n{'='*60}")
        print(f"Scanning {index}: {target}")
        print(f"{'='*60}")
        
        # Create output filename
        safe_name = target.replace('https://', '').replace('http://', '').replace('/', '_')
        output_file = self.results_dir / f"scan_{index:03d}_{safe_name}.md"
        
        # Run scanner
        cmd = [
            sys.executable,
            "websecure_analyzer.py",
            target,
            "-o", str(output_file),
            "-v"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            status = {
                'target': target,
                'status': 'completed' if result.returncode == 0 else 'failed',
                'output_file': str(output_file),
                'exit_code': result.returncode
            }
            
            if result.returncode != 0:
                print(f"⚠️  Scan failed with exit code {result.returncode}")
                status['error'] = result.stderr
            else:
                print(f"✅ Scan completed successfully")
            
            return status
            
        except subprocess.TimeoutExpired:
            print(f"⏱️  Scan timed out after 5 minutes")
            return {
                'target': target,
                'status': 'timeout',
                'output_file': str(output_file)
            }
        except Exception as e:
            print(f"❌ Error scanning: {e}")
            return {
                'target': target,
                'status': 'error',
                'error': str(e)
            }
    
    def run_batch_scan(self):
        """Execute batch scan on all targets"""
        print("="*60)
        print("WebSecure Analyzer - Batch Scanner")
        print("Developed by: Kailas")
        print("="*60)
        
        targets = self.load_targets()
        
        if not targets:
            return
        
        print(f"\n📋 Found {len(targets)} targets to scan")
        print(f"📁 Results will be saved to: {self.results_dir}")
        
        confirm = input("\n⚠️  Make sure you have authorization for ALL targets. Continue? (yes/no): ")
        
        if confirm.lower() not in ['yes', 'y']:
            print("Batch scan cancelled.")
            return
        
        results = []
        start_time = datetime.now()
        
        for idx, target in enumerate(targets, 1):
            result = self.scan_target(target, idx)
            results.append(result)
        
        duration = (datetime.now() - start_time).total_seconds()
        
        # Generate summary report
        self.generate_summary(results, duration)
    
    def generate_summary(self, results: list, duration: float):
        """Generate summary report of batch scan"""
        summary_file = self.results_dir / "batch_summary.json"
        report_file = self.results_dir / "batch_report.md"
        
        # Count statuses
        completed = sum(1 for r in results if r['status'] == 'completed')
        failed = sum(1 for r in results if r['status'] == 'failed')
        timeout = sum(1 for r in results if r['status'] == 'timeout')
        errors = sum(1 for r in results if r['status'] == 'error')
        
        # Save JSON summary
        summary = {
            'scan_date': datetime.now().isoformat(),
            'total_targets': len(results),
            'completed': completed,
            'failed': failed,
            'timeout': timeout,
            'errors': errors,
            'duration_seconds': duration,
            'results': results
        }
        
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Generate Markdown report
        report = f"""# Batch Scan Report

**Developed by:** Kailas  
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Duration:** {duration:.2f} seconds

## Summary

- **Total Targets:** {len(results)}
- **✅ Completed:** {completed}
- **❌ Failed:** {failed}
- **⏱️ Timeout:** {timeout}
- **🚫 Errors:** {errors}

## Results

"""
        
        for idx, result in enumerate(results, 1):
            status_emoji = {
                'completed': '✅',
                'failed': '❌',
                'timeout': '⏱️',
                'error': '🚫'
            }.get(result['status'], '❓')
            
            report += f"### {idx}. {result['target']}\n\n"
            report += f"- **Status:** {status_emoji} {result['status']}\n"
            
            if result['status'] == 'completed':
                report += f"- **Report:** [{result['output_file']}]({result['output_file']})\n"
            
            if 'error' in result:
                report += f"- **Error:** {result.get('error', 'Unknown error')}\n"
            
            report += "\n"
        
        report += f"""
---

**Batch scan completed by WebSecure Analyzer v2.0**  
*Developed by Kailas - January 2026*
"""
        
        with open(report_file, 'w') as f:
            f.write(report)
        
        print(f"\n{'='*60}")
        print(f"Batch Scan Complete!")
        print(f"{'='*60}")
        print(f"📊 Summary: {completed} completed, {failed} failed, {timeout} timeout, {errors} errors")
        print(f"📁 Results saved to: {self.results_dir}")
        print(f"📄 Summary report: {summary_file}")
        print(f"📄 Markdown report: {report_file}")
        print(f"⏱️  Total duration: {duration:.2f} seconds")


def create_sample_targets_file():
    """Create a sample targets file"""
    sample_file = Path("targets.txt")
    
    if sample_file.exists():
        print(f"File 'targets.txt' already exists")
        return
    
    sample_content = """# WebSecure Analyzer - Batch Scan Targets
# One URL per line
# Lines starting with # are comments

# Example targets (replace with your authorized targets):
# https://example1.com
# https://example2.com
# https://testsite.local

# Add your targets below:

"""
    
    with open(sample_file, 'w') as f:
        f.write(sample_content)
    
    print(f"✅ Created sample file: targets.txt")
    print(f"📝 Edit this file and add your authorized scan targets")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Batch scanner for multiple targets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python batch_scanner.py
  python batch_scanner.py --targets my_targets.txt
  python batch_scanner.py --create-sample

Developed by: Kailas
"""
    )
    
    parser.add_argument('--targets', '-t', default='targets.txt',
                       help='File containing target URLs (one per line)')
    parser.add_argument('--create-sample', action='store_true',
                       help='Create a sample targets.txt file')
    
    args = parser.parse_args()
    
    if args.create_sample:
        create_sample_targets_file()
        return
    
    scanner = BatchScanner(args.targets)
    scanner.run_batch_scan()


if __name__ == "__main__":
    main()
