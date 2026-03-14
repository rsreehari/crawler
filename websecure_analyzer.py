"""
WebSecure CSRF Vulnerability Analyzer
Developed by: Kailas
Date: January 2026

Advanced security research tool for detecting CSRF vulnerabilities
through intelligent web crawling and deep form analysis.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Set, List, Dict, Optional, Tuple
from enum import Enum
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import argparse
import json
import logging
from datetime import datetime
from pathlib import Path
import re


class VulnerabilitySeverity(Enum):
    """Classification of security vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class ProtectionMechanism(Enum):
    """Types of CSRF protection mechanisms"""
    TOKEN_BASED = "token_based"
    SAME_SITE_COOKIE = "samesite_cookie"
    CUSTOM_HEADER = "custom_header"
    DOUBLE_SUBMIT = "double_submit"
    ORIGIN_VERIFICATION = "origin_verification"


@dataclass
class SecurityFinding:
    """Represents a detected security vulnerability"""
    finding_id: str
    page_location: str
    endpoint_target: str
    http_method: str
    risk_level: VulnerabilitySeverity
    description: str
    missing_protections: List[ProtectionMechanism] = field(default_factory=list)
    form_inputs: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        """Convert finding to dictionary format"""
        return {
            'id': self.finding_id,
            'page': self.page_location,
            'endpoint': self.endpoint_target,
            'method': self.http_method,
            'severity': self.risk_level.value,
            'description': self.description,
            'missing_protections': [p.value for p in self.missing_protections],
            'form_fields': self.form_inputs,
            'recommendations': self.recommendations,
            'detected_at': self.timestamp.isoformat()
        }


class SecurityAnalyzer(ABC):
    """Abstract base class for security analysis modules"""
    
    @abstractmethod
    async def analyze(self, content: str, metadata: Dict) -> List[SecurityFinding]:
        """Perform security analysis on content"""
        pass


class FormSecurityAnalyzer(SecurityAnalyzer):
    """Analyzes HTML forms for CSRF vulnerabilities"""
    
    PROTECTION_PATTERNS = {
        'csrf': r'csrf[-_]?token|authenticity[-_]?token|__requestverificationtoken',
        'nonce': r'nonce|_wpnonce',
        'state': r'state|anti[-_]?forgery'
    }
    
    async def analyze(self, content: str, metadata: Dict) -> List[SecurityFinding]:
        """Examine forms for security weaknesses"""
        findings = []
        soup = BeautifulSoup(content, 'html.parser')
        forms = soup.find_all('form')
        
        for idx, form in enumerate(forms, 1):
            finding = await self._examine_form(form, metadata, idx)
            if finding:
                findings.append(finding)
        
        return findings
    
    async def _examine_form(self, form, metadata: Dict, form_number: int) -> Optional[SecurityFinding]:
        """Deep analysis of individual form element"""
        method = form.get('method', 'get').upper()
        
        if method != 'POST':
            return None
        
        action = form.get('action', metadata['current_url'])
        if not action.startswith('http'):
            action = urljoin(metadata['current_url'], action)
        
        # Detect protection mechanisms
        protections = self._detect_protections(form, metadata)
        inputs = [inp.get('name', 'unnamed') for inp in form.find_all('input') if inp.get('name')]
        
        # Print form found (like old scanner)
        print(f"[+] form found at {metadata['current_url']} -> action='{action}'")
        
        if not protections:
            # Print missing CSRF token (like old scanner)
            print(f"    [!] Possible missing CSRF token at {action}")
            return SecurityFinding(
                finding_id=f"CSRF-{metadata['scan_id']}-{form_number:03d}",
                page_location=metadata['current_url'],
                endpoint_target=action,
                http_method=method,
                risk_level=self._calculate_risk(inputs),
                description="Form lacks CSRF protection mechanisms",
                missing_protections=[ProtectionMechanism.TOKEN_BASED],
                form_inputs=inputs,
                recommendations=self._generate_recommendations(protections)
            )
        
        return None
    
    def _detect_protections(self, form, metadata: Dict) -> List[ProtectionMechanism]:
        """Identify active protection mechanisms"""
        protections = []
        
        # Check for token-based protection
        for pattern_name, pattern in self.PROTECTION_PATTERNS.items():
            inputs = form.find_all('input', {'name': re.compile(pattern, re.IGNORECASE)})
            if inputs:
                protections.append(ProtectionMechanism.TOKEN_BASED)
                break
        
        # Check SameSite cookies
        if metadata.get('has_samesite_cookies'):
            protections.append(ProtectionMechanism.SAME_SITE_COOKIE)
        
        # Check for custom headers requirement
        if metadata.get('requires_custom_headers'):
            protections.append(ProtectionMechanism.CUSTOM_HEADER)
        
        return protections
    
    def _calculate_risk(self, inputs: List[str]) -> VulnerabilitySeverity:
        """Determine severity based on form inputs"""
        high_risk_keywords = ['password', 'email', 'admin', 'delete', 'transfer', 'payment']
        
        for inp in inputs:
            if any(keyword in inp.lower() for keyword in high_risk_keywords):
                return VulnerabilitySeverity.HIGH
        
        return VulnerabilitySeverity.MEDIUM
    
    def _generate_recommendations(self, existing_protections: List[ProtectionMechanism]) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        if ProtectionMechanism.TOKEN_BASED not in existing_protections:
            recommendations.append("Implement synchronizer token pattern with unique CSRF tokens")
        
        if ProtectionMechanism.SAME_SITE_COOKIE not in existing_protections:
            recommendations.append("Configure SameSite=Strict or SameSite=Lax on session cookies")
        
        recommendations.append("Validate Origin and Referer headers for state-changing operations")
        recommendations.append("Consider implementing double-submit cookie pattern as defense-in-depth")
        
        return recommendations


class WebCrawler:
    """Intelligent web crawler with rate limiting and deduplication"""
    
    def __init__(self, root_url: str, max_depth: int = 3, max_pages: int = 100, verbose: bool = False):
        self.root_url = root_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.domain = urlparse(root_url).netloc
        self.queue: asyncio.Queue = asyncio.Queue()
        self.logger = logging.getLogger(__name__)
        self.verbose = verbose
        
    async def crawl(self) -> Set[str]:
        """Execute crawling operation"""
        await self.queue.put((self.root_url, 0))
        
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'SecurityAnalyzer/2.0'}
        ) as session:
            workers = [
                asyncio.create_task(self._worker(session))
                for _ in range(5)
            ]
            
            await self.queue.join()
            
            for worker in workers:
                worker.cancel()
        
        return self.visited
    
    async def _worker(self, session: aiohttp.ClientSession):
        """Worker coroutine for processing URLs"""
        while True:
            try:
                url, depth = await self.queue.get()
                
                if url in self.visited or depth > self.max_depth or len(self.visited) >= self.max_pages:
                    self.queue.task_done()
                    continue
                
                self.visited.add(url)
                if self.verbose:
                    print(f"[→] Crawling: {url} (depth: {depth})")
                
                links = await self._fetch_and_extract_links(session, url)
                
                if self.verbose and links:
                    print(f"[+] Found {len(links)} links on {url}")
                
                for link in links:
                    if link not in self.visited:
                        await self.queue.put((link, depth + 1))
                
                self.queue.task_done()
                await asyncio.sleep(0.5)  # Rate limiting
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[x] Worker error: {e}")
                self.queue.task_done()
    
    async def _fetch_and_extract_links(self, session: aiohttp.ClientSession, url: str) -> Set[str]:
        """Fetch page and extract valid links"""
        try:
            async with session.get(url) as response:
                if response.status != 200:
                    return set()
                
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                links = set()
                for anchor in soup.find_all('a', href=True):
                    absolute_url = urljoin(url, anchor['href'])
                    if self._is_valid_url(absolute_url):
                        links.add(absolute_url)
                
                return links
                
        except Exception as e:
            print(f"[x] Error at {url}: {e}")
            return set()
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL against crawling criteria"""
        parsed = urlparse(url)
        return (
            parsed.netloc == self.domain and
            parsed.scheme in ['http', 'https'] and
            not any(ext in parsed.path.lower() for ext in ['.pdf', '.jpg', '.png', '.css', '.js'])
        )


class VulnerabilityScanner:
    """Main orchestrator for security vulnerability detection"""
    
    def __init__(self, target_url: str, config: Dict):
        self.target_url = target_url
        self.config = config
        self.findings: List[SecurityFinding] = []
        self.scan_id = datetime.now().strftime('%Y%m%d%H%M%S')
        self.logger = self._configure_logging()
        self.analyzers = [FormSecurityAnalyzer()]
        
    def _configure_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO if self.config.get('verbose') else logging.WARNING)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    async def execute_scan(self):
        """Run comprehensive security scan"""
        # Silent - banner already printed
        start_time = datetime.now()
        
        # Phase 1: Discovery
        print(f"\n[*] Phase 1: Web Crawling (max depth: {self.config.get('depth', 3)}, max pages: {self.config.get('max_pages', 100)})")
        print(f"[*] Starting from: {self.target_url}")
        
        crawler = WebCrawler(
            self.target_url,
            max_depth=self.config.get('depth', 3),
            max_pages=self.config.get('max_pages', 100),
            verbose=self.config.get('verbose', False)
        )
        discovered_urls = await crawler.crawl()
        print(f"[✓] Crawl complete: {len(discovered_urls)} pages discovered")
        
        # Phase 2: Analysis
        print(f"\n[*] Phase 2: Security Analysis")
        print(f"[*] Analyzing {len(discovered_urls)} pages for CSRF vulnerabilities...\n")
        
        connector = aiohttp.TCPConnector(limit=10)
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self._analyze_page(session, url) for url in discovered_urls]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        duration = (datetime.now() - start_time).total_seconds()
        print(f"\n[✓] Analysis complete!")
        print(f"[✓] Total vulnerabilities found: {len(self.findings)}")
        print(f"[✓] Scan duration: {duration:.2f} seconds")
        print(f"[*] Detailed report saved to: {self.config.get('output', 'security_report.md')}")
        
    async def _analyze_page(self, session: aiohttp.ClientSession, url: str):
        """Perform security analysis on a single page"""
        try:
            async with session.get(url) as response:
                content = await response.text()
                cookies = response.cookies
                headers = response.headers
                
                metadata = {
                    'current_url': url,
                    'scan_id': self.scan_id,
                    'has_samesite_cookies': self._check_samesite_cookies(cookies),
                    'requires_custom_headers': 'X-CSRF-Token' in headers
                }
                
                for analyzer in self.analyzers:
                    findings = await analyzer.analyze(content, metadata)
                    self.findings.extend(findings)
                    
        except Exception as e:
            print(f"[x] Error at {url}: {e}")
    
    def _check_samesite_cookies(self, cookies) -> bool:
        """Verify SameSite cookie attribute"""
        for cookie in cookies.values():
            if hasattr(cookie, 'get') and cookie.get('samesite'):
                return True
        return False
    
    def generate_report(self, output_path: str):
        """Generate comprehensive security report"""
        report_data = {
            'scan_metadata': {
                'scan_id': self.scan_id,
                'target': self.target_url,
                'timestamp': datetime.now().isoformat(),
                'total_findings': len(self.findings)
            },
            'findings': [f.to_dict() for f in self.findings],
            'summary': self._generate_summary()
        }
        
        # JSON output
        json_path = Path(output_path).with_suffix('.json')
        with open(json_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Human-readable output
        markdown_report = self._format_markdown_report(report_data)
        with open(output_path, 'w') as f:
            f.write(markdown_report)
        
        # Silent - already showed scan finished
    
    def _generate_summary(self) -> Dict:
        """Create executive summary of findings"""
        severity_counts = {}
        for finding in self.findings:
            severity = finding.risk_level.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'by_severity': severity_counts,
            'total_vulnerabilities': len(self.findings)
        }
    
    def _format_markdown_report(self, data: Dict) -> str:
        """Format report as Markdown"""
        lines = [
            "# Web Application Security Assessment Report",
            f"\n**Scan ID:** {data['scan_metadata']['scan_id']}",
            f"**Target:** {data['scan_metadata']['target']}",
            f"**Date:** {data['scan_metadata']['timestamp']}",
            f"\n## Executive Summary",
            f"\nTotal vulnerabilities detected: **{data['scan_metadata']['total_findings']}**",
            "\n### Findings by Severity"
        ]
        
        for severity, count in data['summary']['by_severity'].items():
            lines.append(f"- **{severity.upper()}**: {count}")
        
        lines.append("\n## Detailed Findings\n")
        
        for finding in data['findings']:
            lines.extend([
                f"### {finding['id']}",
                f"**Severity:** {finding['severity'].upper()}",
                f"**Page:** {finding['page']}",
                f"**Endpoint:** {finding['endpoint']}",
                f"**Method:** {finding['method']}",
                f"\n**Description:** {finding['description']}",
                f"\n**Recommendations:**"
            ])
            
            for rec in finding['recommendations']:
                lines.append(f"- {rec}")
            
            lines.append("\n---\n")
        
        return '\n'.join(lines)


async def main_async(args):
    """Async entry point for application"""
    import time
    start_time = time.time()
    
    config = {
        'verbose': args.verbose,
        'depth': args.depth,
        'max_pages': args.max_pages,
        'output': args.output
    }
    
    scanner = VulnerabilityScanner(args.url, config)
    await scanner.execute_scan()
    scanner.generate_report(args.output)
    
    duration = time.time() - start_time
    print(f"\n[Done] exited with code=0 in {duration:.3f} seconds")


def main():
    """Application entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced Web Application Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('url', help='Target URL for security assessment')
    parser.add_argument('-o', '--output', default='security_report.md',
                       help='Output file path (default: security_report.md)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging output')
    parser.add_argument('-d', '--depth', type=int, default=3,
                       help='Maximum crawl depth (default: 3)')
    parser.add_argument('-m', '--max-pages', type=int, default=100,
                       help='Maximum pages to analyze (default: 100)')
    
    args = parser.parse_args()
    
    print("[Running] python -u \"C:\\Users\\kailas\\Documents\\crawler\\CSRF-Vulnerability-Crawler-and-Research\\websecure_analyzer.py\"")
    print(f"[*] Starting CSRF scan on {args.url}")
    
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        raise


if __name__ == "__main__":
    main()
