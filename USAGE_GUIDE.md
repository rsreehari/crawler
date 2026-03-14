# WebSecure Analyzer - Complete Usage Guide

**Developer:** Kailas  
**Version:** 2.0.0  
**Last Updated:** January 16, 2026

---

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Advanced Features](#advanced-features)
5. [Configuration](#configuration)
6. [Understanding Reports](#understanding-reports)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)

---

## 🚀 Quick Start

### 30-Second Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run your first scan
python websecure_analyzer.py https://example.com

# View results
cat security_report.md
```

---

## 💾 Installation

### Prerequisites

- **Python 3.8+** (Python 3.10+ recommended)
- **pip** package manager
- **Virtual environment** (recommended)

### Step-by-Step Installation

```bash
# 1. Create a virtual environment (recommended)
python -m venv venv

# 2. Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python websecure_analyzer.py --help
```

---

## 🎯 Basic Usage

### Scan a Single Website

```bash
python websecure_analyzer.py https://example.com
```

### Specify Output File

```bash
python websecure_analyzer.py https://example.com -o my_scan_report.md
```

### Enable Verbose Logging

```bash
python websecure_analyzer.py https://example.com -v
```

### Control Crawl Depth

```bash
# Shallow scan (depth 2)
python websecure_analyzer.py https://example.com -d 2

# Deep scan (depth 5)
python websecure_analyzer.py https://example.com -d 5
```

### Limit Pages Scanned

```bash
# Quick scan (50 pages max)
python websecure_analyzer.py https://example.com -m 50

# Comprehensive scan (500 pages)
python websecure_analyzer.py https://example.com -m 500
```

---

## 🔥 Advanced Features

### Complete Scan with All Options

```bash
python websecure_analyzer.py https://example.com \
    --output detailed_security_report.md \
    --verbose \
    --depth 4 \
    --max-pages 200
```

### Using Configuration File

Edit `config.json` to customize scanner behavior:

```json
{
  "scanner_settings": {
    "max_depth": 5,
    "max_pages": 300,
    "concurrent_workers": 10
  }
}
```

Then run with default settings:

```bash
python websecure_analyzer.py https://example.com
```

### Scanning Multiple Domains

Create a batch script:

```bash
# scan_multiple.sh
python websecure_analyzer.py https://site1.com -o site1_report.md
python websecure_analyzer.py https://site2.com -o site2_report.md
python websecure_analyzer.py https://site3.com -o site3_report.md
```

---

## ⚙️ Configuration

### Configuration File Structure

The `config.json` file contains all scanner settings:

```json
{
  "scanner_settings": {
    "max_depth": 3,           // How deep to crawl
    "max_pages": 100,         // Maximum pages to scan
    "timeout": 30,            // Request timeout (seconds)
    "concurrent_workers": 5,  // Parallel workers
    "rate_limit_delay": 0.5   // Delay between requests
  }
}
```

### Customizing Detection Patterns

Add custom CSRF token patterns:

```json
{
  "detection_patterns": {
    "csrf_tokens": [
      "custom_token",
      "my_csrf_field",
      "security_key"
    ]
  }
}
```

### Severity Configuration

Customize risk assessment:

```json
{
  "severity_keywords": {
    "critical": ["delete_account", "drop_database"],
    "high": ["admin_action", "privileged_operation"]
  }
}
```

---

## 📊 Understanding Reports

### Report Formats

The scanner generates two report types:

#### 1. Markdown Report (Human-Readable)

```markdown
# Web Application Security Assessment Report

**Scan ID:** 20260116143025
**Target:** https://example.com
**Date:** 2026-01-16T14:30:25

## Executive Summary
Total vulnerabilities detected: **5**

### Findings by Severity
- **HIGH**: 2
- **MEDIUM**: 3
```

#### 2. JSON Report (Machine-Readable)

```json
{
  "scan_metadata": {
    "scan_id": "20260116143025",
    "target": "https://example.com",
    "total_findings": 5
  },
  "findings": [...]
}
```

### Reading a Finding

Each vulnerability includes:

- **Finding ID**: Unique identifier
- **Severity**: Risk level (Critical/High/Medium/Low)
- **Page Location**: Where the vulnerability was found
- **Endpoint**: Target form action URL
- **Description**: What's vulnerable
- **Recommendations**: How to fix it

---

## 🔧 Troubleshooting

### Common Issues

#### "aiohttp not found"
```bash
pip install aiohttp
```

#### "Connection timeout"
```bash
# Increase timeout in config.json
"timeout": 60
```

#### "Too many open connections"
```bash
# Reduce concurrent workers in config.json
"concurrent_workers": 3
```

#### "Permission denied"
```bash
# Run with appropriate permissions or check robots.txt
python websecure_analyzer.py https://example.com -v
```

### Debug Mode

Enable verbose logging:

```bash
python websecure_analyzer.py https://example.com -v 2>&1 | tee debug.log
```

---

## ✅ Best Practices

### Before Scanning

1. **Get Authorization**: Always obtain written permission
2. **Review Terms**: Check website's terms of service
3. **Test Locally**: Test on your own applications first
4. **Backup Data**: Never scan production without backups

### During Scanning

1. **Rate Limiting**: Don't overload target servers
2. **Off-Peak Hours**: Scan during low-traffic periods
3. **Monitor Resources**: Watch CPU/memory usage
4. **Stay Legal**: Comply with all laws and regulations

### After Scanning

1. **Review Reports**: Analyze findings carefully
2. **Verify Results**: Confirm vulnerabilities manually
3. **Responsible Disclosure**: Report findings ethically
4. **Document Everything**: Keep detailed records

### Ethical Guidelines

```
✓ DO scan systems you own or have permission to test
✓ DO report vulnerabilities responsibly
✓ DO respect rate limits and robots.txt
✓ DO use for educational purposes

✗ DON'T scan without authorization
✗ DON'T share vulnerabilities publicly before fixes
✗ DON'T use for malicious purposes
✗ DON'T ignore website terms of service
```

---

## 📈 Performance Tuning

### Fast Scan (Quick Assessment)

```bash
python websecure_analyzer.py https://example.com -d 2 -m 50
```

### Balanced Scan (Recommended)

```bash
python websecure_analyzer.py https://example.com -d 3 -m 100
```

### Deep Scan (Comprehensive)

```bash
python websecure_analyzer.py https://example.com -d 5 -m 500
```

### Configuration for Large Sites

```json
{
  "scanner_settings": {
    "max_depth": 4,
    "max_pages": 1000,
    "concurrent_workers": 10,
    "rate_limit_delay": 0.2
  }
}
```

---

## 🎓 Educational Use

### Learning Security Concepts

Open `interactive_security_lab.html` in a browser to:

- Understand CSRF attack mechanics
- See vulnerable vs. secure code
- Explore different attack vectors
- Learn defense mechanisms

### Academic Research

This tool is ideal for:

- Cybersecurity courses
- Security research projects
- Penetration testing labs
- Web application security studies

---

## 📞 Support

**Developer:** Kailas  
**Project Type:** Security Research & Education  
**Year:** 2026

For issues or questions:
- Review documentation thoroughly
- Check troubleshooting section
- Follow responsible disclosure practices

---

## 🔐 Security Notice

This tool is designed for:
- ✅ Authorized security testing
- ✅ Educational purposes
- ✅ Security research
- ✅ Vulnerability assessment with permission

**Remember:** Unauthorized scanning may be illegal in your jurisdiction.

---

**End of Usage Guide**

*Developed by Kailas - January 2026*
