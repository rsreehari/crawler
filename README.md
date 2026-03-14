# 🔐 WebSecure CSRF Vulnerability Analyzer

**Developed by Kailas**

Professional-grade security research tool for identifying Cross-Site Request Forgery (CSRF) vulnerabilities in web applications through intelligent crawling and deep analysis.

## 🎯 Project Overview

WebSecure is an advanced security research tool built from the ground up with modern Python async architecture. It performs intelligent web application crawling combined with sophisticated vulnerability detection to identify CSRF weaknesses before attackers can exploit them.

## ✨ Key Features

### Core Capabilities
- **Async Architecture**: High-performance scanning using asyncio and aiohttp
- **Intelligent Crawling**: Smart web crawler with depth control and rate limiting
- **Multi-Pattern Detection**: Identifies various CSRF protection mechanisms
- **Severity Classification**: Risk-based vulnerability categorization
- **Dual Report Format**: Generate both JSON and Markdown reports
- **Extensible Design**: Abstract analyzer interface for custom security checks

### Detection Mechanisms
- Token-based protection (synchronizer tokens)
- SameSite cookie attributes
- Custom security headers
- Double-submit cookie patterns
- Origin/Referer validation

## 🚀 Installation & Setup

### System Requirements
- Python 3.8 or higher
- pip package manager
- Windows/Linux/macOS compatible

### Quick Start

```bash
# Navigate to project directory
cd CSRF-Vulnerability-Crawler-and-Research

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## 📖 Usage

### Basic Scan

```bash
python websecure_analyzer.py https://example.com
```

### Advanced Options

```bash
# Specify output file and enable verbose logging
python websecure_analyzer.py https://example.com -o assessment.md -v

# Control crawl depth and page limit
python websecure_analyzer.py https://example.com -d 5 -m 200

# Full command with all options
python websecure_analyzer.py https://example.com \
    --output security_report.md \
    --verbose \
    --depth 4 \
    --max-pages 150
```

### Quick Start Script

```bash
# Interactive setup and scan
python quickstart.py
```

### Educational Lab

Open the interactive security demonstration:

```bash
# Open in browser
start interactive_security_lab.html
```

### Command-Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `url` | - | Target URL for assessment (required) | - |
| `--output` | `-o` | Output file path | `security_report.md` |
| `--verbose` | `-v` | Enable verbose logging | `False` |
| `--depth` | `-d` | Maximum crawl depth | `3` |
| `--max-pages` | `-m` | Maximum pages to analyze | `100` |

## 📊 Report Format

The analyzer generates two report formats:

### Markdown Report
Human-readable report with:
- Executive summary
- Severity breakdown
- Detailed findings with recommendations

### JSON Report
Machine-readable format with:
- Structured vulnerability data
- Scan metadata
- Programmatic access to findings

## 🏗️ Architecture

### Project Structure

```
WebSecure-Analyzer/
├── websecure_analyzer.py          # Main scanner application
├── interactive_security_lab.html  # Educational demonstration
├── utils.py                        # Helper utilities
├── config.json                     # Configuration settings
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── USAGE_GUIDE.md                  # Comprehensive usage guide
├── CHANGELOG.md                    # Version history
├── LICENSE                         # MIT License
├── .gitignore                      # Git ignore rules
├── quickstart.py                   # Quick start script
├── vulnerability_research_notes.md # Research documentation
├── security_assessment_report.txt  # Sample report
└── proof/                          # Screenshots and evidence
```

### Design Patterns
- **Abstract Factory**: Extensible analyzer modules
- **Async Workers**: Concurrent crawling and analysis
- **Data Classes**: Type-safe vulnerability representation
- **Enum Types**: Consistent severity and protection type classification

## 🛡️ CSRF Protection Best Practices

### Implementation Recommendations

1. **Synchronizer Token Pattern**
   ```html
   <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
   ```

2. **SameSite Cookies**
   ```
   Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
   ```

3. **Custom Headers**
   ```javascript
   fetch('/api/endpoint', {
     headers: { 'X-CSRF-Token': token }
   })
   ```

4. **Origin Validation**
   ```python
   if request.headers.get('Origin') != expected_origin:
       abort(403)
   ```

### Defense in Depth
Implement multiple layers of protection for critical operations:
- CSRF tokens + SameSite cookies
- Origin/Referer validation
- Re-authentication for sensitive actions
Interactive Security Lab

Open `interactive_security_lab.html` in your browser to explore:
- Live attack simulations (safe, educational)
- Multiple attack vectors and scenarios  
- Side-by-side vulnerable vs. secure code
- Defense mechanism demonstrations
- Implementation best practices

### Additional Documentation

- **USAGE_GUIDE.md**: Complete usage documentation with examples
- **CHANGELOG.md**: Version history and roadmap
- **vulnerability_research_notes.md**: Security research findings
- **config.json**: Customizable scanner settings
### Understanding CSRF

CSRF exploits the trust a website has in a user's browser. If a user is authenticated to a site, an attacker can trick the user's browser into making unauthorized requests.

### Proof of Concept

The included `csrf_poc.html` demonstrates CSRF attack mechanics in a safe, educational context. Open it in a browser to understand attack vectors.

## ⚖️ Legal & Ethical Guidelines

### Authorized Use Only
- Only scan applications you own or have written permission to test
- Obtain proper authorization before conducting security assessments
- Follow responsible disclosure practices for discovered vulnerabilities

### Compliance
- Ensure compliance with local laws and regulations
- Respect website terms of service
- Do not use for malicious purposes

### Disclaimer
This tool is provided for educational and authorized security testing purposes only. Users are solely responsible for ensuring their use complies with applicable laws and regulations.

## 🎓 Educational Purpose

This tool was developed as part of security research and education initiatives. It demonstrates:
- Modern web security vulnerabilities
- Professional security assessment methodologies
- Async programming patterns in Python
- Best practices for security tool development

## 📝 License & Usage

**Author:** Kailas
**License:** Educational and Research Use

This project is released for:
- Educational purposes in cybersecurity courses
- Security research and vulnerability analysis
- Authorized penetration testing engagements
- Learning modern Python security tool development

### Restrictions
- Not for unauthorized testing
- Not for malicious purposes
- Always obtain written permission before scanning
- Follow local laws and regulations

## 🔄 Version Information

**Current Version:** 2.0.0 (January 2026)
**Created by:** Kailas

### What's New in v2.0
- ✨ Complete async/await implementation
- 🚀 5-10x faster scanning with aiohttp
- 🎯 Advanced pattern matching algorithms
- 📊 Dual-format reporting (JSON + Markdown)
- 🏗️ Modular analyzer architecture
- 🛡️ Enhanced security detection capabilities
- 📝 Comprehensive logging system
- ⚡ Smart rate limiting and queue management

## 📧 Contact Information

**Developer:** Kailas
**Purpose:** Security Research & Education
**Date:** January 2026

### Support
For security-related inquiries or responsible disclosure:
- Follow ethical hacking guidelines
- Report vulnerabilities responsibly
- Use only for authorized testing

---

**⚠️ Critical Reminder**

This tool is a product of security research by Kailas. Always:
- Obtain explicit written authorization before scanning
- Comply with all applicable laws and regulations  
- Use ethically and responsibly for legitimate security testing
- Never use against systems without permission
