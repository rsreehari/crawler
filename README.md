```markdown
# WebSecure CSRF Vulnerability Analyzer

A lightweight,asynchronous Python tool that crawls a web site, detects missing or weak CSRF protections, and produces JSON and Markdown reports.

---

## Key Features
- **Async scanning** with `aiohttp` for fast, concurrent crawling.
- Detects:
  - Synchronizer tokens
  - SameSite cookie attributes
  - Custom CSRF headers
  - Double‑submit cookies
  - Origin/Referer validation
- Severity rating (Critical / High / Medium / Low).
- Extensible analyzer interface for custom checks.
- Dual‑output: machine‑readable **JSON** and human‑readable **Markdown**.

---

## Installation
```bash
git clone <repo‑url>
cd CSRF-Vulnerability-Crawler-and-Research
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Quick Usage
```bash
# Basic scan
python websecure_analyzer.py https://example.com
```

### Common options
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--output` | `-o` | Output file (Markdown) | `security_report.md` |
| `--verbose`| `-v` | Enable verbose logging | off |
| `--depth`  | `-d` | Crawl depth | `3` |
| `--max-pages`| `-m` | Max pages to scan | `100` |

**Example with all options**
```bash
python websecure_analyzer.py https://example.com \
    -o report.md -v -d 4 -m 150
```

Two files are created:
- `report.md` – readable summary.
- `report.json` – structured data for CI/CD or further analysis.

---

## Report Highlights
- **Executive summary** – overall risk score.
- **Severity breakdown** – count of findings per severity level.
- **Finding details** – URL, missing protection, recommendation, CVE‑style ID.

---

## CSRF Mitigation Quick‑Reference
```html
<!-- synchronizer token -->
<input type="hidden" name="csrf_token" value="{{ csrf_token }}">
```
```
Set-Cookie: session=xyz; SameSite=Strict; Secure; HttpOnly
```
```js
fetch('/api', { headers: { 'X-CSRF-Token': token } })
```
```python
if request.headers.get('Origin') != TRUSTED_ORIGIN:
    abort(403)
```
*Combine token validation, SameSite cookies, and Origin checks for defense‑in‑depth.*

---

## Responsible Use
- Scan **only** assets you own or have explicit, written permission to test.
- Follow responsible disclosure guidelines.
- Misuse may breach laws and is prohibited.

---

## License & Contact
- MIT‑style license – educational and research use.
- Open an issue on the repository or contact the author for questions.

```

*Save the above as `README.md` in the project root.*
