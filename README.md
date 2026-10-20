# Phishing Link Detector

Educational tool that analyzes URLs for common phishing indicators.

This project is designed for learning. It uses **heuristics** (rules of thumb) — not a commercial threat-intelligence feed. Results are for educational purposes only and should not be treated as definitive security advice.

**Live demo idea**: Open `index.html` in any browser, or host the folder on GitHub Pages / Netlify.

---

## Features

Detects common red flags such as:

- IP address used instead of a domain name
- Known URL shorteners (bit.ly, t.co, tinyurl, etc.)
- Suspicious / free TLDs often abused in phishing
- Brand impersonation (e.g. "paypal" appearing in a non-official domain)
- Excessive subdomains or unusually long hostnames
- `@` symbol tricks in the URL path
- Missing HTTPS
- Homoglyph / look-alike characters (basic check)
- Very long or obfuscated URLs

Each finding is explained so you can learn *why* it is suspicious.

---

## 1. Web App (Browser)

No installation required.

1. Open `index.html` in your browser, **or**
2. Serve the folder with any static host (GitHub Pages, Netlify, VS Code Live Server, etc.)

Paste a URL and click **Analyze**. The tool runs entirely client-side.

---

## 2. Python CLI

Requires Python 3.8+.

```bash
# From the project root
python phishing_detector.py "https://example.com"

# Or interactive mode
python phishing_detector.py
```

Example output:

```
URL: http://paypa1-secure-login.tk/verify
Risk Score: 78 / 100  → HIGH RISK

Findings:
  [HIGH] Uses a free/suspicious TLD (.tk)
  [HIGH] Contains brand keyword "paypal" on a non-official domain
  [MED]  Uses HTTP instead of HTTPS
  [MED]  Hostname looks like a brand + random words pattern
```

---

## Project Structure

```
phishing-link-detector/
├── index.html          # Web UI
├── style.css           # Styling
├── script.js           # Detection logic (shared concepts with Python)
├── phishing_detector.py# Python CLI version
└── README.md
```

---

## Learning Goals

By studying and extending this project you will practice:

- URL parsing and normalization
- Heuristic-based detection (the same idea used by many real filters)
- Risk scoring
- Clean separation of UI vs logic
- Writing educational security tools responsibly

### Ideas for improvement

- Add more brand keywords or a local blocklist
- Integrate a free public API (e.g. Google Safe Browsing, PhishTank) with an API key
- Detect punycode / IDN homograph attacks more thoroughly
- Export results as JSON
- Add a “why is this risky?” expandable explanation for each rule

---

## Disclaimer

This is an **educational** project.  
It does **not** replace professional security tools, antivirus, or browser phishing protection.  
Never use it to scan URLs you do not own or have permission to analyze in a way that violates terms of service or laws.

---

Built as part of a personal cybersecurity learning portfolio.
