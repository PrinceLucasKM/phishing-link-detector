#!/usr/bin/env python3
"""
Educational Phishing Link Detector – Python CLI version

Heuristic-based analysis of URLs for common phishing indicators.
For learning purposes only. Not a replacement for real security tools.
"""

from __future__ import annotations

import re
import sys
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "shorturl.at", "cutt.ly", "rb.gy",
    "tiny.cc", "rebrand.ly", "bl.ink", "lnkd.in", "trib.al",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
    "link", "info", "online", "site", "website", "space", "icu",
    "buzz", "rest", "fit", "cam", "sbs", "cyou",
}

BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "bank", "chase", "wellsfargo",
    "citibank", "hsbc", "barclays", "dhl", "fedex", "ups", "irs",
    "hmrc", "dropbox", "linkedin", "twitter", "outlook",
    "office365", "onedrive", "icloud", "steam", "epicgames",
]

OFFICIAL_DOMAINS = {
    "paypal.com", "apple.com", "microsoft.com", "google.com", "amazon.com",
    "netflix.com", "facebook.com", "instagram.com", "whatsapp.com",
    "chase.com", "wellsfargo.com", "citibank.com", "hsbc.com",
    "barclays.com", "dhl.com", "fedex.com", "ups.com", "irs.gov",
    "gov.uk", "dropbox.com", "linkedin.com", "twitter.com", "x.com",
    "outlook.com", "office.com", "live.com", "icloud.com", "steampowered.com",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_url(raw: str) -> str | None:
    url = raw.strip()
    if not url:
        return None
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return None
        return url
    except Exception:
        return None


def is_ip_address(hostname: str) -> bool:
    # IPv4
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname):
        return True
    # very basic IPv6
    if ":" in hostname and re.match(r"^[0-9a-fA-F:]+$", hostname):
        return True
    return False


def get_tld(hostname: str) -> str:
    parts = hostname.lower().split(".")
    return parts[-1] if len(parts) > 1 else ""


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(url: str) -> dict:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "") + (parsed.query and ("?" + parsed.query) or "")
    full = url

    findings: list[dict] = []
    score = 0

    # 1. IP address
    if is_ip_address(hostname):
        findings.append({
            "level": "HIGH",
            "text": "Uses an IP address instead of a domain name. Legitimate sites almost always use a domain.",
        })
        score += 30

    # 2. URL shortener
    if any(hostname == s or hostname.endswith("." + s) for s in SHORTENERS):
        findings.append({
            "level": "MED",
            "text": f"Uses a known URL shortener ({hostname}). Shorteners hide the real destination and are frequently abused in phishing.",
        })
        score += 20

    # 3. Suspicious TLD
    tld = get_tld(hostname)
    if tld in SUSPICIOUS_TLDS:
        findings.append({
            "level": "HIGH",
            "text": f"Uses a free or frequently-abused TLD (.{tld}). Many phishing campaigns register domains on these TLDs.",
        })
        score += 25

    # 4. Brand impersonation
    brand_hit = next((b for b in BRANDS if b in hostname), None)
    if brand_hit:
        is_official = any(
            hostname == d or hostname.endswith("." + d) for d in OFFICIAL_DOMAINS
        )
        if not is_official:
            findings.append({
                "level": "HIGH",
                "text": f'Contains the brand keyword "{brand_hit}" but is not on an official domain. Classic impersonation technique.',
            })
            score += 30

    # 5. Too many subdomains / long hostname
    labels = hostname.split(".")
    if len(labels) >= 5:
        findings.append({
            "level": "MED",
            "text": f"Hostname has many subdomains ({len(labels)} labels). Attackers sometimes nest fake brands deep in the subdomain chain.",
        })
        score += 15
    if len(hostname) > 50:
        findings.append({
            "level": "MED",
            "text": f"Very long hostname ({len(hostname)} characters). Can be used to hide the real domain or confuse users.",
        })
        score += 12

    # 6. @ symbol trick
    if "@" in path or ("@" in full and not full.lower().startswith("mailto:")):
        findings.append({
            "level": "HIGH",
            "text": "Contains an @ symbol. This is a classic phishing trick that can make a URL appear to point to a different site.",
        })
        score += 25

    # 7. Missing HTTPS
    if parsed.scheme == "http":
        findings.append({
            "level": "MED",
            "text": "Uses HTTP instead of HTTPS. Modern legitimate sites almost always force HTTPS.",
        })
        score += 12

    # 8. Homoglyph / look-alike (basic Cyrillic check)
    if re.search(r"[аеорсухії]", hostname):
        findings.append({
            "level": "HIGH",
            "text": "Hostname contains characters that look like Latin letters but are from another alphabet (possible homograph / look-alike attack).",
        })
        score += 28

    # 9. Very long URL
    if len(full) > 150:
        findings.append({
            "level": "LOW",
            "text": f"URL is unusually long ({len(full)} characters). Sometimes used to hide the real destination or overwhelm the user.",
        })
        score += 8

    # 10. High digit ratio
    digits = sum(c.isdigit() for c in hostname)
    if len(hostname) > 8 and digits / len(hostname) > 0.35:
        findings.append({
            "level": "MED",
            "text": "Hostname contains a high proportion of digits. Can indicate auto-generated or disposable domains.",
        })
        score += 12

    score = min(score, 100)

    if score >= 60:
        risk = "HIGH RISK"
    elif score >= 30:
        risk = "MEDIUM RISK"
    else:
        risk = "LOW"

    if not findings:
        findings.append({
            "level": "LOW",
            "text": "No strong phishing indicators detected by the current rules. Still stay cautious — heuristics are never perfect.",
        })

    return {
        "url": full,
        "score": score,
        "risk": risk,
        "findings": findings,
    }


def print_report(result: dict) -> None:
    print()
    print(f"URL: {result['url']}")
    print(f"Risk Score: {result['score']} / 100  →  {result['risk']}")
    print()
    print("Findings:")
    for f in result["findings"]:
        print(f"  [{f['level']:<4}] {f['text']}")
    print()
    print("Disclaimer: Educational heuristics only. Not a real-time threat feed.")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) > 1:
        raw = " ".join(sys.argv[1:])
    else:
        try:
            raw = input("Enter URL to analyze: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

    url = normalize_url(raw)
    if not url:
        print("Error: Please provide a valid URL.")
        sys.exit(1)

    result = analyze(url)
    print_report(result)


if __name__ == "__main__":
    main()
