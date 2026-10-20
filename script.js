/**
 * Educational Phishing Link Detector – Browser version
 * Heuristic-based only. For learning purposes.
 */

const SHORTENERS = [
  "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "adf.ly", "bit.do", "shorturl.at", "cutt.ly", "rb.gy",
  "tiny.cc", "rebrand.ly", "bl.ink", "lnkd.in", "trib.al"
];

const SUSPICIOUS_TLDS = [
  "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
  "link", "info", "online", "site", "website", "space", "icu",
  "buzz", "rest", "fit", "cam", "sbs", "cyou"
];

const BRANDS = [
  "paypal", "apple", "microsoft", "google", "amazon", "netflix",
  "facebook", "instagram", "whatsapp", "bank", "chase", "wellsfargo",
  "citibank", "hsbc", "barclays", "dhl", "fedex", "ups", "irs",
  "hmrc", "dropbox", "linkedin", "twitter", "x.com", "outlook",
  "office365", "onedrive", "icloud", "steam", "epicgames"
];

const OFFICIAL_DOMAINS = [
  "paypal.com", "apple.com", "microsoft.com", "google.com", "amazon.com",
  "netflix.com", "facebook.com", "instagram.com", "whatsapp.com",
  "chase.com", "wellsfargo.com", "citibank.com", "hsbc.com",
  "barclays.com", "dhl.com", "fedex.com", "ups.com", "irs.gov",
  "gov.uk", "dropbox.com", "linkedin.com", "twitter.com", "x.com",
  "outlook.com", "office.com", "live.com", "icloud.com", "steampowered.com"
];

function normalizeUrl(input) {
  let url = input.trim();
  if (!url) return null;
  if (!/^https?:\/\//i.test(url)) {
    url = "http://" + url;
  }
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

function isIpAddress(hostname) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return true;
  if (hostname.includes(":") && /^[0-9a-fA-F:]+$/.test(hostname)) return true;
  return false;
}

function getTld(hostname) {
  const parts = hostname.toLowerCase().split(".");
  return parts.length > 1 ? parts[parts.length - 1] : "";
}

function analyze(urlObj) {
  const findings = [];
  let score = 0;

  const hostname = urlObj.hostname.toLowerCase();
  const full = urlObj.href;
  const path = urlObj.pathname + urlObj.search;

  if (isIpAddress(hostname)) {
    findings.push({
      level: "high",
      text: "Uses an IP address instead of a domain name. Legitimate sites almost always use a domain."
    });
    score += 30;
  }

  if (SHORTENERS.some(s => hostname === s || hostname.endsWith("." + s))) {
    findings.push({
      level: "med",
      text: `Uses a known URL shortener (${hostname}). Shorteners hide the real destination and are frequently abused in phishing.`
    });
    score += 20;
  }

  const tld = getTld(hostname);
  if (SUSPICIOUS_TLDS.includes(tld)) {
    findings.push({
      level: "high",
      text: `Uses a free or frequently-abused TLD (.${tld}). Many phishing campaigns register domains on these TLDs.`
    });
    score += 25;
  }

  const brandHit = BRANDS.find(b => hostname.includes(b));
  if (brandHit) {
    const isOfficial = OFFICIAL_DOMAINS.some(d => hostname === d || hostname.endsWith("." + d));
    if (!isOfficial) {
      findings.push({
        level: "high",
        text: `Contains the brand keyword "${brandHit}" but is not on an official domain. Classic impersonation technique.`
      });
      score += 30;
    }
  }

  const labels = hostname.split(".");
  if (labels.length >= 5) {
    findings.push({
      level: "med",
      text: `Hostname has many subdomains (${labels.length} labels). Attackers sometimes nest fake brands deep in the subdomain chain.`
    });
    score += 15;
  }
  if (hostname.length > 50) {
    findings.push({
      level: "med",
      text: `Very long hostname (${hostname.length} characters). Can be used to hide the real domain or confuse users.`
    });
    score += 12;
  }

  if (path.includes("@") || (full.includes("@") && !full.startsWith("mailto:"))) {
    findings.push({
      level: "high",
      text: "Contains an @ symbol. This is a classic phishing trick that can make a URL appear to point to a different site."
    });
    score += 25;
  }

  if (urlObj.protocol === "http:") {
    findings.push({
      level: "med",
      text: "Uses HTTP instead of HTTPS. Modern legitimate sites almost always force HTTPS."
    });
    score += 12;
  }

  const suspiciousChars = /[аеорсухії]/n  if (suspiciousChars.test(hostname)) {
    findings.push({
      level: "high",
      text: "Hostname contains characters that look like Latin letters but are from another alphabet (possible homograph / look-alike attack)."
    });
    score += 28;
  }

  if (full.length > 150) {
    findings.push({
      level: "low",
      text: `URL is unusually long (${full.length} characters). Sometimes used to hide the real destination or overwhelm the user.`
    });
    score += 8;
  }

  const digitRatio = (hostname.match(/\d/g) || []).length / Math.max(hostname.length, 1);
  if (digitRatio > 0.35 && hostname.length > 8) {
    findings.push({
      level: "med",
      text: "Hostname contains a high proportion of digits. Can indicate auto-generated or disposable domains."
    });
    score += 12;
  }

  score = Math.min(score, 100);

  let risk = "Low";
  let riskClass = "low";
  if (score >= 60) {
    risk = "High Risk";
    riskClass = "high";
  } else if (score >= 30) {
    risk = "Medium Risk";
    riskClass = "med";
  }

  if (findings.length === 0) {
    findings.push({
      level: "low",
      text: "No strong phishing indicators detected by the current rules. Still stay cautious — heuristics are never perfect."
    });
  }

  return { score, risk, riskClass, findings, url: full };
}

// UI
const input = document.getElementById("url-input");
const btn = document.getElementById("analyze-btn");
const results = document.getElementById("results");
const scoreCircle = document.getElementById("score-circle");
const scoreValue = document.getElementById("score-value");
const riskLevel = document.getElementById("risk-level");
const urlDisplay = document.getElementById("url-display");
const findingsList = document.getElementById("findings-list");

function runAnalysis() {
  const raw = input.value;
  const urlObj = normalizeUrl(raw);

  if (!urlObj) {
    alert("Please enter a valid URL (e.g. https://example.com or example.com).");
    return;
  }

  const result = analyze(urlObj);

  // Force re-animation of results section
  results.classList.add("hidden");
  // Small delay so the browser registers the class change before removing it
  requestAnimationFrame(() => {
    scoreValue.textContent = result.score;
    riskLevel.textContent = result.risk;
    urlDisplay.textContent = result.url;

    scoreCircle.className = "score-circle " + result.riskClass;

    findingsList.innerHTML = "";
    result.findings.forEach(f => {
      const div = document.createElement("div");
      div.className = "finding " + f.level;
      div.innerHTML = `<span class="badge">${f.level}</span><p>${f.text}</p>`;
      findingsList.appendChild(div);
    });

    results.classList.remove("hidden");
  });
}

btn.addEventListener("click", runAnalysis);
input.addEventListener("keydown", e => {
  if (e.key === "Enter") runAnalysis();
});
