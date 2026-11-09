## 🔗 Live Demo
[https://gamilasaid.pythonanywhere.com](https://gamilasaid.pythonanywhere.com)

# 🛡️ Secure Link Checker

A Flask web application that analyzes URLs and gives each one a **0–100 safety score** based on multiple security checks. Built with security-by-design principles, with an Arabic interface.

**Programmed by Gamila Said**

## Features

- **URL structure analysis**: detects missing HTTPS, IP-based links, `@` tricks, long suspicious subdomains, and Punycode (homograph) domains
- **SSRF protection**: blocks links pointing to internal networks (localhost, private IPs) before the server opens them
- **Redirect tracing**: follows redirects manually (max 5 hops) and re-validates every hop
- **SSL certificate check**: issuer, expiry date, and validity
- **Domain age (WHOIS)**: flags newly registered domains
- **Reputation check** (optional): Google Safe Browsing and VirusTotal APIs
- **Risk score (0–100)** with a color-coded result (safe / suspicious / dangerous)
- **Rate limiting**: 10 checks per minute per client
- **History and statistics**: every check is stored in SQLite, with a stats dashboard at `/stats`

## Tech Stack

Python · Flask · SQLite · Requests · python-whois · HTML/CSS/JavaScript

## Installation

```bash
git clone https://github.com/gamilasaeed041-svg/link-checker.git

cd link-checker
python -m venv venv
venv\Scripts\activate        # Linux/Mac: source venv/bin/activate
pip install flask requests python-dotenv python-whois

