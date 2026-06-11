# DecodeLabs Task 4 - Advanced URL Threat Scanner

## Overview
The Advanced URL Threat Scanner is a cybersecurity tool developed in Python that analyzes URLs and identifies potential phishing and malicious indicators.

The scanner evaluates multiple risk factors and generates a risk score to help users determine whether a URL is safe or dangerous.

## Features
- HTTPS validation
- URL shortener detection
- Hyphen-based domain detection
- Nested subdomain detection
- IP-based URL detection
- Suspicious keyword analysis
- Brand impersonation detection
- Risk score generation
- Threat classification
- Security recommendations

## Technologies Used
- Python 3
- urllib.parse
- Regular Expressions (re)

## Project File

```text
url_threat_scanner.py
```

## How to Run

```bash
python url_threat_scanner.py
```

or

```bash
py url_threat_scanner.py
```

## Example

Input:

```text
http://paypal-secure-login.verify-account.com/update
```

Output:

```text
Status: High Risk / Malicious
Recommended Action: Do not open. Block and report.
```

## Risk Levels

- Low Risk
- Suspicious
- High Risk / Malicious

## Author

Muhammad Abubakar Farooq

## Internship

DecodeLabs Cyber Security Internship 2026
