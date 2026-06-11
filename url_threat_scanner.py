from urllib.parse import urlparse
import re

print("=== DecodeLabs Task 4: Advanced URL Threat Scanner ===")

url = input("Enter URL to scan: ").strip()

if not url.startswith(("http://", "https://")):
    url = "http://" + url

parsed = urlparse(url)
domain = parsed.netloc.lower()
path = parsed.path.lower()

risk_score = 0
red_flags = []

shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
brand_names = ["paypal", "amazon", "google", "facebook", "microsoft", "apple", "netflix", "bank"]
suspicious_words = ["login", "verify", "secure", "update", "account", "billing", "password", "free", "claim", "reward"]

if not url.startswith("https://"):
    risk_score += 2
    red_flags.append("URL does not use HTTPS.")

if any(shortener in domain for shortener in shorteners):
    risk_score += 3
    red_flags.append("URL shortener detected.")

if "-" in domain:
    risk_score += 2
    red_flags.append("Hyphen found in domain, often used in fake domains.")

if domain.count(".") >= 3:
    risk_score += 3
    red_flags.append("Multiple subdomains detected, real domain may be hidden.")

if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
    risk_score += 4
    red_flags.append("IP address used instead of domain name.")

if any(word in url.lower() for word in suspicious_words):
    risk_score += 2
    red_flags.append("Suspicious phishing-related keyword found.")

for brand in brand_names:
    if brand in domain and not domain.endswith(brand + ".com"):
        risk_score += 3
        red_flags.append(f"Possible brand impersonation detected: {brand}")

if len(url) > 80:
    risk_score += 2
    red_flags.append("URL is unusually long.")

if "@" in url:
    risk_score += 4
    red_flags.append("@ symbol found in URL, may hide real destination.")

print("\n========== URL THREAT REPORT ==========")
print("URL:", url)
print("Domain:", domain)
print("Path:", path)
print("Risk Score:", risk_score)

if risk_score >= 10:
    status = "High Risk / Malicious"
    action = "Do not open. Block and report."
elif risk_score >= 5:
    status = "Suspicious"
    action = "Verify before opening."
else:
    status = "Low Risk"
    action = "URL appears safe, but still verify source."

print("Status:", status)
print("Recommended Action:", action)

print("\nRed Flags:")
if red_flags:
    for i, flag in enumerate(red_flags, 1):
        print(f"{i}. {flag}")
else:
    print("No major red flags detected.")