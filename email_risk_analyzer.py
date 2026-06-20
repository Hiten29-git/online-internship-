import re

# --- Risk Patterns ---

URGENT_PATTERNS = [
    r'\burgent\b', r'\bimmediately\b', r'\bact now\b', r'\baction required\b',
    r'\bfinal notice\b', r'\blast chance\b', r'\bexpires?\b', r'\bdeadline\b',
    r'\bwithin \d+ hours?\b', r'\bdo not ignore\b', r'\brespond now\b',
    r'\btime.sensitive\b', r'\bcritical\b',
]

SENSITIVE_DATA_PATTERNS = [
    r'\bpassword\b', r'\bpin\b', r'\bssn\b', r'\bsocial security\b',
    r'\bcredit card\b', r'\bbank account\b', r'\baccount number\b',
    r'\bverify your (account|identity|details|information)\b',
    r'\bconfirm your (account|identity|details|password)\b',
    r'\benter your (details|credentials|password|otp)\b',
    r'\bprovide your\b', r'\bupdate your (account|information|details)\b',
]

SUSPICIOUS_LINK_PATTERNS = [
    r'http[s]?://\d+\.\d+\.\d+\.\d+',           # IP-based URLs
    r'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly',     # URL shorteners
    r'http[s]?://[^\s]*\.(ru|cn|tk|pw|cc|xyz)',  # Suspicious TLDs
    r'click here',                                 # Generic click prompts
    r'login[.\-]?\w+\.(com|net|org)',             # Fake login domains
    r'verify[.\-]?\w+\.(com|net|org)',            # Fake verify domains
    r'secure[.\-]?\w+\.(com|net|org)',            # Fake secure domains
]

PHISHING_PATTERNS = [
    r'\byou (have won|are selected|are a winner)\b',
    r'\bcongratulations\b',
    r'\bclaim your (prize|reward|gift)\b',
    r'\bfree (gift|money|offer|iphone|laptop)\b',
    r'\blottery\b', r'\binheritance\b', r'\bnigerian\b',
    r'\bmillion dollars?\b',
    r'\byour account (has been|will be) (suspended|locked|disabled|terminated)\b',
    r'\bunauthorized (access|login|activity)\b',
]


def scan_email(subject: str, body: str) -> dict:
    """
    Scan an email for suspicious patterns and return a risk report.

    Args:
        subject (str): Email subject line
        body (str): Email body content

    Returns:
        dict: Risk report with flags, risk level, and details
    """
    full_text = (subject + " " + body).lower()
    flags = []

    # Check urgent patterns
    urgent_matches = [p for p in URGENT_PATTERNS if re.search(p, full_text)]
    if urgent_matches:
        flags.append({
            "category": "Urgency / Pressure",
            "details": f"Detected urgent language patterns ({len(urgent_matches)} match(es))"
        })

    # Check sensitive data prompts
    sensitive_matches = [p for p in SENSITIVE_DATA_PATTERNS if re.search(p, full_text)]
    if sensitive_matches:
        flags.append({
            "category": "Sensitive Data Request",
            "details": f"Email requests sensitive information ({len(sensitive_matches)} match(es))"
        })

    # Check suspicious links
    link_matches = [p for p in SUSPICIOUS_LINK_PATTERNS if re.search(p, full_text)]
    if link_matches:
        flags.append({
            "category": "Suspicious Link / URL",
            "details": f"Contains suspicious links or click prompts ({len(link_matches)} match(es))"
        })

    # Check phishing patterns
    phishing_matches = [p for p in PHISHING_PATTERNS if re.search(p, full_text)]
    if phishing_matches:
        flags.append({
            "category": "Phishing / Scam Indicator",
            "details": f"Contains known phishing/scam phrases ({len(phishing_matches)} match(es))"
        })

    # Determine risk level
    num_flags = len(flags)
    if num_flags == 0:
        risk_level = "LOW"
    elif num_flags == 1:
        risk_level = "MEDIUM"
    elif num_flags == 2:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "risk_level": risk_level,
        "flags": flags,
        "total_flags": num_flags
    }


def print_report(subject: str, report: dict):
    print("\n" + "=" * 55)
    print(f"  EMAIL RISK ANALYSIS REPORT")
    print("=" * 55)
    print(f"  Subject : {subject}")
    print(f"  Risk    : {report['risk_level']}  ({report['total_flags']} flag(s) detected)")
    print("-" * 55)
    if report["flags"]:
        print("  ⚠️  Issues Found:")
        for flag in report["flags"]:
            print(f"\n  [{flag['category']}]")
            print(f"    → {flag['details']}")
    else:
        print("  ✅ No suspicious patterns detected. Email looks safe.")
    print("=" * 55)


def main():
    print("=== Email Risk Analyzer ===")
    print("Enter the email details below (press Enter twice to finish body):\n")

    subject = input("Email Subject: ").strip()

    print("Email Body (type 'END' on a new line when done):")
    body_lines = []
    while True:
        line = input()
        if line.strip().upper() == "END":
            break
        body_lines.append(line)
    body = "\n".join(body_lines)

    report = scan_email(subject, body)
    print_report(subject, report)


if __name__ == "__main__":
    main()