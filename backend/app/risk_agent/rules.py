from email.utils import parseaddr
from typing import Any


COMPANY_DOMAIN_HINTS: dict[str, list[str]] = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
}

URGENCY_KEYWORDS = {
    "urgent",
    "immediately",
    "action required",
    "suspended",
    "final notice",
    "expires today",
    "limited time",
}

CREDENTIAL_KEYWORDS = {
    "verify your account",
    "confirm your account",
    "password",
    "login",
    "reset password",
    "otp",
    "security code",
    "ssn",
    "social security",
}

PAYMENT_KEYWORDS = {
    "wire transfer",
    "gift card",
    "invoice attached",
    "payment due",
    "bank details",
    "crypto payment",
    "overdue payment",
}

IMPERSONATION_KEYWORDS = {
    "ceo",
    "finance team",
    "hr team",
    "support team",
    "helpdesk",
}

SUSPICIOUS_TLDS = {".top", ".xyz", ".biz", ".click", ".shop", ".work", ".zip"}


def _extract_sender(from_email: str) -> tuple[str, str]:
    name, addr = parseaddr(from_email)
    if addr:
        return name.strip(), addr.lower().strip()
    return "", from_email.lower().strip()


def _domain(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.split("@", maxsplit=1)[1]


def extract_features(email: dict[str, Any]) -> dict[str, Any]:
    from_email = str(email.get("from_email", ""))
    subject = str(email.get("subject", ""))
    body = str(email.get("body", ""))
    sender_name, sender_addr = _extract_sender(from_email)
    sender_domain = _domain(sender_addr)
    text_blob = " ".join([sender_name, sender_addr, subject, body]).lower()

    matched_company = ""
    expected_domains: list[str] = []
    for company, domains in COMPANY_DOMAIN_HINTS.items():
        if company in text_blob:
            matched_company = company
            expected_domains = domains
            break

    has_urgency = any(keyword in text_blob for keyword in URGENCY_KEYWORDS)
    has_credential_pattern = any(keyword in text_blob for keyword in CREDENTIAL_KEYWORDS)
    has_payment_pattern = any(keyword in text_blob for keyword in PAYMENT_KEYWORDS)
    has_impersonation_pattern = any(keyword in text_blob for keyword in IMPERSONATION_KEYWORDS)
    has_domain_mismatch = bool(
        matched_company
        and sender_domain
        and expected_domains
        and not any(sender_domain.endswith(domain) for domain in expected_domains)
    )
    has_suspicious_tld = any(sender_domain.endswith(tld) for tld in SUSPICIOUS_TLDS if sender_domain)

    local_part = sender_addr.split("@", maxsplit=1)[0] if "@" in sender_addr else sender_addr
    local_part_has_many_digits = sum(ch.isdigit() for ch in local_part) >= 4

    return {
        "sender_name": sender_name,
        "sender_addr": sender_addr,
        "sender_domain": sender_domain,
        "subject": subject,
        "body": body,
        "matched_company": matched_company,
        "expected_domains": expected_domains,
        "has_urgency": has_urgency,
        "has_credential_pattern": has_credential_pattern,
        "has_payment_pattern": has_payment_pattern,
        "has_impersonation_pattern": has_impersonation_pattern,
        "has_domain_mismatch": has_domain_mismatch,
        "has_suspicious_tld": has_suspicious_tld,
        "local_part_has_many_digits": local_part_has_many_digits,
    }


def score_features(features: dict[str, Any]) -> tuple[float, list[str], str]:
    score = 0.0
    reasons: list[str] = []

    if features.get("has_domain_mismatch"):
        score += 0.45
        reasons.append("display_name_domain_mismatch")
    if features.get("has_urgency"):
        score += 0.15
        reasons.append("urgency_language")
    if features.get("has_credential_pattern"):
        score += 0.25
        reasons.append("credential_phishing_pattern")
    if features.get("has_payment_pattern"):
        score += 0.20
        reasons.append("payment_request_pattern")
    if features.get("has_impersonation_pattern"):
        score += 0.10
        reasons.append("impersonation_pattern")
    if features.get("has_suspicious_tld"):
        score += 0.12
        reasons.append("suspicious_sender_tld")
    if features.get("local_part_has_many_digits"):
        score += 0.08
        reasons.append("suspicious_sender_local_part")

    score = min(score, 1.0)

    if reasons:
        description = "Potential scam indicators detected: " + ", ".join(reasons[:4])
    else:
        description = "No strong phishing indicators detected by deterministic rules."

    return score, reasons, description

