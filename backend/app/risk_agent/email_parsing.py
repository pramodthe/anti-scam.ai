import re
from email.utils import parseaddr


EMAIL_PATTERN = re.compile(
    r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
    flags=re.IGNORECASE,
)


def _find_first_email(text: str) -> str | None:
    match = EMAIL_PATTERN.search(text or "")
    if not match:
        return None
    return match.group(0).lower().strip()


def parse_sender(from_email: str) -> tuple[str, str]:
    raw = (from_email or "").strip()
    if not raw:
        return "", ""

    parsed_name, parsed_addr = parseaddr(raw)
    sender_name = parsed_name.strip()
    if "@" in sender_name:
        sender_name = ""

    sender_addr = _find_first_email(parsed_addr) or _find_first_email(raw)
    if sender_addr:
        if not sender_name:
            candidate = raw
            candidate = candidate.replace(sender_addr, " ")
            for token in ("<", ">", "(", ")", '"', "'"):
                candidate = candidate.replace(token, " ")
            candidate = re.sub(r"\s+", " ", candidate).strip()
            if candidate and "@" not in candidate:
                sender_name = candidate
        return sender_name, sender_addr

    return sender_name, raw.lower()
