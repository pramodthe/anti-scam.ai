import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatch
from urllib.parse import urlparse


@dataclass
class SSLCheckResult:
    certificate_present: bool
    ssl_valid: bool
    ssl_issuer: str
    ssl_subject: str
    ssl_expires_at: str | None
    ssl_hostname_match: bool
    error: str | None = None


def _flatten_name(name_field: tuple[tuple[tuple[str, str], ...], ...] | None) -> str:
    if not name_field:
        return ""
    parts: list[str] = []
    for rdn in name_field:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _parse_cert_time(raw_value: str | None) -> datetime | None:
    if not raw_value:
        return None
    try:
        parsed = datetime.strptime(raw_value, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC)


def _hostname_matches(cert: dict, hostname: str) -> bool:
    hostname = hostname.lower()
    subject_alt_names = cert.get("subjectAltName", [])
    candidates: list[str] = []
    for key, value in subject_alt_names:
        if key == "DNS":
            candidates.append(str(value).lower())

    if not candidates:
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    candidates.append(str(value).lower())

    if not candidates:
        return False

    for pattern in candidates:
        if pattern.startswith("*."):
            if fnmatch(hostname, pattern):
                return True
            continue
        if hostname == pattern:
            return True
    return False


def _fetch_cert(hostname: str, port: int, timeout_seconds: float) -> dict:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=timeout_seconds) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()
    return cert or {}


def _verify_cert_chain(hostname: str, port: int, timeout_seconds: float) -> bool:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((hostname, port), timeout=timeout_seconds) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=hostname):
                return True
    except Exception:
        return False


def check_ssl_certificate(url: str, timeout_seconds: float = 5.0) -> SSLCheckResult:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return SSLCheckResult(
            certificate_present=False,
            ssl_valid=False,
            ssl_issuer="",
            ssl_subject="",
            ssl_expires_at=None,
            ssl_hostname_match=False,
            error="non_https_url",
        )

    hostname = parsed.hostname
    if not hostname:
        return SSLCheckResult(
            certificate_present=False,
            ssl_valid=False,
            ssl_issuer="",
            ssl_subject="",
            ssl_expires_at=None,
            ssl_hostname_match=False,
            error="invalid_hostname",
        )

    port = parsed.port or 443
    cert: dict
    try:
        cert = _fetch_cert(hostname=hostname, port=port, timeout_seconds=timeout_seconds)
    except Exception as exc:
        return SSLCheckResult(
            certificate_present=False,
            ssl_valid=False,
            ssl_issuer="",
            ssl_subject="",
            ssl_expires_at=None,
            ssl_hostname_match=False,
            error=f"cert_fetch_error:{exc}",
        )

    if not cert:
        return SSLCheckResult(
            certificate_present=False,
            ssl_valid=False,
            ssl_issuer="",
            ssl_subject="",
            ssl_expires_at=None,
            ssl_hostname_match=False,
            error="cert_missing",
        )

    issuer = _flatten_name(cert.get("issuer"))
    subject = _flatten_name(cert.get("subject"))
    not_before = _parse_cert_time(cert.get("notBefore"))
    not_after = _parse_cert_time(cert.get("notAfter"))
    now = datetime.now(UTC)
    time_valid = bool(not_before and not_after and not_before <= now <= not_after)
    expires_at = not_after.isoformat().replace("+00:00", "Z") if not_after else None

    hostname_match = _hostname_matches(cert, hostname)

    chain_valid = _verify_cert_chain(hostname=hostname, port=port, timeout_seconds=timeout_seconds)
    ssl_valid = bool(time_valid and hostname_match and chain_valid)

    error_parts: list[str] = []
    if not time_valid:
        error_parts.append("cert_time_invalid")
    if not hostname_match:
        error_parts.append("cert_hostname_mismatch")
    if not chain_valid:
        error_parts.append("cert_chain_untrusted")

    return SSLCheckResult(
        certificate_present=True,
        ssl_valid=ssl_valid,
        ssl_issuer=issuer,
        ssl_subject=subject,
        ssl_expires_at=expires_at,
        ssl_hostname_match=hostname_match,
        error="|".join(error_parts) if error_parts else None,
    )
