from dataclasses import dataclass

from backend.app.schemas import LinkScanResult


@dataclass
class LinkRiskAssessment:
    risk_score: float | None
    risk_flags: list[str]
    force_quarantine: bool
    failed_closed: bool


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def assess_link_risk(link_results: list[LinkScanResult], fail_closed: bool) -> LinkRiskAssessment:
    if not link_results:
        return LinkRiskAssessment(risk_score=None, risk_flags=[], force_quarantine=False, failed_closed=False)

    score = 0.0
    flags: list[str] = []
    force_quarantine = False
    failed_closed = False

    for result in link_results:
        if result.yutori_verdict == "malicious":
            score = max(score, 1.0)
            force_quarantine = True
            flags.append("malicious_link_detected")
        elif result.yutori_verdict == "suspicious":
            score = max(score, 0.8)
            flags.append("suspicious_link_detected")
        elif result.yutori_verdict == "unknown":
            score = max(score, 0.55)
            flags.append("unknown_link_verdict")

        if not result.reachable:
            score = max(score, 0.65)
            flags.append("link_unreachable")
            if fail_closed:
                force_quarantine = True
                failed_closed = True
                flags.append("link_unreachable_fail_closed")

        if not result.ssl_valid and result.normalized_url.startswith("https://"):
            score = max(score, 0.92)
            force_quarantine = True
            flags.append("invalid_ssl_certificate")

        if result.scan_status == "timeout":
            score = max(score, 0.75)
            flags.append("link_scan_timeout")
            if fail_closed:
                force_quarantine = True
                failed_closed = True
                flags.append("link_scan_timeout_fail_closed")
        elif result.scan_status == "error":
            score = max(score, 0.7)
            flags.append("link_scan_error")
            if fail_closed:
                force_quarantine = True
                failed_closed = True
                flags.append("link_scan_error_fail_closed")

        flags.extend(result.risk_flags)

    return LinkRiskAssessment(
        risk_score=min(score, 1.0),
        risk_flags=_dedupe(flags),
        force_quarantine=force_quarantine,
        failed_closed=failed_closed,
    )
