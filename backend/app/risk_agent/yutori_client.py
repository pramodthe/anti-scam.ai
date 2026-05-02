import html
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import requests


@dataclass
class YutoriScanResult:
    final_url: str
    reachable: bool
    http_status: int | None
    verdict: str
    summary: str
    provider: str = "yutori_api"
    executed: bool = False
    task_id: str | None = None
    preview_url: str | None = None
    details: dict[str, Any] | None = None
    risk_flags: list[str] = field(default_factory=list)
    scan_status: str = "error"
    ssl_state: Literal["valid", "invalid", "unknown"] = "unknown"
    ssl_source: str = "unknown"
    ssl_issuer: str = ""
    ssl_subject: str = ""
    ssl_expires_at: str | None = None
    ssl_hostname_match: bool = False


@dataclass
class YutoriResearchResult:
    query: str
    summary: str
    provider: str = "yutori_api"
    executed: bool = False
    task_id: str | None = None
    preview_url: str | None = None
    details: dict[str, Any] | None = None


SSL_INVALID_TOKENS = {
    "invalid certificate",
    "certificate invalid",
    "ssl invalid",
    "tls invalid",
    "expired certificate",
    "certificate expired",
    "self-signed",
    "self signed",
    "hostname mismatch",
    "certificate hostname mismatch",
    "untrusted certificate",
    "untrusted issuer",
    "certificate verify failed",
    "cert chain untrusted",
}

SSL_VALID_TOKENS = {
    "valid certificate",
    "certificate valid",
    "ssl valid",
    "tls valid",
    "certificate verified",
    "trusted certificate",
    "secure connection",
}


def _heuristic_verdict(text: str) -> tuple[str, list[str]]:
    content = text.lower()
    flags: list[str] = []

    malicious_tokens = {"phishing", "credential theft", "malicious", "scam", "fake login", "fraud"}
    suspicious_tokens = {"suspicious", "deceptive", "untrusted", "risk", "impersonation"}
    safe_tokens = {"safe", "legitimate", "benign", "legit", "trustworthy"}

    if any(token in content for token in malicious_tokens):
        flags.append("yutori_malicious_signal")
        return "malicious", flags
    if any(token in content for token in suspicious_tokens):
        flags.append("yutori_suspicious_signal")
        return "suspicious", flags
    if any(token in content for token in safe_tokens):
        return "safe", flags
    return "unknown", flags


def _extract_preview_url(payload: dict[str, Any]) -> str | None:
    priority_keys = ("preview_url", "view_url", "replay_url", "session_url", "video_url", "task_url")
    candidates: list[tuple[str, str]] = []

    def visit(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                next_prefix = f"{prefix}.{key}" if prefix else str(key)
                visit(nested, next_prefix)
        elif isinstance(value, list):
            for idx, nested in enumerate(value):
                visit(nested, f"{prefix}[{idx}]")
        elif isinstance(value, str):
            normalized = value.strip()
            if normalized.startswith("http://") or normalized.startswith("https://"):
                candidates.append((prefix.lower(), normalized))

    visit(payload)

    for preferred in priority_keys:
        for key_path, url in candidates:
            if key_path.endswith(preferred) or f".{preferred}" in key_path:
                return url
    for key_path, url in candidates:
        if "preview" in key_path or "replay" in key_path or "session" in key_path or "video" in key_path:
            return url
    return None


def _compact_details(payload: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {"status": payload.get("status")}
    for key in ("result", "error", "summary", "steps", "actions", "artifacts"):
        if key in payload:
            compact[key] = payload[key]
    return compact


def _normalize_path(path: str) -> str:
    normalized = path.strip()
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized


def _normalize_result_text(value: Any) -> str:
    text = html.unescape(str(value))
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _iter_payload_items(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    items: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            items.extend(_iter_payload_items(nested, next_prefix))
    elif isinstance(value, list):
        for idx, nested in enumerate(value):
            items.extend(_iter_payload_items(nested, f"{prefix}[{idx}]"))
    else:
        items.append((prefix.lower(), value))
    return items


def _is_ssl_path(path: str) -> bool:
    return any(token in path for token in ("ssl", "certificate", "tls"))


def _extract_ssl_observations(
    payload: dict[str, Any] | None,
) -> tuple[Literal["valid", "invalid", "unknown"], str, str, str | None, bool]:
    if not payload:
        return "unknown", "", "", None, False

    explicit_valid: bool | None = None
    explicit_invalid: bool | None = None
    status_hints: list[str] = []
    text_chunks: list[str] = []
    ssl_issuer = ""
    ssl_subject = ""
    ssl_expires_at: str | None = None
    ssl_hostname_match = False

    for path, raw_value in _iter_payload_items(payload):
        if isinstance(raw_value, bool):
            if path.endswith(("ssl_valid", "certificate_valid", "tls_valid", "ssl.valid", "certificate.valid", "tls.valid")):
                if raw_value:
                    explicit_valid = True
                else:
                    explicit_invalid = True
            if path.endswith(("ssl_invalid", "certificate_invalid", "tls_invalid", "ssl.invalid", "certificate.invalid", "tls.invalid")):
                if raw_value:
                    explicit_invalid = True
                else:
                    explicit_valid = True
            if path.endswith(
                (
                    "ssl_hostname_match",
                    "certificate_hostname_match",
                    "hostname_match",
                    "ssl.hostname_match",
                    "certificate.hostname_match",
                )
            ):
                ssl_hostname_match = raw_value
            continue

        if not isinstance(raw_value, str):
            continue

        normalized = _normalize_result_text(raw_value).lower()
        if not normalized:
            continue
        text_chunks.append(normalized)

        if path.endswith(("ssl_state", "ssl_status", "certificate_status", "tls_status", "security_status")) or (
            _is_ssl_path(path) and path.endswith(("state", "status"))
        ):
            status_hints.append(normalized)

        if not ssl_issuer and path.endswith(("ssl_issuer", "certificate_issuer", "tls_issuer")):
            ssl_issuer = raw_value.strip()
        if not ssl_subject and path.endswith(("ssl_subject", "certificate_subject", "tls_subject")):
            ssl_subject = raw_value.strip()
        if ssl_expires_at is None and path.endswith(
            (
                "ssl_expires_at",
                "certificate_expires_at",
                "certificate_expiry",
                "tls_expires_at",
                "not_after",
                "valid_to",
            )
        ):
            candidate = raw_value.strip()
            ssl_expires_at = candidate or None

    ssl_state: Literal["valid", "invalid", "unknown"] = "unknown"
    if explicit_invalid:
        ssl_state = "invalid"
    elif explicit_valid:
        ssl_state = "valid"
    else:
        status_blob = " ".join(status_hints)
        text_blob = " ".join(text_chunks)
        if any(token in status_blob for token in SSL_INVALID_TOKENS) or any(
            token in text_blob for token in SSL_INVALID_TOKENS
        ):
            ssl_state = "invalid"
        elif any(token in status_blob for token in SSL_VALID_TOKENS) or any(
            token in text_blob for token in SSL_VALID_TOKENS
        ):
            ssl_state = "valid"

    return ssl_state, ssl_issuer, ssl_subject, ssl_expires_at, ssl_hostname_match


class YutoriBrowserClient:
    def __init__(
        self,
        api_key: str | None,
        base_url: str | None,
        browse_max_steps: int,
        timeout_seconds: int,
    ) -> None:
        self.api_key = api_key or ""
        self.base_url = (base_url or "https://api.yutori.com/v1").rstrip("/")
        self.browse_max_steps = browse_max_steps
        self.timeout_seconds = timeout_seconds
        self._canonical_run_path = "/browsing/tasks"
        self._canonical_result_path_template = "/browsing/tasks/{task_id}"
        self._run_path = _normalize_path(os.getenv("YUTORI_BROWSE_PATH", self._canonical_run_path))
        self._result_path_template = _normalize_path(
            os.getenv("YUTORI_BROWSE_RESULT_PATH", self._canonical_result_path_template)
        )
        self._poll_timeout_seconds = max(
            self.timeout_seconds,
            int(os.getenv("YUTORI_POLL_TIMEOUT_SECONDS", "90")),
        )

    @classmethod
    def from_env(cls, timeout_seconds: int, browse_max_steps: int) -> "YutoriBrowserClient":
        return cls(
            api_key=os.getenv("YUTORI_API_KEY"),
            base_url=os.getenv("YUTORI_BASE_URL"),
            browse_max_steps=browse_max_steps,
            timeout_seconds=timeout_seconds,
        )

    def _headers(self) -> dict[str, str]:
        # Yutori REST expects X-API-Key; Authorization is included as fallback for older environments.
        return {
            "Authorization": f"Bearer {self.api_key}",
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
        }

    def _run_path_candidates(self) -> list[str]:
        candidates = [self._run_path]
        if self._canonical_run_path not in candidates:
            candidates.append(self._canonical_run_path)
        return candidates

    def _result_endpoint_candidates(self, task_id: str) -> list[str]:
        configured = _normalize_path(self._result_path_template.format(task_id=task_id))
        canonical = self._canonical_result_path_template.format(task_id=task_id)
        candidates = [configured]
        if canonical not in candidates:
            candidates.append(canonical)
        return candidates

    def _resolve_url(self, url: str) -> tuple[str, bool, int | None]:
        try:
            response = requests.get(url, allow_redirects=True, timeout=self.timeout_seconds)
            return response.url or url, True, response.status_code
        except Exception:
            return url, False, None

    def _start_task(self, start_url: str, sender_domain: str) -> tuple[str, str | None, dict[str, Any]]:
        prompt = (
            "Open this page and evaluate whether it looks legitimate or scam/phishing. "
            "Check login/payment prompts, brand-domain mismatch, suspicious redirects, and trust signals. "
            f"Sender domain context: {sender_domain or 'unknown'}."
        )
        payload = {
            "start_url": start_url,
            "task": prompt,
            "max_steps": self.browse_max_steps,
        }
        last_http_error: requests.HTTPError | None = None
        for run_path in self._run_path_candidates():
            response = requests.post(
                f"{self.base_url}{run_path}",
                json=payload,
                headers=self._headers(),
                timeout=self.timeout_seconds,
            )
            try:
                response.raise_for_status()
            except requests.HTTPError as exc:
                status_code = exc.response.status_code if exc.response is not None else None
                if status_code in {403, 404, 405} and run_path != self._canonical_run_path:
                    last_http_error = exc
                    continue
                raise

            body = response.json()
            task_id = body.get("task_id") or body.get("id")
            if not task_id:
                raise RuntimeError("missing_task_id")
            preview_url = _extract_preview_url(body)
            return str(task_id), preview_url, _compact_details(body)

        if last_http_error is not None:
            raise last_http_error
        raise RuntimeError("yutori_start_failed")

    def _poll_task(self, task_id: str) -> tuple[str, str, list[str], str, str | None, dict[str, Any] | None]:
        deadline = time.time() + self._poll_timeout_seconds
        endpoints = self._result_endpoint_candidates(task_id)
        endpoint_idx = 0
        while time.time() < deadline:
            endpoint = endpoints[endpoint_idx]
            response = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self._headers(),
                timeout=self.timeout_seconds,
            )
            if response.status_code >= 400:
                if response.status_code in {403, 404, 405} and endpoint_idx + 1 < len(endpoints):
                    endpoint_idx += 1
                    time.sleep(0.5)
                    continue
                response.raise_for_status()
            body = response.json()
            status = str(body.get("status", "")).lower()
            if status in {"succeeded", "completed", "success"}:
                result_text = _normalize_result_text(body.get("result", body))
                verdict, flags = _heuristic_verdict(result_text)
                return verdict, result_text, flags, "ok", _extract_preview_url(body), _compact_details(body)
            if status in {"failed", "error"}:
                return (
                    "unknown",
                    str(body.get("error", "yutori_task_failed")),
                    ["yutori_task_failed"],
                    "error",
                    _extract_preview_url(body),
                    _compact_details(body),
                )
            time.sleep(1.0)
        return (
            "unknown",
            f"yutori_task_timeout_after_{self._poll_timeout_seconds}s",
            ["yutori_task_timeout"],
            "timeout",
            None,
            None,
        )

    def scan_url(self, url: str, sender_domain: str) -> YutoriScanResult:
        final_url, reachable, http_status = self._resolve_url(url)
        target_url = final_url if reachable else url
        precheck_flags = ["link_unreachable"] if not reachable else []

        if not self.api_key:
            return YutoriScanResult(
                final_url=target_url,
                reachable=reachable,
                http_status=http_status,
                verdict="unknown",
                summary="Yutori API key not configured",
                provider="yutori_api",
                executed=False,
                task_id=None,
                preview_url=None,
                details={
                    "provider": "yutori_api",
                    "executed": False,
                    "reason": "yutori_unconfigured",
                    "precheck_reachable": reachable,
                },
                risk_flags=_dedupe(precheck_flags + ["yutori_unconfigured", "yutori_ssl_unknown"]),
                scan_status="error",
                ssl_state="unknown",
                ssl_source="unknown",
            )

        try:
            task_id, start_preview_url, start_details = self._start_task(start_url=target_url, sender_domain=sender_domain)
            verdict, summary, flags, scan_status, poll_preview_url, poll_details = self._poll_task(task_id=task_id)
            ssl_state, ssl_issuer, ssl_subject, ssl_expires_at, ssl_hostname_match = _extract_ssl_observations(
                {
                    "start": start_details or {},
                    "poll": poll_details or {},
                    "summary": summary,
                }
            )
            if not reachable:
                flags.append("link_unreachable")
            if ssl_state == "invalid":
                flags.append("yutori_invalid_ssl_certificate")
            elif ssl_state == "unknown":
                flags.append("yutori_ssl_unknown")
            return YutoriScanResult(
                final_url=target_url,
                reachable=reachable or scan_status == "ok",
                http_status=http_status,
                verdict=verdict,
                summary=summary,
                provider="yutori_api",
                executed=True,
                task_id=task_id,
                preview_url=poll_preview_url or start_preview_url,
                details=poll_details or start_details,
                risk_flags=_dedupe(flags),
                scan_status=scan_status,
                ssl_state=ssl_state,
                ssl_source="yutori",
                ssl_issuer=ssl_issuer,
                ssl_subject=ssl_subject,
                ssl_expires_at=ssl_expires_at,
                ssl_hostname_match=ssl_hostname_match,
            )
        except requests.Timeout:
            return YutoriScanResult(
                final_url=target_url,
                reachable=reachable,
                http_status=http_status,
                verdict="unknown",
                summary="Yutori request timeout",
                provider="yutori_api",
                executed=False,
                task_id=None,
                preview_url=None,
                details={
                    "provider": "yutori_api",
                    "executed": False,
                    "reason": "yutori_request_timeout",
                    "precheck_reachable": reachable,
                },
                risk_flags=_dedupe(precheck_flags + ["yutori_request_timeout", "yutori_ssl_unknown"]),
                scan_status="timeout",
                ssl_state="unknown",
                ssl_source="unknown",
            )
        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            response_text = ""
            if exc.response is not None:
                response_text = (exc.response.text or "").strip()
            http_details: dict[str, Any] = {
                "provider": "yutori_api",
                "executed": False,
                "reason": "yutori_http_error",
                "status_code": status_code,
            }
            if response_text:
                http_details["response"] = response_text[:500]
            return YutoriScanResult(
                final_url=target_url,
                reachable=reachable,
                http_status=http_status,
                verdict="unknown",
                summary=f"Yutori HTTP error {status_code}",
                provider="yutori_api",
                executed=False,
                task_id=None,
                preview_url=None,
                details=http_details,
                risk_flags=_dedupe(precheck_flags + ["yutori_http_error", "yutori_ssl_unknown"]),
                scan_status="error",
                ssl_state="unknown",
                ssl_source="unknown",
            )
        except Exception as exc:
            return YutoriScanResult(
                final_url=target_url,
                reachable=reachable,
                http_status=http_status,
                verdict="unknown",
                summary=f"Yutori error: {exc}",
                provider="yutori_api",
                executed=False,
                task_id=None,
                preview_url=None,
                details={
                    "provider": "yutori_api",
                    "executed": False,
                    "reason": "yutori_error",
                    "precheck_reachable": reachable,
                },
                risk_flags=_dedupe(precheck_flags + ["yutori_error", "yutori_ssl_unknown"]),
                scan_status="error",
                ssl_state="unknown",
                ssl_source="unknown",
            )

    def research_text(
        self,
        *,
        sender_email: str,
        company_name: str,
        subject: str,
        body: str,
    ) -> YutoriResearchResult:
        query_parts = [company_name.strip(), sender_email.strip(), subject.strip(), body.strip()[:240]]
        query = " | ".join(part for part in query_parts if part)
        if not query:
            query = "Suspicious email investigation"

        if not self.api_key:
            return YutoriResearchResult(
                query=query,
                summary="Yutori API key not configured.",
                executed=False,
                details={"reason": "yutori_unconfigured"},
            )

        sender_domain = sender_email.split("@", maxsplit=1)[1].strip() if "@" in sender_email else ""
        start_url = f"https://{sender_domain}" if sender_domain else "https://www.google.com"
        prompt = (
            "Investigate whether this email context appears to be scam or phishing. "
            "Check sender identity, company legitimacy, signs of impersonation, payment or credential theft patterns, "
            f"and summarize the risk clearly. Context: sender={sender_email or 'unknown'}; "
            f"company={company_name or 'unknown'}; subject={subject or 'n/a'}; "
            f"body_excerpt={body[:500] or 'n/a'}."
        )
        payload = {
            "start_url": start_url,
            "task": prompt,
            "max_steps": self.browse_max_steps,
        }

        try:
            response = requests.post(
                f"{self.base_url}{self._canonical_run_path}",
                json=payload,
                headers=self._headers(),
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            body_payload = response.json()
            task_id = str(body_payload.get("task_id") or body_payload.get("id") or "")
            if not task_id:
                return YutoriResearchResult(
                    query=query,
                    summary="Yutori task id missing from response.",
                    executed=False,
                    details=_compact_details(body_payload),
                )
            verdict, summary, _flags, _scan_status, preview_url, details = self._poll_task(task_id=task_id)
            label = verdict.upper()
            final_summary = f"{label}: {summary}" if summary else label
            return YutoriResearchResult(
                query=query,
                summary=final_summary,
                executed=True,
                task_id=task_id,
                preview_url=preview_url or _extract_preview_url(body_payload),
                details=details or _compact_details(body_payload),
            )
        except Exception as exc:
            return YutoriResearchResult(
                query=query,
                summary=f"Yutori research failed: {exc}",
                executed=False,
                details={"reason": "yutori_research_error"},
            )
