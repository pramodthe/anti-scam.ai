import os
import time
from dataclasses import dataclass, field
from typing import Any

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


def _heuristic_verdict(text: str) -> tuple[str, list[str]]:
    content = text.lower()
    flags: list[str] = []

    malicious_tokens = {"phishing", "credential theft", "malicious", "scam", "fake login", "fraud"}
    suspicious_tokens = {"suspicious", "deceptive", "untrusted", "risk", "impersonation"}
    safe_tokens = {"safe", "legitimate", "benign"}

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
        self._run_path = os.getenv("YUTORI_BROWSE_PATH", "/browsing/tasks")
        self._result_path_template = os.getenv("YUTORI_BROWSE_RESULT_PATH", "/browsing/tasks/{task_id}")
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
        response = requests.post(
            f"{self.base_url}{self._run_path}",
            json=payload,
            headers=self._headers(),
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        body = response.json()
        task_id = body.get("task_id") or body.get("id")
        if not task_id:
            raise RuntimeError("missing_task_id")
        preview_url = _extract_preview_url(body)
        return str(task_id), preview_url, _compact_details(body)

    def _poll_task(self, task_id: str) -> tuple[str, str, list[str], str, str | None, dict[str, Any] | None]:
        deadline = time.time() + self._poll_timeout_seconds
        endpoint = self._result_path_template.format(task_id=task_id)
        while time.time() < deadline:
            response = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self._headers(),
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            body = response.json()
            status = str(body.get("status", "")).lower()
            if status in {"succeeded", "completed", "success"}:
                result_text = str(body.get("result", body))
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
        if not reachable:
            return YutoriScanResult(
                final_url=final_url,
                reachable=False,
                http_status=http_status,
                verdict="unknown",
                summary="URL unreachable during pre-check",
                provider="yutori_api",
                executed=False,
                task_id=None,
                preview_url=None,
                details={"provider": "yutori_api", "executed": False, "reason": "link_unreachable"},
                risk_flags=["link_unreachable"],
                scan_status="error",
            )

        if not self.api_key:
            return YutoriScanResult(
                final_url=final_url,
                reachable=True,
                http_status=http_status,
                verdict="unknown",
                summary="Yutori API key not configured",
                provider="yutori_api",
                executed=False,
                task_id=None,
                preview_url=None,
                details={"provider": "yutori_api", "executed": False, "reason": "yutori_unconfigured"},
                risk_flags=["yutori_unconfigured"],
                scan_status="error",
            )

        try:
            task_id, start_preview_url, start_details = self._start_task(start_url=final_url, sender_domain=sender_domain)
            verdict, summary, flags, scan_status, poll_preview_url, poll_details = self._poll_task(task_id=task_id)
            return YutoriScanResult(
                final_url=final_url,
                reachable=True,
                http_status=http_status,
                verdict=verdict,
                summary=summary,
                provider="yutori_api",
                executed=True,
                task_id=task_id,
                preview_url=poll_preview_url or start_preview_url,
                details=poll_details or start_details,
                risk_flags=flags,
                scan_status=scan_status,
            )
        except requests.Timeout:
            return YutoriScanResult(
                final_url=final_url,
                reachable=True,
                http_status=http_status,
                verdict="unknown",
                summary="Yutori request timeout",
                provider="yutori_api",
                executed=False,
                task_id=None,
                preview_url=None,
                details={"provider": "yutori_api", "executed": False, "reason": "yutori_request_timeout"},
                risk_flags=["yutori_request_timeout"],
                scan_status="timeout",
            )
        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            response_text = ""
            if exc.response is not None:
                response_text = (exc.response.text or "").strip()
            details: dict[str, Any] = {
                "provider": "yutori_api",
                "executed": False,
                "reason": "yutori_http_error",
                "status_code": status_code,
            }
            if response_text:
                details["response"] = response_text[:500]
            return YutoriScanResult(
                final_url=final_url,
                reachable=True,
                http_status=http_status,
                verdict="unknown",
                summary=f"Yutori HTTP error {status_code}",
                provider="yutori_api",
                executed=False,
                task_id=None,
                preview_url=None,
                details=details,
                risk_flags=["yutori_http_error"],
                scan_status="error",
            )
        except Exception as exc:
            return YutoriScanResult(
                final_url=final_url,
                reachable=True,
                http_status=http_status,
                verdict="unknown",
                summary=f"Yutori error: {exc}",
                provider="yutori_api",
                executed=False,
                task_id=None,
                preview_url=None,
                details={"provider": "yutori_api", "executed": False, "reason": "yutori_error"},
                risk_flags=["yutori_error"],
                scan_status="error",
            )
