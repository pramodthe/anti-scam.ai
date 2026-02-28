import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.risk_agent.service import RiskService
from backend.app.risk_agent.ssl_check import SSLCheckResult
from backend.app.risk_agent.yutori_client import YutoriScanResult
from backend.app.schemas import RiskEmailInput


class RiskLinksTests(unittest.TestCase):
    def _email(self, message_id: str) -> RiskEmailInput:
        return RiskEmailInput(
            id=message_id,
            thread_id=f"thread-{message_id}",
            from_email="alerts@example.com",
            to_email="user@example.com",
            subject="Please verify your account",
            body="Review security update: https://security-check.example.com/login",
            send_time="Fri, 27 Feb 2026 12:00:00 +0000",
            headers=None,
        )

    def _build_service(self, tmpdir: str) -> RiskService:
        env = {
            "RISK_THRESHOLD": "0.65",
            "RISK_LLM_ENABLED": "false",
            "RISK_LINK_SCAN_ENABLED": "true",
            "RISK_LINK_SCAN_FAIL_CLOSED": "true",
            "RISK_QUARANTINE_PATH": str(Path(tmpdir) / "quarantine.jsonl"),
            "RISK_FEEDBACK_PATH": str(Path(tmpdir) / "training_feedback.jsonl"),
        }
        with patch.dict(os.environ, env, clear=False):
            return RiskService()

    def test_malicious_link_forces_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            service = self._build_service(tmpdir)
            with patch.object(
                service.graph.yutori_client,
                "scan_url",
                return_value=YutoriScanResult(
                    final_url="https://security-check.example.com/login",
                    reachable=True,
                    http_status=200,
                    verdict="malicious",
                    summary="Phishing login page.",
                    risk_flags=["phishing_page"],
                    scan_status="ok",
                ),
            ), patch(
                "backend.app.risk_agent.graph.check_ssl_certificate",
                return_value=SSLCheckResult(
                    certificate_present=True,
                    ssl_valid=True,
                    ssl_issuer="issuer",
                    ssl_subject="subject",
                    ssl_expires_at="2030-01-01T00:00:00Z",
                    ssl_hostname_match=True,
                    error=None,
                ),
            ):
                result = service.evaluate_email(self._email("msg-link-malicious"))
                self.assertEqual(result.decision, "quarantine")
                self.assertGreaterEqual(result.links_scanned, 1)
                self.assertIn("malicious_link_detected", result.risk_reasons)

    def test_timeout_fail_closed_quarantines(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            service = self._build_service(tmpdir)
            with patch.object(
                service.graph.yutori_client,
                "scan_url",
                return_value=YutoriScanResult(
                    final_url="https://security-check.example.com/login",
                    reachable=True,
                    http_status=200,
                    verdict="unknown",
                    summary="timeout",
                    risk_flags=[],
                    scan_status="timeout",
                ),
            ), patch(
                "backend.app.risk_agent.graph.check_ssl_certificate",
                return_value=SSLCheckResult(
                    certificate_present=True,
                    ssl_valid=True,
                    ssl_issuer="issuer",
                    ssl_subject="subject",
                    ssl_expires_at="2030-01-01T00:00:00Z",
                    ssl_hostname_match=True,
                    error=None,
                ),
            ):
                result = service.evaluate_email(self._email("msg-link-timeout"))
                self.assertEqual(result.decision, "quarantine")
                self.assertTrue(result.link_scan_failed_closed)
                self.assertIn("link_scan_timeout_fail_closed", result.risk_reasons)


if __name__ == "__main__":
    unittest.main()
