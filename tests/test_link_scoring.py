import unittest

from backend.app.risk_agent.link_scoring import assess_link_risk
from backend.app.schemas import LinkScanResult


class LinkScoringTests(unittest.TestCase):
    def test_malicious_verdict_forces_quarantine(self) -> None:
        results = [
            LinkScanResult(
                original_url="https://evil.example.com",
                normalized_url="https://evil.example.com/",
                final_url="https://evil.example.com/login",
                reachable=True,
                http_status=200,
                ssl_valid=True,
                ssl_issuer="issuer",
                ssl_subject="subject",
                ssl_expires_at="2030-01-01T00:00:00Z",
                ssl_hostname_match=True,
                yutori_verdict="malicious",
                yutori_summary="Phishing login page detected.",
                risk_flags=[],
                scan_status="ok",
            )
        ]
        assessment = assess_link_risk(results, fail_closed=True)
        self.assertTrue(assessment.force_quarantine)
        self.assertGreaterEqual(float(assessment.risk_score or 0), 0.99)

    def test_timeout_fail_closed_sets_force(self) -> None:
        results = [
            LinkScanResult(
                original_url="https://unknown.example.com",
                normalized_url="https://unknown.example.com/",
                final_url="https://unknown.example.com/",
                reachable=True,
                http_status=200,
                ssl_valid=True,
                ssl_issuer="issuer",
                ssl_subject="subject",
                ssl_expires_at="2030-01-01T00:00:00Z",
                ssl_hostname_match=True,
                yutori_verdict="unknown",
                yutori_summary="timeout",
                risk_flags=[],
                scan_status="timeout",
            )
        ]
        assessment = assess_link_risk(results, fail_closed=True)
        self.assertTrue(assessment.force_quarantine)
        self.assertTrue(assessment.failed_closed)
        self.assertIn("link_scan_timeout_fail_closed", assessment.risk_flags)


if __name__ == "__main__":
    unittest.main()
