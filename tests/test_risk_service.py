import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.risk_agent.service import RiskService
from backend.app.schemas import RiskEmailInput


class RiskServiceTests(unittest.TestCase):
    def _email(self, body: str) -> RiskEmailInput:
        return RiskEmailInput(
            id="msg-service-1",
            thread_id="thread-service-1",
            from_email="PayPal Support <notify@fraud-check.biz>",
            to_email="user@example.com",
            subject="Urgent: verify your account",
            body=body,
            send_time="Fri, 27 Feb 2026 12:00:00 +0000",
            headers=None,
        )

    def test_idempotency_and_label_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = {
                "RISK_THRESHOLD": "0.65",
                "RISK_LLM_ENABLED": "false",
                "RISK_QUARANTINE_PATH": str(Path(tmpdir) / "quarantine.jsonl"),
                "RISK_FEEDBACK_PATH": str(Path(tmpdir) / "training_feedback.jsonl"),
            }
            with patch.dict(os.environ, env, clear=False):
                service = RiskService()
                first_eval = service.evaluate_email(self._email("Immediate action required. Login now."))
                self.assertEqual(first_eval.decision, "quarantine")

                second_eval = service.evaluate_email(self._email("This body changed but same ID"))
                self.assertEqual(second_eval.decision, "quarantine")

                label_response = service.label_quarantine("msg-service-1", 0)
                self.assertEqual(label_response.label, 0)
                self.assertEqual(label_response.status, "confirmed_legit")

                release_response = service.release_quarantine("msg-service-1")
                self.assertEqual(release_response.status, "released")

                third_eval = service.evaluate_email(self._email("Another body"))
                self.assertEqual(third_eval.decision, "deliver")

                feedback_path = Path(env["RISK_FEEDBACK_PATH"])
                self.assertTrue(feedback_path.exists())
                lines = [line for line in feedback_path.read_text(encoding="utf-8").splitlines() if line]
                self.assertEqual(len(lines), 1)


if __name__ == "__main__":
    unittest.main()

