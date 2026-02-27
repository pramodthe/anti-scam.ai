import unittest

from backend.app.risk_agent.graph import EmailRiskGraph, decision_from_score


class _FailingLLMScorer:
    def score(self, email: dict, features: dict) -> dict:
        raise RuntimeError("llm failed")


class RiskGraphTests(unittest.TestCase):
    def test_threshold_boundary(self) -> None:
        self.assertEqual(decision_from_score(0.64, 0.65), "deliver")
        self.assertEqual(decision_from_score(0.65, 0.65), "quarantine")

    def test_llm_fallback_uses_rules_and_marks_reason(self) -> None:
        graph = EmailRiskGraph(
            threshold=0.65,
            model_version="risk-agent-v1",
            llm_scorer=_FailingLLMScorer(),  # type: ignore[arg-type]
        )
        email = {
            "id": "msg-2",
            "thread_id": "thread-2",
            "from_email": "Microsoft Security <noreply-security@ms-login-check.xyz>",
            "to_email": "user@example.com",
            "subject": "Action required: reset password now",
            "body": "Immediate action required. Verify your account password.",
            "send_time": "Fri, 27 Feb 2026 12:00:00 +0000",
        }

        result = graph.evaluate(email)
        self.assertIn("llm_unavailable", result["risk_reasons"])
        self.assertEqual(result["decision"], "quarantine")


if __name__ == "__main__":
    unittest.main()

