import os
import unittest
from unittest.mock import Mock, patch

from backend.app.risk_agent.llm import RiskLLMScorer


class RiskLLMScorerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = {
            "RISK_LLM_API_URL": "https://api.pioneer.ai/gliner-2/custom",
            "RISK_LLM_API_KEY": "test-key",
            "RISK_LLM_JOB_ID": "job-123",
            "RISK_LLM_TASK": "classify_text",
            "RISK_LLM_SCHEMA_CATEGORIES": "scam,legitimate",
            "RISK_LLM_THRESHOLD": "0.5",
            "RISK_LLM_TIMEOUT_SECONDS": "10",
        }

    def test_score_maps_legitimate_category_to_low_risk(self) -> None:
        with patch.dict(os.environ, self.env, clear=False):
            scorer = RiskLLMScorer(model="unused", enabled=True)
            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value={"result": {"category": "legitimate"}})

            with patch("backend.app.risk_agent.llm.requests.post", return_value=response):
                result = scorer.score(
                    email={"from_email": "sender@example.com", "subject": "Hello", "body": "Body"},
                    features={"rule_score": 0.2},
                )

            self.assertEqual(result.risk_score, 0.0)
            self.assertIn("pioneer_category:legitimate", result.risk_reasons)

    def test_score_maps_scam_category_to_high_risk(self) -> None:
        with patch.dict(os.environ, self.env, clear=False):
            scorer = RiskLLMScorer(model="unused", enabled=True)
            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value={"result": {"category": "scam", "score": 0.93}})

            with patch("backend.app.risk_agent.llm.requests.post", return_value=response):
                result = scorer.score(
                    email={"from_email": "sender@example.com", "subject": "Urgent", "body": "Click now"},
                    features={"rule_score": 0.8},
                )

            self.assertAlmostEqual(result.risk_score, 0.93, places=6)
            self.assertIn("pioneer_category:scam", result.risk_reasons)

    def test_missing_api_key_is_unavailable(self) -> None:
        env = dict(self.env)
        env["RISK_LLM_API_KEY"] = ""
        with patch.dict(os.environ, env, clear=False):
            scorer = RiskLLMScorer(model="unused", enabled=True)
            with self.assertRaises(RuntimeError) as err:
                scorer.score(email={}, features={})
        self.assertEqual(str(err.exception), "llm_unavailable")


if __name__ == "__main__":
    unittest.main()
