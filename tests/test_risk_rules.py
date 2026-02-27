import unittest

from backend.app.risk_agent.rules import extract_features, score_features


class RiskRulesTests(unittest.TestCase):
    def test_detects_domain_mismatch_and_phishing_keywords(self) -> None:
        email = {
            "id": "msg-1",
            "thread_id": "thread-1",
            "from_email": "PayPal Support <alerts-security@payment-review.biz>",
            "to_email": "user@example.com",
            "subject": "Urgent: verify your account now",
            "body": "Your account will be suspended. Login to verify password immediately.",
            "send_time": "Fri, 27 Feb 2026 12:00:00 +0000",
        }

        features = extract_features(email)
        score, reasons, _ = score_features(features)

        self.assertGreater(score, 0.6)
        self.assertIn("display_name_domain_mismatch", reasons)
        self.assertIn("credential_phishing_pattern", reasons)
        self.assertIn("urgency_language", reasons)

    def test_detects_bonus_payout_lure_and_random_sender_patterns(self) -> None:
        email = {
            "id": "msg-3",
            "thread_id": "thread-3",
            "from_email": "gsqsxezcvh <xgejztwlnpkrok.505@drz8ov.yklc8d.dmxmsq.us>",
            "to_email": "user@example.com",
            "subject": "Final Notice: 2500 payout and 300 free spins",
            "body": "2500 bonus offer. No deposit. Promo code WELCOME100. Pending verification.",
            "send_time": "Fri, 27 Feb 2026 12:00:00 +0000",
        }

        features = extract_features(email)
        score, reasons, _ = score_features(features)

        self.assertGreaterEqual(score, 0.65)
        self.assertIn("promo_lure_pattern", reasons)
        self.assertIn("suspicious_sender_domain_structure", reasons)


if __name__ == "__main__":
    unittest.main()
