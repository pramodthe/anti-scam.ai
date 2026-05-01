import unittest

from backend.app.risk_agent.email_parsing import parse_sender


class EmailParsingTests(unittest.TestCase):
    def test_parse_standard_from_header(self) -> None:
        name, addr = parse_sender("PayPal Support <alerts@security-check.biz>")
        self.assertEqual(name, "PayPal Support")
        self.assertEqual(addr, "alerts@security-check.biz")

    def test_parse_comment_style_from_header(self) -> None:
        name, addr = parse_sender("PayPal Support (security-alerts@payment-review.biz)")
        self.assertEqual(name, "PayPal Support")
        self.assertEqual(addr, "security-alerts@payment-review.biz")

    def test_parse_quoted_bare_address(self) -> None:
        name, addr = parse_sender('"PayPal Support" security-alerts@payment-review.biz')
        self.assertEqual(name, "PayPal Support")
        self.assertEqual(addr, "security-alerts@payment-review.biz")


if __name__ == "__main__":
    unittest.main()
