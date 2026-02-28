import unittest
from unittest.mock import patch

from backend.app.risk_agent.ssl_check import check_ssl_certificate


class SSLCheckTests(unittest.TestCase):
    def test_valid_certificate_path(self) -> None:
        cert = {
            "issuer": ((("commonName", "Test CA"),),),
            "subject": ((("commonName", "example.com"),),),
            "notBefore": "Jan 01 00:00:00 2020 GMT",
            "notAfter": "Jan 01 00:00:00 2035 GMT",
        }
        with patch("backend.app.risk_agent.ssl_check._fetch_cert", return_value=cert), patch(
            "backend.app.risk_agent.ssl_check._verify_cert_chain", return_value=True
        ), patch("backend.app.risk_agent.ssl_check._hostname_matches", return_value=True):
            result = check_ssl_certificate("https://example.com")
            self.assertTrue(result.ssl_valid)
            self.assertTrue(result.ssl_hostname_match)

    def test_expired_certificate_is_invalid(self) -> None:
        cert = {
            "issuer": ((("commonName", "Test CA"),),),
            "subject": ((("commonName", "example.com"),),),
            "notBefore": "Jan 01 00:00:00 2010 GMT",
            "notAfter": "Jan 01 00:00:00 2011 GMT",
        }
        with patch("backend.app.risk_agent.ssl_check._fetch_cert", return_value=cert), patch(
            "backend.app.risk_agent.ssl_check._verify_cert_chain", return_value=True
        ), patch("backend.app.risk_agent.ssl_check._hostname_matches", return_value=True):
            result = check_ssl_certificate("https://example.com")
            self.assertFalse(result.ssl_valid)
            self.assertIn("cert_time_invalid", result.error or "")

    def test_hostname_mismatch_is_invalid(self) -> None:
        cert = {
            "issuer": ((("commonName", "Test CA"),),),
            "subject": ((("commonName", "example.com"),),),
            "notBefore": "Jan 01 00:00:00 2020 GMT",
            "notAfter": "Jan 01 00:00:00 2035 GMT",
        }
        with patch("backend.app.risk_agent.ssl_check._fetch_cert", return_value=cert), patch(
            "backend.app.risk_agent.ssl_check._verify_cert_chain", return_value=True
        ), patch("backend.app.risk_agent.ssl_check._hostname_matches", return_value=False):
            result = check_ssl_certificate("https://example.com")
            self.assertFalse(result.ssl_valid)
            self.assertFalse(result.ssl_hostname_match)
            self.assertIn("cert_hostname_mismatch", result.error or "")


if __name__ == "__main__":
    unittest.main()
