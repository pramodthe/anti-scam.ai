import unittest
from unittest.mock import patch

import requests

from backend.app.risk_agent.yutori_client import YutoriBrowserClient, _extract_preview_url, _heuristic_verdict


class YutoriClientTests(unittest.TestCase):
    def test_heuristic_verdict_mapping(self) -> None:
        self.assertEqual(_heuristic_verdict("This page is phishing and malicious")[0], "malicious")
        self.assertEqual(_heuristic_verdict("Suspicious redirect flow")[0], "suspicious")
        self.assertEqual(_heuristic_verdict("Safe and legitimate page")[0], "safe")
        self.assertEqual(_heuristic_verdict("No decision text")[0], "unknown")

    def test_scan_unconfigured_returns_unknown_error(self) -> None:
        client = YutoriBrowserClient(api_key=None, base_url=None, browse_max_steps=5, timeout_seconds=3)
        with patch.object(client, "_resolve_url", return_value=("https://example.com", True, 200)):
            result = client.scan_url("https://example.com", sender_domain="example.com")
            self.assertEqual(result.verdict, "unknown")
            self.assertEqual(result.scan_status, "error")
            self.assertIn("yutori_unconfigured", result.risk_flags)

    def test_scan_timeout_mapping(self) -> None:
        client = YutoriBrowserClient(api_key="token", base_url="https://api.example.test", browse_max_steps=5, timeout_seconds=3)
        with patch.object(client, "_resolve_url", return_value=("https://example.com", True, 200)), patch.object(
            client, "_start_task", side_effect=requests.Timeout("timeout")
        ):
            result = client.scan_url("https://example.com", sender_domain="example.com")
            self.assertEqual(result.scan_status, "timeout")
            self.assertEqual(result.verdict, "unknown")

    def test_default_paths_and_headers(self) -> None:
        client = YutoriBrowserClient(api_key="token", base_url="https://api.example.test", browse_max_steps=5, timeout_seconds=3)
        self.assertEqual(client._run_path, "/browsing/tasks")
        self.assertEqual(client._result_path_template, "/browsing/tasks/{task_id}")
        headers = client._headers()
        self.assertEqual(headers["X-API-Key"], "token")
        self.assertEqual(headers["Authorization"], "Bearer token")

    def test_extract_preview_url_supports_view_url(self) -> None:
        payload = {"task_id": "abc", "view_url": "https://platform.yutori.com/browsing/tasks/abc"}
        self.assertEqual(_extract_preview_url(payload), "https://platform.yutori.com/browsing/tasks/abc")


if __name__ == "__main__":
    unittest.main()
