import os
import unittest
from unittest.mock import MagicMock, patch

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
            self.assertEqual(result.ssl_state, "unknown")
            self.assertIn("yutori_ssl_unknown", result.risk_flags)

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

    def test_start_task_fallbacks_to_canonical_path(self) -> None:
        with patch.dict(os.environ, {"YUTORI_BROWSE_PATH": "/browsing"}, clear=False):
            client = YutoriBrowserClient(
                api_key="token",
                base_url="https://api.example.test",
                browse_max_steps=5,
                timeout_seconds=3,
            )

        first_error_response = MagicMock()
        first_error_response.status_code = 404
        first_http_error = requests.HTTPError("not found", response=first_error_response)

        first_response = MagicMock()
        first_response.raise_for_status.side_effect = first_http_error

        second_response = MagicMock()
        second_response.raise_for_status.return_value = None
        second_response.json.return_value = {
            "task_id": "task-123",
            "status": "queued",
            "view_url": "https://platform.yutori.com/browsing/tasks/task-123",
        }

        with patch("backend.app.risk_agent.yutori_client.requests.post", side_effect=[first_response, second_response]) as post:
            task_id, preview_url, _details = client._start_task(start_url="https://example.com", sender_domain="example.com")

        self.assertEqual(task_id, "task-123")
        self.assertEqual(preview_url, "https://platform.yutori.com/browsing/tasks/task-123")
        called_urls = [call.args[0] for call in post.call_args_list]
        self.assertEqual(called_urls, ["https://api.example.test/browsing", "https://api.example.test/browsing/tasks"])

    def test_scan_extracts_valid_ssl_state(self) -> None:
        client = YutoriBrowserClient(api_key="token", base_url="https://api.example.test", browse_max_steps=5, timeout_seconds=3)
        with patch.object(client, "_resolve_url", return_value=("https://example.com", True, 200)), patch.object(
            client,
            "_start_task",
            return_value=("task-1", None, {"status": "queued"}),
        ), patch.object(
            client,
            "_poll_task",
            return_value=(
                "safe",
                "This page appears legitimate.",
                [],
                "ok",
                None,
                {
                    "result": {
                        "ssl_valid": True,
                        "ssl_issuer": "Let's Encrypt",
                        "ssl_subject": "CN=example.com",
                        "ssl_expires_at": "2030-01-01T00:00:00Z",
                        "ssl_hostname_match": True,
                    }
                },
            ),
        ):
            result = client.scan_url("https://example.com", sender_domain="example.com")

        self.assertEqual(result.ssl_state, "valid")
        self.assertEqual(result.ssl_source, "yutori")
        self.assertEqual(result.ssl_issuer, "Let's Encrypt")
        self.assertEqual(result.ssl_subject, "CN=example.com")
        self.assertEqual(result.ssl_expires_at, "2030-01-01T00:00:00Z")
        self.assertTrue(result.ssl_hostname_match)

    def test_scan_extracts_invalid_ssl_state(self) -> None:
        client = YutoriBrowserClient(api_key="token", base_url="https://api.example.test", browse_max_steps=5, timeout_seconds=3)
        with patch.object(client, "_resolve_url", return_value=("https://example.com", True, 200)), patch.object(
            client,
            "_start_task",
            return_value=("task-1", None, {"status": "queued"}),
        ), patch.object(
            client,
            "_poll_task",
            return_value=(
                "suspicious",
                "Certificate invalid due to hostname mismatch.",
                [],
                "ok",
                None,
                {"result": {"ssl_status": "invalid certificate"}},
            ),
        ):
            result = client.scan_url("https://example.com", sender_domain="example.com")

        self.assertEqual(result.ssl_state, "invalid")
        self.assertIn("yutori_invalid_ssl_certificate", result.risk_flags)

    def test_scan_extracts_unknown_ssl_state(self) -> None:
        client = YutoriBrowserClient(api_key="token", base_url="https://api.example.test", browse_max_steps=5, timeout_seconds=3)
        with patch.object(client, "_resolve_url", return_value=("https://example.com", True, 200)), patch.object(
            client,
            "_start_task",
            return_value=("task-1", None, {"status": "queued"}),
        ), patch.object(
            client,
            "_poll_task",
            return_value=(
                "safe",
                "No SSL details available.",
                [],
                "ok",
                None,
                {"result": {"note": "no certificate data"}},
            ),
        ):
            result = client.scan_url("https://example.com", sender_domain="example.com")

        self.assertEqual(result.ssl_state, "unknown")
        self.assertIn("yutori_ssl_unknown", result.risk_flags)


if __name__ == "__main__":
    unittest.main()
