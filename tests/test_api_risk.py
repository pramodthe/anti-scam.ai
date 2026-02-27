import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import backend.app.api as api_module
from backend.app.risk_agent.service import RiskService
from backend.app.schemas import DeleteEmailResponse, GmailEmail, ListEmailsResponse, SendEmailResponse


class RiskApiTests(unittest.TestCase):
    def test_risk_endpoints_and_legacy_gmail_routes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env = {
                "RISK_THRESHOLD": "0.65",
                "RISK_LLM_ENABLED": "false",
                "RISK_QUARANTINE_PATH": str(Path(tmpdir) / "quarantine.jsonl"),
                "RISK_FEEDBACK_PATH": str(Path(tmpdir) / "training_feedback.jsonl"),
            }
            with patch.dict(os.environ, env, clear=False):
                risk_service = RiskService()
                payload = {
                    "email": {
                        "id": "msg-api-1",
                        "thread_id": "thread-api-1",
                        "from_email": "PayPal Support <alerts@review-center.biz>",
                        "to_email": "user@example.com",
                        "subject": "Urgent account verification",
                        "body": "Immediate action required. Verify your account password.",
                        "send_time": "Fri, 27 Feb 2026 12:00:00 +0000",
                        "headers": None,
                    }
                }

                with patch.object(api_module, "risk", risk_service):
                    client = TestClient(api_module.app)
                    eval_resp = client.post("/risk/emails/evaluate", json=payload)
                    self.assertEqual(eval_resp.status_code, 200)
                    self.assertIn("decision", eval_resp.json())

                    list_resp = client.get("/risk/quarantine")
                    self.assertEqual(list_resp.status_code, 200)
                    self.assertEqual(list_resp.json()["count"], 1)

                    detail_resp = client.get("/risk/quarantine/msg-api-1")
                    self.assertEqual(detail_resp.status_code, 200)
                    self.assertEqual(detail_resp.json()["id"], "msg-api-1")

                    invalid_label = client.post("/risk/quarantine/msg-api-1/label", json={"label": 2})
                    self.assertEqual(invalid_label.status_code, 422)

                    valid_label = client.post("/risk/quarantine/msg-api-1/label", json={"label": 1})
                    self.assertEqual(valid_label.status_code, 200)
                    self.assertEqual(valid_label.json()["label"], 1)

                    release_resp = client.post("/risk/quarantine/msg-api-1/release", json={})
                    self.assertEqual(release_resp.status_code, 200)
                    self.assertEqual(release_resp.json()["status"], "released")

            with patch.object(
                api_module.gmail,
                "list_emails",
                return_value=ListEmailsResponse(
                    count=1,
                    emails=[
                        GmailEmail(
                            id="msg-gmail-1",
                            thread_id="thread-gmail-1",
                            from_email="a@example.com",
                            to_email="b@example.com",
                            subject="hello",
                            send_time="Fri, 27 Feb 2026 12:00:00 +0000",
                            body="hi",
                        )
                    ],
                ),
            ), patch.object(
                api_module.gmail,
                "send_email",
                return_value=SendEmailResponse(message_id="sent-1", thread_id="thread-sent-1"),
            ), patch.object(
                api_module.gmail,
                "delete_email",
                return_value=DeleteEmailResponse(message_id="msg-gmail-1", status="trashed"),
            ):
                client = TestClient(api_module.app)

                list_gmail = client.get(
                    "/gmail/emails",
                    params={
                        "email_address": "user@example.com",
                        "minutes_since": 60,
                        "include_read": True,
                        "max_results": 10,
                    },
                )
                self.assertEqual(list_gmail.status_code, 200)
                self.assertEqual(list_gmail.json()["count"], 1)

                send_gmail = client.post("/gmail/send", json={"to": "friend@example.com", "subject": "x", "body": "y"})
                self.assertEqual(send_gmail.status_code, 200)
                self.assertEqual(send_gmail.json()["message_id"], "sent-1")

                delete_gmail = client.delete("/gmail/emails/msg-gmail-1")
                self.assertEqual(delete_gmail.status_code, 200)
                self.assertEqual(delete_gmail.json()["status"], "trashed")


if __name__ == "__main__":
    unittest.main()

