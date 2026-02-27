import json
import tempfile
import unittest
from pathlib import Path

from backend.app.risk_agent.store import QuarantineStore
from backend.app.schemas import QuarantineRecord, RiskEmailInput


class RiskStoreTests(unittest.TestCase):
    def _record(self, status: str = "pending_human_review") -> QuarantineRecord:
        return QuarantineRecord(
            id="msg-store-1",
            description="Suspicious payment request",
            risk_score=0.9,
            risk_reasons=["payment_request_pattern"],
            model_version="risk-agent-v1",
            status=status,  # type: ignore[arg-type]
            label=None,
            created_at="2026-02-27T21:00:00Z",
            updated_at="2026-02-27T21:00:00Z",
            email=RiskEmailInput(
                id="msg-store-1",
                thread_id="thread-store-1",
                from_email="Example <fake@alerts.xyz>",
                to_email="user@example.com",
                subject="Payment request",
                body="Wire transfer now.",
                send_time="Fri, 27 Feb 2026 12:00:00 +0000",
                headers=None,
            ),
        )

    def test_upsert_reload_and_feedback_append(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            quarantine_path = str(Path(tmpdir) / "quarantine.jsonl")
            feedback_path = str(Path(tmpdir) / "feedback.jsonl")

            store = QuarantineStore(quarantine_path=quarantine_path, feedback_path=feedback_path)
            first = self._record()
            store.upsert(first)

            updated = first.model_copy(
                update={"status": "confirmed_scam", "label": 1, "updated_at": "2026-02-27T21:10:00Z"}
            )
            store.upsert(updated)
            store.append_feedback(
                {
                    "id": updated.id,
                    "description": updated.description,
                    "risk_score": updated.risk_score,
                    "label": 1,
                    "reviewed_at": "2026-02-27T21:10:00Z",
                }
            )

            reloaded = QuarantineStore(quarantine_path=quarantine_path, feedback_path=feedback_path)
            loaded = reloaded.get("msg-store-1")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded.status, "confirmed_scam")
            self.assertEqual(loaded.label, 1)

            with Path(feedback_path).open("r", encoding="utf-8") as handle:
                lines = [line.strip() for line in handle if line.strip()]
            self.assertEqual(len(lines), 1)
            payload = json.loads(lines[0])
            self.assertEqual(payload["label"], 1)


if __name__ == "__main__":
    unittest.main()

