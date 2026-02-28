"""
Batch Email Risk Evaluation Test
=================================
Sends a diverse batch of emails through the full API pipeline in one go:
  1. POST /risk/emails/evaluate  (for every email in the batch)
  2. GET  /risk/quarantine       (verify quarantine list)
  3. GET  /risk/quarantine/{id}  (spot-check details)
  4. POST /risk/quarantine/{id}/label   (HITL labelling)
  5. POST /risk/quarantine/{id}/release (release flow)

Run:
    python -m pytest tests/test_batch_emails.py -v
    # or
    python -m unittest tests.test_batch_emails -v
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import backend.app.api as api_module
from backend.app.risk_agent.service import RiskService

# ---------------------------------------------------------------------------
# Test email corpus – 15 emails covering a wide range of scenarios
# ---------------------------------------------------------------------------
BATCH_EMAILS: list[dict] = [
    # ── HIGH-RISK: should be quarantined ──────────────────────────────────
    {
        "id": "batch-001",
        "thread_id": "t-001",
        "from_email": "PayPal Support <security-alerts@payment-review.biz>",
        "to_email": "victim@example.com",
        "subject": "Urgent: verify your PayPal account",
        "body": "Your account has been suspended. Login immediately to verify your password or your funds will be locked.",
        "send_time": "Fri, 27 Feb 2026 09:00:00 +0000",
        "headers": None,
        "expect_decision": "quarantine",
        "expect_reasons_contain": ["display_name_domain_mismatch", "credential_phishing_pattern", "urgency_language"],
        "category": "phishing-domain-mismatch",
    },
    {
        "id": "batch-002",
        "thread_id": "t-002",
        "from_email": "Amazon Customer Service <orders@amaz0n-support.top>",
        "to_email": "victim@example.com",
        "subject": "Action required: confirm your Amazon order",
        "body": "We detected unusual activity. Verify your account now or your recent order will be canceled.",
        "send_time": "Fri, 27 Feb 2026 09:05:00 +0000",
        "headers": None,
        "expect_decision": "quarantine",
        "expect_reasons_contain": ["display_name_domain_mismatch"],
        "category": "phishing-fake-amazon",
    },
    {
        "id": "batch-003",
        "thread_id": "t-003",
        "from_email": "Microsoft Security <noreply@ms-login-check.xyz>",
        "to_email": "victim@example.com",
        "subject": "Reset your password now – final notice",
        "body": "Immediate action required. Your Microsoft account credentials need to be reset. Click here to login.",
        "send_time": "Fri, 27 Feb 2026 09:10:00 +0000",
        "headers": None,
        "expect_decision": "quarantine",
        "expect_reasons_contain": ["credential_phishing_pattern", "urgency_language"],
        "category": "phishing-microsoft-impersonation",
    },
    {
        "id": "batch-004",
        "thread_id": "t-004",
        "from_email": "gsqsxezcvh <xgejztwlnpkrok.505@drz8ov.yklc8d.dmxmsq.us>",
        "to_email": "victim@example.com",
        "subject": "Final Notice: 2500 payout and 300 free spins",
        "body": "Congratulations! Claim your 2500 bonus offer. No deposit required. Promo code WELCOME100. Pending verification.",
        "send_time": "Fri, 27 Feb 2026 09:15:00 +0000",
        "headers": None,
        "expect_decision": "quarantine",
        "expect_reasons_contain": ["promo_lure_pattern"],
        "category": "promo-scam-random-sender",
    },
    {
        "id": "batch-005",
        "thread_id": "t-005",
        "from_email": "CEO Office <ceo@company-internal.work>",
        "to_email": "accountant@example.com",
        "subject": "Wire transfer needed urgently – action required",
        "body": "I need you to arrange a wire transfer of $45,000 to a new vendor. Use these bank details. Verify your account login credentials and confirm your password immediately. This is your final notice.",
        "send_time": "Fri, 27 Feb 2026 09:20:00 +0000",
        "headers": None,
        "expect_decision": "quarantine",
        "expect_reasons_contain": ["payment_request_pattern", "urgency_language", "credential_phishing_pattern"],
        "category": "bec-wire-transfer",
    },
    {
        "id": "batch-006",
        "thread_id": "t-006",
        "from_email": "HR Team <hr-notifications@random-hr-portal.click>",
        "to_email": "employee@example.com",
        "subject": "Urgent: Update your SSN for payroll – action required",
        "body": "Please confirm your social security number and password for payroll processing. Verify your account immediately or access will be suspended. This is your final notice.",
        "send_time": "Fri, 27 Feb 2026 09:25:00 +0000",
        "headers": None,
        "expect_decision": "quarantine",
        "expect_reasons_contain": ["credential_phishing_pattern", "urgency_language"],
        "category": "hr-impersonation-ssn",
    },
    {
        "id": "batch-007",
        "thread_id": "t-007",
        "from_email": "Netflix Billing <billing-update3942@nf-renewal.shop>",
        "to_email": "victim@example.com",
        "subject": "Payment due – your Netflix subscription expires today",
        "body": "Your Netflix account payment is overdue. Update your payment details to avoid service interruption. Limited time.",
        "send_time": "Fri, 27 Feb 2026 09:30:00 +0000",
        "headers": None,
        "expect_decision": "quarantine",
        "expect_reasons_contain": ["display_name_domain_mismatch"],
        "category": "phishing-netflix-payment",
    },
    {
        "id": "batch-008",
        "thread_id": "t-008",
        "from_email": "Apple ID Support <verify2984710@apple-id-check.biz>",
        "to_email": "victim@example.com",
        "subject": "Your Apple ID has been locked",
        "body": "We detected suspicious activity on your Apple account. Verify your account OTP and security code immediately.",
        "send_time": "Fri, 27 Feb 2026 09:35:00 +0000",
        "headers": None,
        "expect_decision": "quarantine",
        "expect_reasons_contain": ["display_name_domain_mismatch", "credential_phishing_pattern"],
        "category": "phishing-apple-impersonation",
    },
    {
        "id": "batch-009",
        "thread_id": "t-009",
        "from_email": "jyr7k2m9x4832@bnw4xr.yklc8d.top",
        "to_email": "victim@example.com",
        "subject": "Final Notice: Claim reward – jackpot winner",
        "body": "You've won the online casino jackpot! Claim your reward now with promo code JACKPOT2026. No deposit needed. Action required immediately or your payout expires today. Verify your account to confirm.",
        "send_time": "Fri, 27 Feb 2026 09:40:00 +0000",
        "headers": None,
        "expect_decision": "quarantine",
        "expect_reasons_contain": ["promo_lure_pattern", "urgency_language"],
        "category": "casino-promo-scam",
    },
    {
        "id": "batch-010",
        "thread_id": "t-010",
        "from_email": "Finance Team <finance8294@invoicepay.xyz>",
        "to_email": "manager@example.com",
        "subject": "Urgent: Invoice attached – payment due immediately",
        "body": "Action required: process the invoice attached. Overdue payment must be settled via crypto payment to the address below. Verify your account login and confirm your password to authorise the wire transfer. Final notice.",
        "send_time": "Fri, 27 Feb 2026 09:45:00 +0000",
        "headers": None,
        "expect_decision": "quarantine",
        "expect_reasons_contain": ["payment_request_pattern", "urgency_language", "credential_phishing_pattern"],
        "category": "invoice-crypto-fraud",
    },
    # ── LOW-RISK: should be delivered ─────────────────────────────────────
    {
        "id": "batch-011",
        "thread_id": "t-011",
        "from_email": "Alice Johnson <alice@company.com>",
        "to_email": "bob@company.com",
        "subject": "Meeting tomorrow at 10am",
        "body": "Hi Bob, just confirming our 10am meeting tomorrow in the main conference room. See you there!",
        "send_time": "Fri, 27 Feb 2026 10:00:00 +0000",
        "headers": None,
        "expect_decision": "deliver",
        "expect_reasons_contain": [],
        "category": "legitimate-internal-meeting",
    },
    {
        "id": "batch-012",
        "thread_id": "t-012",
        "from_email": "GitHub <noreply@github.com>",
        "to_email": "dev@example.com",
        "subject": "New comment on your pull request",
        "body": "A reviewer left a comment on your PR #42. Check it out when you get a chance.",
        "send_time": "Fri, 27 Feb 2026 10:05:00 +0000",
        "headers": None,
        "expect_decision": "deliver",
        "expect_reasons_contain": [],
        "category": "legitimate-github-notification",
    },
    {
        "id": "batch-013",
        "thread_id": "t-013",
        "from_email": "Jane Smith <jane@example.org>",
        "to_email": "john@example.com",
        "subject": "Lunch plans",
        "body": "Hey John, do you want to grab lunch tomorrow? There's a new Thai place on Main Street.",
        "send_time": "Fri, 27 Feb 2026 10:10:00 +0000",
        "headers": None,
        "expect_decision": "deliver",
        "expect_reasons_contain": [],
        "category": "legitimate-personal",
    },
    {
        "id": "batch-014",
        "thread_id": "t-014",
        "from_email": "noreply@linkedin.com",
        "to_email": "professional@example.com",
        "subject": "You have 3 new connection requests",
        "body": "Hi, you have 3 new connection requests on LinkedIn. Click to view your pending invitations.",
        "send_time": "Fri, 27 Feb 2026 10:15:00 +0000",
        "headers": None,
        "expect_decision": "deliver",
        "expect_reasons_contain": [],
        "category": "legitimate-linkedin",
    },
    {
        "id": "batch-015",
        "thread_id": "t-015",
        "from_email": "Project Bot <ci-bot@company.dev>",
        "to_email": "team@company.dev",
        "subject": "Build #1234 passed",
        "body": "All 142 tests passed. Coverage: 94%. Deployment to staging successful.",
        "send_time": "Fri, 27 Feb 2026 10:20:00 +0000",
        "headers": None,
        "expect_decision": "deliver",
        "expect_reasons_contain": [],
        "category": "legitimate-ci-notification",
    },
]


class BatchEmailRiskTest(unittest.TestCase):
    """Evaluate all emails in one test run and validate decisions + quarantine flow."""

    def setUp(self) -> None:
        self.tmpdir_obj = tempfile.TemporaryDirectory()
        tmpdir = self.tmpdir_obj.name
        env = {
            "RISK_THRESHOLD": "0.65",
            "RISK_LLM_ENABLED": "false",
            "RISK_DECISION_MODE": "rules_only",
            "RISK_QUARANTINE_PATH": str(Path(tmpdir) / "quarantine.jsonl"),
            "RISK_FEEDBACK_PATH": str(Path(tmpdir) / "training_feedback.jsonl"),
        }
        self.env_patcher = patch.dict(os.environ, env, clear=False)
        self.env_patcher.start()
        self.risk_service = RiskService()
        self.api_patcher = patch.object(api_module, "risk", self.risk_service)
        self.api_patcher.start()
        self.client = TestClient(api_module.app)
        self.quarantine_path = Path(tmpdir) / "quarantine.jsonl"
        self.feedback_path = Path(tmpdir) / "training_feedback.jsonl"

    def tearDown(self) -> None:
        self.api_patcher.stop()
        self.env_patcher.stop()
        self.tmpdir_obj.cleanup()

    # ------------------------------------------------------------------
    # 1. Evaluate all emails in batch and verify decisions
    # ------------------------------------------------------------------
    def test_batch_evaluate_decisions(self) -> None:
        """Send all 15 emails to /risk/emails/evaluate and check each decision."""
        results: list[dict] = []
        for email_data in BATCH_EMAILS:
            payload = {
                "email": {
                    k: email_data[k]
                    for k in (
                        "id", "thread_id", "from_email", "to_email",
                        "subject", "body", "send_time", "headers",
                    )
                }
            }
            resp = self.client.post("/risk/emails/evaluate", json=payload)
            self.assertEqual(resp.status_code, 200, f"Failed for {email_data['id']}: {resp.text}")
            body = resp.json()
            results.append(body)

            # ── Decision assertion ────────────────────────────────────
            self.assertEqual(
                body["decision"],
                email_data["expect_decision"],
                f"[{email_data['category']}] {email_data['id']}: "
                f"expected {email_data['expect_decision']}, got {body['decision']} "
                f"(score={body['risk_score']:.3f}, reasons={body['risk_reasons']})",
            )

            # ── Expected reasons present ──────────────────────────────
            for expected_reason in email_data["expect_reasons_contain"]:
                self.assertIn(
                    expected_reason,
                    body["risk_reasons"],
                    f"[{email_data['category']}] {email_data['id']}: "
                    f"missing expected reason '{expected_reason}' in {body['risk_reasons']}",
                )

        # ── Summary printout ──────────────────────────────────────────
        print("\n" + "=" * 90)
        print(f"{'ID':<14} {'CATEGORY':<38} {'DECISION':<12} {'SCORE':>6}  REASONS")
        print("-" * 90)
        for email_data, result in zip(BATCH_EMAILS, results):
            reasons_str = ", ".join(result["risk_reasons"][:3]) or "(none)"
            print(
                f"{result['id']:<14} {email_data['category']:<38} "
                f"{result['decision']:<12} {result['risk_score']:>5.3f}  {reasons_str}"
            )
        print("=" * 90)

        quarantined = [r for r in results if r["decision"] == "quarantine"]
        delivered = [r for r in results if r["decision"] == "deliver"]
        print(f"Total: {len(results)} | Quarantined: {len(quarantined)} | Delivered: {len(delivered)}")

    # ------------------------------------------------------------------
    # 2. Verify quarantine listing after batch evaluation
    # ------------------------------------------------------------------
    def test_quarantine_list_after_batch(self) -> None:
        """After evaluating the batch, GET /risk/quarantine should list all quarantined emails."""
        expected_quarantined_ids: set[str] = set()
        for email_data in BATCH_EMAILS:
            payload = {
                "email": {
                    k: email_data[k]
                    for k in (
                        "id", "thread_id", "from_email", "to_email",
                        "subject", "body", "send_time", "headers",
                    )
                }
            }
            self.client.post("/risk/emails/evaluate", json=payload)
            if email_data["expect_decision"] == "quarantine":
                expected_quarantined_ids.add(email_data["id"])

        resp = self.client.get("/risk/quarantine")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        actual_ids = {e["id"] for e in body["emails"]}
        self.assertEqual(body["count"], len(expected_quarantined_ids))
        self.assertEqual(actual_ids, expected_quarantined_ids)

    # ------------------------------------------------------------------
    # 3. Verify individual quarantine detail retrieval
    # ------------------------------------------------------------------
    def test_quarantine_detail_retrieval(self) -> None:
        """Each quarantined email should be retrievable by ID."""
        for email_data in BATCH_EMAILS:
            payload = {
                "email": {
                    k: email_data[k]
                    for k in (
                        "id", "thread_id", "from_email", "to_email",
                        "subject", "body", "send_time", "headers",
                    )
                }
            }
            self.client.post("/risk/emails/evaluate", json=payload)

        for email_data in BATCH_EMAILS:
            resp = self.client.get(f"/risk/quarantine/{email_data['id']}")
            if email_data["expect_decision"] == "quarantine":
                self.assertEqual(resp.status_code, 200, f"Quarantine detail missing for {email_data['id']}")
                body = resp.json()
                self.assertEqual(body["id"], email_data["id"])
                self.assertEqual(body["status"], "pending_human_review")
                self.assertIsNone(body["label"])
            else:
                self.assertEqual(resp.status_code, 404, f"Non-quarantined {email_data['id']} should 404")

    # ------------------------------------------------------------------
    # 4. HITL labelling flow across quarantined batch
    # ------------------------------------------------------------------
    def test_batch_hitl_labelling(self) -> None:
        """Label half as scam (1) and half as not-scam (0), then verify feedback file."""
        quarantined_ids: list[str] = []
        for email_data in BATCH_EMAILS:
            payload = {
                "email": {
                    k: email_data[k]
                    for k in (
                        "id", "thread_id", "from_email", "to_email",
                        "subject", "body", "send_time", "headers",
                    )
                }
            }
            resp = self.client.post("/risk/emails/evaluate", json=payload)
            if resp.json()["decision"] == "quarantine":
                quarantined_ids.append(email_data["id"])

        self.assertGreater(len(quarantined_ids), 0, "No quarantined emails to label")

        # Label first half as scam, second half as not-scam
        midpoint = len(quarantined_ids) // 2
        scam_ids = quarantined_ids[:midpoint]
        legit_ids = quarantined_ids[midpoint:]

        for msg_id in scam_ids:
            resp = self.client.post(f"/risk/quarantine/{msg_id}/label", json={"label": 1})
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertEqual(body["label"], 1)
            self.assertEqual(body["status"], "confirmed_scam")

        for msg_id in legit_ids:
            resp = self.client.post(f"/risk/quarantine/{msg_id}/label", json={"label": 0})
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertEqual(body["label"], 0)
            self.assertEqual(body["status"], "confirmed_legit")

        # Verify feedback file has one entry per labelled email
        self.assertTrue(self.feedback_path.exists(), "Feedback file should exist")
        lines = [l for l in self.feedback_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        self.assertEqual(len(lines), len(quarantined_ids))

        for line in lines:
            record = json.loads(line)
            self.assertIn("label", record)
            self.assertIn("risk_score", record)
            self.assertIn("reviewed_at", record)

    # ------------------------------------------------------------------
    # 5. Release flow for labelled emails
    # ------------------------------------------------------------------
    def test_batch_release_after_label(self) -> None:
        """Label emails as not-scam and release them; verify they leave quarantine list."""
        quarantined_ids: list[str] = []
        for email_data in BATCH_EMAILS:
            payload = {
                "email": {
                    k: email_data[k]
                    for k in (
                        "id", "thread_id", "from_email", "to_email",
                        "subject", "body", "send_time", "headers",
                    )
                }
            }
            resp = self.client.post("/risk/emails/evaluate", json=payload)
            if resp.json()["decision"] == "quarantine":
                quarantined_ids.append(email_data["id"])

        # Release all quarantined emails
        for msg_id in quarantined_ids:
            resp = self.client.post(f"/risk/quarantine/{msg_id}/release", json={})
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.json()["status"], "released")

        # Quarantine list should now be empty (released emails excluded)
        resp = self.client.get("/risk/quarantine")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["count"], 0)

    # ------------------------------------------------------------------
    # 6. Idempotency: re-evaluating same email returns cached decision
    # ------------------------------------------------------------------
    def test_idempotent_evaluation(self) -> None:
        """Evaluating the same email twice should return the same result from cache."""
        email_data = BATCH_EMAILS[0]  # high-risk email
        payload = {
            "email": {
                k: email_data[k]
                for k in (
                    "id", "thread_id", "from_email", "to_email",
                    "subject", "body", "send_time", "headers",
                )
            }
        }
        resp1 = self.client.post("/risk/emails/evaluate", json=payload)
        resp2 = self.client.post("/risk/emails/evaluate", json=payload)
        self.assertEqual(resp1.json()["decision"], resp2.json()["decision"])
        self.assertEqual(resp1.json()["id"], resp2.json()["id"])

    # ------------------------------------------------------------------
    # 7. Persistence: quarantine state survives service restart
    # ------------------------------------------------------------------
    def test_quarantine_persistence_across_restart(self) -> None:
        """Evaluate batch, create new RiskService from same files, verify records survive."""
        quarantined_ids: set[str] = set()
        for email_data in BATCH_EMAILS:
            payload = {
                "email": {
                    k: email_data[k]
                    for k in (
                        "id", "thread_id", "from_email", "to_email",
                        "subject", "body", "send_time", "headers",
                    )
                }
            }
            resp = self.client.post("/risk/emails/evaluate", json=payload)
            if resp.json()["decision"] == "quarantine":
                quarantined_ids.add(email_data["id"])

        # Simulate restart: new service from same JSONL files
        new_service = RiskService()
        with patch.object(api_module, "risk", new_service):
            client2 = TestClient(api_module.app)
            resp = client2.get("/risk/quarantine")
            self.assertEqual(resp.status_code, 200)
            reloaded_ids = {e["id"] for e in resp.json()["emails"]}
            self.assertEqual(reloaded_ids, quarantined_ids)

    # ------------------------------------------------------------------
    # 8. Score sanity: all scores in [0.0, 1.0] range
    # ------------------------------------------------------------------
    def test_all_scores_in_valid_range(self) -> None:
        """Every evaluated email must have a risk_score between 0.0 and 1.0."""
        for email_data in BATCH_EMAILS:
            payload = {
                "email": {
                    k: email_data[k]
                    for k in (
                        "id", "thread_id", "from_email", "to_email",
                        "subject", "body", "send_time", "headers",
                    )
                }
            }
            resp = self.client.post("/risk/emails/evaluate", json=payload)
            score = resp.json()["risk_score"]
            self.assertGreaterEqual(score, 0.0, f"{email_data['id']} score below 0")
            self.assertLessEqual(score, 1.0, f"{email_data['id']} score above 1")

    # ------------------------------------------------------------------
    # 9. Invalid label rejected
    # ------------------------------------------------------------------
    def test_invalid_label_rejected(self) -> None:
        """POST with label=2 should return 422 validation error."""
        email_data = BATCH_EMAILS[0]
        payload = {
            "email": {
                k: email_data[k]
                for k in (
                    "id", "thread_id", "from_email", "to_email",
                    "subject", "body", "send_time", "headers",
                )
            }
        }
        self.client.post("/risk/emails/evaluate", json=payload)
        resp = self.client.post(f"/risk/quarantine/{email_data['id']}/label", json={"label": 2})
        self.assertEqual(resp.status_code, 422)

    # ------------------------------------------------------------------
    # 10. Label non-existent message returns 404
    # ------------------------------------------------------------------
    def test_label_nonexistent_message_404(self) -> None:
        resp = self.client.post("/risk/quarantine/does-not-exist/label", json={"label": 1})
        self.assertEqual(resp.status_code, 404)

    # ------------------------------------------------------------------
    # 11. Release non-existent message returns 404
    # ------------------------------------------------------------------
    def test_release_nonexistent_message_404(self) -> None:
        resp = self.client.post("/risk/quarantine/does-not-exist/release", json={})
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
