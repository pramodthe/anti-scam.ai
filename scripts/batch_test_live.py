#!/usr/bin/env python3
"""
Batch Email Live Test
=====================
Sends 15 realistic emails to the RUNNING FastAPI server at http://127.0.0.1:8000.
Quarantined emails are persisted to data/quarantine.jsonl (real file).
Then exercises the full HITL flow: list, detail, label, release.

Usage:
    python3 scripts/batch_test_live.py
"""

import json
import sys
import requests

BASE_URL = "http://127.0.0.1:8000"

# ── 15 realistic test emails ─────────────────────────────────────────────────
EMAILS = [
    # --- HIGH-RISK (expect quarantine) ---
    {
        "id": "live-001",
        "thread_id": "t-live-001",
        "from_email": "PayPal Support <security-alerts@payment-review.biz>",
        "to_email": "victim@example.com",
        "subject": "Urgent: verify your PayPal account",
        "body": "Your account has been suspended. Login immediately to verify your password or your funds will be locked.",
        "send_time": "Fri, 27 Feb 2026 09:00:00 +0000",
        "headers": None,
    },
    {
        "id": "live-002",
        "thread_id": "t-live-002",
        "from_email": "Amazon Customer Service <orders@amaz0n-support.top>",
        "to_email": "victim@example.com",
        "subject": "Action required: confirm your Amazon order",
        "body": "We detected unusual activity. Verify your account now or your recent order will be canceled.",
        "send_time": "Fri, 27 Feb 2026 09:05:00 +0000",
        "headers": None,
    },
    {
        "id": "live-003",
        "thread_id": "t-live-003",
        "from_email": "Microsoft Security <noreply@ms-login-check.xyz>",
        "to_email": "victim@example.com",
        "subject": "Reset your password now – final notice",
        "body": "Immediate action required. Your Microsoft account credentials need to be reset. Click here to login.",
        "send_time": "Fri, 27 Feb 2026 09:10:00 +0000",
        "headers": None,
    },
    {
        "id": "live-004",
        "thread_id": "t-live-004",
        "from_email": "gsqsxezcvh <xgejztwlnpkrok.505@drz8ov.yklc8d.dmxmsq.us>",
        "to_email": "victim@example.com",
        "subject": "Final Notice: 2500 payout and 300 free spins",
        "body": "Congratulations! Claim your 2500 bonus offer. No deposit required. Promo code WELCOME100. Pending verification.",
        "send_time": "Fri, 27 Feb 2026 09:15:00 +0000",
        "headers": None,
    },
    {
        "id": "live-005",
        "thread_id": "t-live-005",
        "from_email": "CEO Office <ceo@company-internal.work>",
        "to_email": "accountant@example.com",
        "subject": "Wire transfer needed urgently – action required",
        "body": "I need you to arrange a wire transfer of $45,000 to a new vendor. Use these bank details. Verify your account login credentials and confirm your password immediately. This is your final notice.",
        "send_time": "Fri, 27 Feb 2026 09:20:00 +0000",
        "headers": None,
    },
    {
        "id": "live-006",
        "thread_id": "t-live-006",
        "from_email": "HR Team <hr-notifications@random-hr-portal.click>",
        "to_email": "employee@example.com",
        "subject": "Urgent: Update your SSN for payroll – action required",
        "body": "Please confirm your social security number and password for payroll processing. Verify your account immediately or access will be suspended. This is your final notice.",
        "send_time": "Fri, 27 Feb 2026 09:25:00 +0000",
        "headers": None,
    },
    {
        "id": "live-007",
        "thread_id": "t-live-007",
        "from_email": "Netflix Billing <billing-update3942@nf-renewal.shop>",
        "to_email": "victim@example.com",
        "subject": "Payment due – your Netflix subscription expires today",
        "body": "Your Netflix account payment is overdue. Update your payment details to avoid service interruption. Limited time.",
        "send_time": "Fri, 27 Feb 2026 09:30:00 +0000",
        "headers": None,
    },
    {
        "id": "live-008",
        "thread_id": "t-live-008",
        "from_email": "Apple ID Support <verify2984710@apple-id-check.biz>",
        "to_email": "victim@example.com",
        "subject": "Your Apple ID has been locked",
        "body": "We detected suspicious activity on your Apple account. Verify your account OTP and security code immediately.",
        "send_time": "Fri, 27 Feb 2026 09:35:00 +0000",
        "headers": None,
    },
    {
        "id": "live-009",
        "thread_id": "t-live-009",
        "from_email": "jyr7k2m9x4832@bnw4xr.yklc8d.top",
        "to_email": "victim@example.com",
        "subject": "Final Notice: Claim reward – jackpot winner",
        "body": "You've won the online casino jackpot! Claim your reward now with promo code JACKPOT2026. No deposit needed. Action required immediately or your payout expires today. Verify your account to confirm.",
        "send_time": "Fri, 27 Feb 2026 09:40:00 +0000",
        "headers": None,
    },
    {
        "id": "live-010",
        "thread_id": "t-live-010",
        "from_email": "Finance Team <finance8294@invoicepay.xyz>",
        "to_email": "manager@example.com",
        "subject": "Urgent: Invoice attached – payment due immediately",
        "body": "Action required: process the invoice attached. Overdue payment must be settled via crypto payment to the address below. Verify your account login and confirm your password to authorise the wire transfer. Final notice.",
        "send_time": "Fri, 27 Feb 2026 09:45:00 +0000",
        "headers": None,
    },
    # --- LOW-RISK (expect deliver) ---
    {
        "id": "live-011",
        "thread_id": "t-live-011",
        "from_email": "Alice Johnson <alice@company.com>",
        "to_email": "bob@company.com",
        "subject": "Meeting tomorrow at 10am",
        "body": "Hi Bob, just confirming our 10am meeting tomorrow in the main conference room. See you there!",
        "send_time": "Fri, 27 Feb 2026 10:00:00 +0000",
        "headers": None,
    },
    {
        "id": "live-012",
        "thread_id": "t-live-012",
        "from_email": "GitHub <noreply@github.com>",
        "to_email": "dev@example.com",
        "subject": "New comment on your pull request",
        "body": "A reviewer left a comment on your PR #42. Check it out when you get a chance.",
        "send_time": "Fri, 27 Feb 2026 10:05:00 +0000",
        "headers": None,
    },
    {
        "id": "live-013",
        "thread_id": "t-live-013",
        "from_email": "Jane Smith <jane@example.org>",
        "to_email": "john@example.com",
        "subject": "Lunch plans",
        "body": "Hey John, do you want to grab lunch tomorrow? There's a new Thai place on Main Street.",
        "send_time": "Fri, 27 Feb 2026 10:10:00 +0000",
        "headers": None,
    },
    {
        "id": "live-014",
        "thread_id": "t-live-014",
        "from_email": "noreply@linkedin.com",
        "to_email": "professional@example.com",
        "subject": "You have 3 new connection requests",
        "body": "Hi, you have 3 new connection requests on LinkedIn. Click to view your pending invitations.",
        "send_time": "Fri, 27 Feb 2026 10:15:00 +0000",
        "headers": None,
    },
    {
        "id": "live-015",
        "thread_id": "t-live-015",
        "from_email": "Project Bot <ci-bot@company.dev>",
        "to_email": "team@company.dev",
        "subject": "Build #1234 passed",
        "body": "All 142 tests passed. Coverage: 94%. Deployment to staging successful.",
        "send_time": "Fri, 27 Feb 2026 10:20:00 +0000",
        "headers": None,
    },
]


def main() -> None:
    # ── Step 0: Health check ──────────────────────────────────────────────
    try:
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        r.raise_for_status()
    except Exception as e:
        print(f"ERROR: Server not reachable at {BASE_URL} — {e}")
        sys.exit(1)

    print(f"Server is up: {r.json()}\n")

    # ── Step 1: Evaluate all 15 emails ────────────────────────────────────
    print("=" * 95)
    print(f"{'#':<4} {'ID':<12} {'DECISION':<12} {'SCORE':>6}  {'STATUS':<22} REASONS")
    print("-" * 95)

    quarantined_ids: list[str] = []
    delivered_ids: list[str] = []

    for i, email in enumerate(EMAILS, 1):
        resp = requests.post(
            f"{BASE_URL}/risk/emails/evaluate",
            json={"email": email},
            timeout=30,
        )
        if resp.status_code != 200:
            print(f"  FAIL {email['id']}: {resp.status_code} {resp.text}")
            continue

        data = resp.json()
        reasons = ", ".join(data["risk_reasons"][:4]) or "(none)"
        print(
            f"{i:<4} {data['id']:<12} {data['decision']:<12} "
            f"{data['risk_score']:>5.3f}  {data['status']:<22} {reasons}"
        )

        if data["decision"] == "quarantine":
            quarantined_ids.append(data["id"])
        else:
            delivered_ids.append(data["id"])

    print("=" * 95)
    print(f"Total: {len(EMAILS)} | Quarantined: {len(quarantined_ids)} | Delivered: {len(delivered_ids)}\n")

    # ── Step 2: List quarantine ───────────────────────────────────────────
    print("── GET /risk/quarantine ──")
    resp = requests.get(f"{BASE_URL}/risk/quarantine", timeout=10)
    qlist = resp.json()
    print(f"Quarantine count: {qlist['count']}")
    for rec in qlist["emails"]:
        print(f"  [{rec['status']}] {rec['id']} — score={rec['risk_score']:.3f} — {rec['subject']}")
    print()

    # ── Step 3: Detail check for first quarantined email ──────────────────
    if quarantined_ids:
        first_id = quarantined_ids[0]
        print(f"── GET /risk/quarantine/{first_id} ──")
        resp = requests.get(f"{BASE_URL}/risk/quarantine/{first_id}", timeout=10)
        detail = resp.json()
        print(f"  ID:          {detail['id']}")
        print(f"  Sender:      {detail.get('sender_name', '')} <{detail.get('sender_email', '')}>")
        print(f"  Subject:     {detail['subject']}")
        print(f"  Score:       {detail['risk_score']}")
        print(f"  Reasons:     {detail['risk_reasons']}")
        print(f"  Status:      {detail['status']}")
        print(f"  Description: {detail['description']}")
        print()

    # ── Step 4: HITL label — mark first 3 as scam, next 3 as legit ───────
    scam_ids = quarantined_ids[:3]
    legit_ids = quarantined_ids[3:6]

    if scam_ids:
        print("── Labelling as SCAM (label=1) ──")
        for mid in scam_ids:
            resp = requests.post(
                f"{BASE_URL}/risk/quarantine/{mid}/label",
                json={"label": 1},
                timeout=10,
            )
            d = resp.json()
            print(f"  {d['id']} → label={d['label']} status={d['status']}")
        print()

    if legit_ids:
        print("── Labelling as NOT SCAM (label=0) ──")
        for mid in legit_ids:
            resp = requests.post(
                f"{BASE_URL}/risk/quarantine/{mid}/label",
                json={"label": 0},
                timeout=10,
            )
            d = resp.json()
            print(f"  {d['id']} → label={d['label']} status={d['status']}")
        print()

    # ── Step 5: Release the legit-labelled ones ───────────────────────────
    if legit_ids:
        print("── Releasing legit-labelled emails ──")
        for mid in legit_ids:
            resp = requests.post(
                f"{BASE_URL}/risk/quarantine/{mid}/release",
                json={},
                timeout=10,
            )
            d = resp.json()
            print(f"  {d['id']} → status={d['status']}")
        print()

    # ── Step 6: Final quarantine state ────────────────────────────────────
    print("── Final quarantine list ──")
    resp = requests.get(f"{BASE_URL}/risk/quarantine", timeout=10)
    qlist = resp.json()
    print(f"Remaining in quarantine: {qlist['count']}")
    for rec in qlist["emails"]:
        print(f"  [{rec['status']}] {rec['id']} — label={rec['label']} — {rec['subject']}")
    print()

    # ── Step 7: Show what's persisted to data/ ────────────────────────────
    print("── Persisted files ──")
    for fpath in ("data/quarantine.jsonl", "data/training_feedback.jsonl"):
        try:
            with open(fpath) as f:
                lines = [l for l in f if l.strip()]
            print(f"  {fpath}: {len(lines)} records")
        except FileNotFoundError:
            print(f"  {fpath}: NOT FOUND")

    print("\nDone. All emails processed through the live API.")


if __name__ == "__main__":
    main()
