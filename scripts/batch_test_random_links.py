#!/usr/bin/env python3
"""
Random Link Batch Test
======================
Generates synthetic inbound emails with random links and sends each payload to:
    POST /risk/emails/evaluate

Usage:
    python scripts/batch_test_random_links.py --base-url http://127.0.0.1:8001 --count 10
"""

from __future__ import annotations

import argparse
import random
import string
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import requests


SAFE_DOMAINS = [
    "github.com",
    "docs.python.org",
    "openai.com",
    "wikipedia.org",
    "ietf.org",
    "developer.mozilla.org",
]

SUSPICIOUS_TLDS = [".top", ".xyz", ".biz", ".click", ".shop", ".work", ".zip"]

TRUSTED_SENDERS = [
    ("GitHub", "github.com"),
    ("Python Docs", "python.org"),
    ("Team Ops", "company.dev"),
    ("Alice Johnson", "company.com"),
]

RISKY_SENDERS = [
    "alerts-security",
    "account-verify",
    "billing-check",
    "support-ops",
    "security-update",
]

RISKY_SUBJECTS = [
    "Urgent action required: verify account now",
    "Final notice: payment pending confirmation",
    "Security alert: reset password immediately",
    "Invoice overdue: update payment details",
    "Claim reward now to avoid expiration",
]

BENIGN_SUBJECTS = [
    "Weekly engineering updates",
    "Build report and deployment notes",
    "Project docs for review",
    "Meeting notes and references",
    "Resource links for next sprint",
]


@dataclass
class GeneratedEmail:
    payload: dict[str, Any]
    profile: str


def _random_token(length: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _random_suspicious_domain() -> str:
    left = _random_token(random.randint(6, 10))
    mid = _random_token(random.randint(5, 8))
    tld = random.choice(SUSPICIOUS_TLDS)
    return f"{left}.{mid}{tld}"


def _safe_url() -> str:
    domain = random.choice(SAFE_DOMAINS)
    path = random.choice(
        [
            "/",
            "/docs",
            "/security",
            "/about",
            "/reference",
            "/release-notes",
        ]
    )
    return f"https://{domain}{path}"


def _risky_url() -> str:
    if random.random() < 0.35:
        bucket = _random_token(20)
        return f"https://storage.googleapis.com/{bucket}/exclusive.html"
    return f"https://{_random_suspicious_domain()}/{random.choice(['login', 'verify', 'claim', 'billing', 'update'])}"


def _gen_sender(profile: str) -> str:
    if profile == "benign":
        name, domain = random.choice(TRUSTED_SENDERS)
        local = random.choice(["noreply", "updates", "team", "alice", "ops"])
        return f"{name} <{local}@{domain}>"
    domain = _random_suspicious_domain()
    local = random.choice(RISKY_SENDERS) + str(random.randint(10, 9999))
    return f"Support Team <{local}@{domain}>"


def _gen_links(profile: str) -> list[str]:
    count = random.randint(1, 3)
    urls: list[str] = []
    for _ in range(count):
        if profile == "benign":
            urls.append(_safe_url())
        else:
            urls.append(_risky_url() if random.random() < 0.8 else _safe_url())
    deduped = list(dict.fromkeys(urls))
    return deduped[:3]


def _gen_email(index: int) -> GeneratedEmail:
    profile = "risky" if random.random() < 0.6 else "benign"
    sender = _gen_sender(profile)
    subject = random.choice(RISKY_SUBJECTS if profile == "risky" else BENIGN_SUBJECTS)
    urls = _gen_links(profile)
    url_lines = "\n".join(f"- {url}" for url in urls)
    body_intro = (
        "Please review the following urgent links and complete verification."
        if profile == "risky"
        else "Sharing reference links for regular follow-up."
    )

    now = datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S +0000")
    uniq = f"{int(time.time())}-{index}-{_random_token(6)}"
    payload = {
        "id": f"rand-link-{uniq}",
        "thread_id": f"thread-rand-link-{uniq}",
        "from_email": sender,
        "to_email": "pramodthebe@gmail.com",
        "subject": subject,
        "body": f"{body_intro}\n\nLinks:\n{url_lines}\n",
        "send_time": now,
        "headers": None,
    }
    return GeneratedEmail(payload=payload, profile=profile)


def _post_evaluate(base_url: str, email: dict[str, Any]) -> dict[str, Any]:
    response = requests.post(
        f"{base_url.rstrip('/')}/risk/emails/evaluate",
        json={"email": email},
        timeout=90,
    )
    response.raise_for_status()
    return response.json()


def run_batch(base_url: str, count: int) -> int:
    print(f"Batch start | base_url={base_url} | count={count}")
    print("-" * 120)
    print(
        f"{'idx':<4} {'profile':<7} {'decision':<10} {'score':>6} "
        f"{'links':<8} {'y_exec':<7} {'fail_closed':<11} subject"
    )
    print("-" * 120)

    risky_count = 0
    benign_count = 0
    quarantined = 0
    delivered = 0
    yutori_executed_total = 0

    for idx in range(1, count + 1):
        generated = _gen_email(idx)
        if generated.profile == "risky":
            risky_count += 1
        else:
            benign_count += 1

        try:
            result = _post_evaluate(base_url=base_url, email=generated.payload)
        except Exception as exc:
            print(f"{idx:<4} {generated.profile:<7} ERROR      {'-':>6} {'-':<8} {'-':<7} {'-':<11} {exc}")
            continue

        decision = str(result.get("decision", "unknown"))
        score = float(result.get("risk_score", 0.0))
        links_scanned = int(result.get("links_scanned", 0) or 0)
        links_found = int(result.get("links_found", 0) or 0)
        link_scan_failed_closed = bool(result.get("link_scan_failed_closed", False))
        subject = str(generated.payload.get("subject", ""))[:80]

        link_results = result.get("link_results", []) or []
        yutori_executed_count = sum(1 for link in link_results if bool(link.get("yutori_executed", False)))
        yutori_executed_total += yutori_executed_count

        if decision == "quarantine":
            quarantined += 1
        elif decision == "deliver":
            delivered += 1

        print(
            f"{idx:<4} {generated.profile:<7} {decision:<10} {score:>6.3f} "
            f"{f'{links_scanned}/{links_found}':<8} {yutori_executed_count:<7} "
            f"{str(link_scan_failed_closed):<11} {subject}"
        )

        for link in link_results:
            url = str(link.get("final_url") or link.get("normalized_url") or link.get("original_url") or "")
            verdict = str(link.get("yutori_verdict", "unknown"))
            status = str(link.get("scan_status", "error"))
            executed = bool(link.get("yutori_executed", False))
            preview = str(link.get("yutori_preview_url") or "")
            print(
                f"     link verdict={verdict:<10} status={status:<7} executed={str(executed):<5} "
                f"url={url}"
            )
            if preview:
                print(f"     preview={preview}")

    print("-" * 120)
    print(
        "Summary "
        f"| risky={risky_count} benign={benign_count} "
        f"| quarantined={quarantined} delivered={delivered} "
        f"| yutori_executed_links={yutori_executed_total}"
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch test random-link emails via /risk/emails/evaluate")
    parser.add_argument("--base-url", default="http://127.0.0.1:8001", help="API base URL")
    parser.add_argument("--count", type=int, default=12, help="Number of synthetic emails")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.count <= 0:
        print("count must be > 0", file=sys.stderr)
        return 2

    random.seed()
    return run_batch(base_url=args.base_url, count=args.count)


if __name__ == "__main__":
    raise SystemExit(main())
