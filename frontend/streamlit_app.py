import html
import os
from pathlib import Path
from typing import Any

import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

API_BASE = os.getenv("EMAIL_ASSISTANT_API", "http://127.0.0.1:8000")
DEFAULT_ACCOUNT = os.getenv("GMAIL_ACCOUNT", "")
DEFAULT_TO = os.getenv("EMAIL_DEFAULT_TO", "")


def friendly_error(exc: Exception) -> str:
    msg = str(exc)
    if isinstance(exc, requests.ConnectionError):
        return "Cannot reach the API server. Verify the backend is running."
    if isinstance(exc, requests.Timeout):
        return "The request timed out. Retry or reduce the scan size."
    if isinstance(exc, requests.HTTPError):
        resp = getattr(exc, "response", None)
        if resp is not None:
            if resp.status_code == 404:
                return "The requested item was not found."
            if resp.status_code == 422:
                return "The request payload was rejected by the API."
            return f"Server error ({resp.status_code})."
    return f"Unexpected error: {msg[:140]}"


def api_get(path: str, params: dict[str, Any] | None = None, timeout: int = 60) -> dict[str, Any]:
    resp = requests.get(f"{API_BASE}{path}", params=params, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def api_post(path: str, payload: dict[str, Any], timeout: int = 60) -> dict[str, Any]:
    resp = requests.post(f"{API_BASE}{path}", json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def api_delete(path: str, timeout: int = 60) -> dict[str, Any]:
    resp = requests.delete(f"{API_BASE}{path}", timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def init_state() -> None:
    defaults = {
        "account_email": DEFAULT_ACCOUNT,
        "minutes_since": 1440,
        "include_read": True,
        "max_results": 25,
        "safe_emails": [],
        "quarantine_emails": [],
        "delete_confirm_id": "",
        "scam_confirm_id": "",
        "release_confirm_id": "",
        "risk_eval_failures": 0,
        "eval_by_id": {},
        "scan_activity": [],
        "link_lab_result": None,
        "email_api_status": "unknown",
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default


def health_ping() -> None:
    try:
        api_get("/health", timeout=5)
        st.session_state.email_api_status = "online"
    except requests.RequestException:
        st.session_state.email_api_status = "offline"


def filter_emails(emails: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    if not query.strip():
        return emails
    q = query.strip().lower()
    return [
        email
        for email in emails
        if q in str(email.get("subject", "")).lower()
        or q in str(email.get("from_email", "")).lower()
        or q in str(email.get("body", "")).lower()
    ]


def filter_quarantine(records: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    if not query.strip():
        return records
    q = query.strip().lower()
    return [
        record
        for record in records
        if q in str(record.get("email", {}).get("subject", "")).lower()
        or q in str(record.get("email", {}).get("from_email", "")).lower()
        or q in " ".join(str(x) for x in record.get("risk_reasons", [])).lower()
    ]


def risk_dot(score: float) -> str:
    if score <= 0.3:
        return "●"
    if score <= 0.6:
        return "◐"
    return "▲"


def risk_tone(score: float) -> str:
    if score <= 0.3:
        return "safe"
    if score <= 0.6:
        return "elevated"
    return "threat"


def decision_color(decision: str) -> str:
    normalized = decision.strip().lower()
    if normalized in {"deliver", "safe"}:
        return "#9fcca4"
    if normalized in {"suspicious", "pending_human_review"}:
        return "#f2c47d"
    return "#f38b72"


def fmt_pct(score: float) -> str:
    return f"{score * 100:.0f}%"


def render_global_style() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;700&display=swap');

        :root {
            --bg: #0d1117;
            --panel: #121821;
            --panel-strong: #171f2b;
            --line: rgba(255, 255, 255, 0.08);
            --text: #eff4f7;
            --muted: #97a7b7;
            --safe: #9fcca4;
            --warn: #f2c47d;
            --threat: #f38b72;
            --accent: #79b6ff;
        }

        .stApp {
            background:
                radial-gradient(circle at top left, rgba(121, 182, 255, 0.16), transparent 28%),
                radial-gradient(circle at 85% 10%, rgba(243, 139, 114, 0.18), transparent 20%),
                linear-gradient(180deg, #081018 0%, #0d1117 46%, #0d1117 100%);
            color: var(--text);
        }

        .main .block-container {
            padding-top: 2rem;
            padding-bottom: 4rem;
            max-width: 1380px;
        }

        h1, h2, h3, h4 {
            font-family: "Space Grotesk", "IBM Plex Sans", sans-serif;
            letter-spacing: -0.03em;
            color: var(--text);
        }

        p, div, label, span, li {
            font-family: "IBM Plex Sans", sans-serif;
        }

        [data-testid="stMetric"] {
            background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
            border: 1px solid var(--line);
            border-radius: 22px;
            padding: 0.9rem 1rem;
        }

        [data-testid="stMetricLabel"] {
            color: var(--muted);
            font-size: 0.82rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }

        [data-testid="stMetricValue"] {
            font-family: "Space Grotesk", sans-serif;
            color: var(--text);
        }

        .stButton > button, .stDownloadButton > button, div[data-baseweb="tab-list"] button {
            border-radius: 999px;
        }

        .stButton > button {
            background: #f0f4f7;
            color: #091018;
            border: 0;
            font-weight: 600;
            padding: 0.68rem 1.1rem;
        }

        .stButton > button[kind="secondary"] {
            background: transparent;
            color: var(--text);
            border: 1px solid var(--line);
        }

        .stTextInput input, .stTextArea textarea, .stNumberInput input {
            background: rgba(255,255,255,0.04);
            border-radius: 16px;
            border: 1px solid var(--line);
            color: var(--text);
        }

        .stCheckbox label, .stRadio label {
            color: var(--muted);
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 0.75rem;
            background: transparent;
            padding-bottom: 1rem;
        }

        .stTabs [data-baseweb="tab"] {
            background: rgba(255,255,255,0.03);
            border: 1px solid var(--line);
            color: var(--muted);
            font-weight: 600;
            padding: 0.55rem 0.95rem;
        }

        .stTabs [aria-selected="true"] {
            background: rgba(255,255,255,0.92) !important;
            color: #071018 !important;
        }

        .stExpander {
            border: 1px solid var(--line);
            border-radius: 22px;
            background: rgba(255,255,255,0.02);
        }

        .stAlert {
            border-radius: 18px;
            border: 1px solid var(--line);
        }

        .hero-shell {
            min-height: calc(100svh - 5rem);
            border: 1px solid var(--line);
            border-radius: 34px;
            overflow: hidden;
            position: relative;
            background:
                radial-gradient(circle at 18% 20%, rgba(121, 182, 255, 0.22), transparent 26%),
                radial-gradient(circle at 85% 25%, rgba(243, 139, 114, 0.24), transparent 18%),
                linear-gradient(135deg, rgba(15,22,32,0.95), rgba(9,14,22,0.92));
            padding: 1.35rem;
            margin-bottom: 1.4rem;
        }

        .hero-grid {
            display: grid;
            grid-template-columns: minmax(0, 1.1fr) minmax(340px, 0.9fr);
            gap: 1.25rem;
            align-items: stretch;
        }

        .hero-copy {
            padding: 1.2rem 1rem 1rem 1.2rem;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 70svh;
        }

        .eyebrow {
            display: inline-flex;
            align-items: center;
            gap: 0.55rem;
            padding: 0.4rem 0.8rem;
            border: 1px solid var(--line);
            border-radius: 999px;
            color: var(--muted);
            font-size: 0.82rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            width: fit-content;
        }

        .hero-brand {
            font-size: clamp(2.8rem, 7vw, 6.7rem);
            line-height: 0.95;
            margin: 0.9rem 0 0.35rem 0;
            max-width: 9ch;
        }

        .hero-sub {
            max-width: 32rem;
            color: #d0d8df;
            font-size: 1.02rem;
            line-height: 1.7;
            margin-bottom: 1.5rem;
        }

        .hero-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 0.75rem;
            margin-bottom: 1.2rem;
        }

        .hero-chip {
            display: inline-flex;
            align-items: center;
            gap: 0.45rem;
            border: 1px solid var(--line);
            border-radius: 999px;
            padding: 0.5rem 0.82rem;
            color: #e4edf2;
            background: rgba(255,255,255,0.03);
        }

        .radar-panel {
            border: 1px solid var(--line);
            border-radius: 28px;
            min-height: 100%;
            padding: 1.1rem;
            background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.01));
            position: relative;
            overflow: hidden;
        }

        .radar-panel::before {
            content: "";
            position: absolute;
            inset: 6% 11%;
            border-radius: 999px;
            border: 1px solid rgba(121, 182, 255, 0.12);
            box-shadow:
                0 0 0 52px rgba(121, 182, 255, 0.04),
                0 0 0 104px rgba(121, 182, 255, 0.03),
                0 0 0 156px rgba(121, 182, 255, 0.02);
        }

        .radar-sweep {
            position: absolute;
            width: 72%;
            height: 72%;
            left: 14%;
            top: 14%;
            border-radius: 50%;
            background: conic-gradient(from 0deg, rgba(121,182,255,0.30), transparent 21%, transparent 100%);
            filter: blur(2px);
            animation: sweep 8s linear infinite;
        }

        .radar-core {
            position: relative;
            z-index: 1;
            min-height: 68svh;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }

        .signal-stack {
            display: grid;
            gap: 0.7rem;
            margin-top: auto;
        }

        .signal {
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            gap: 1rem;
            border-top: 1px solid rgba(255,255,255,0.08);
            padding-top: 0.65rem;
            color: #dbe5ec;
        }

        .signal small {
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .section-note {
            color: var(--muted);
            max-width: 46rem;
            margin-top: -0.45rem;
            margin-bottom: 1rem;
        }

        .band {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 0.8rem;
            margin: 0.5rem 0 1.35rem 0;
        }

        .band-cell {
            border-top: 1px solid var(--line);
            padding-top: 0.7rem;
        }

        .band-cell small {
            display: block;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 0.25rem;
        }

        .band-cell strong {
            font-size: 1.15rem;
            font-family: "Space Grotesk", sans-serif;
        }

        .record-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 0.55rem;
            margin: 0.25rem 0 0.85rem 0;
        }

        .record-pill {
            border: 1px solid var(--line);
            border-radius: 999px;
            padding: 0.35rem 0.7rem;
            color: var(--muted);
            font-size: 0.82rem;
        }

        .reason-list {
            margin: 0;
            padding-left: 1rem;
            color: #dce5ec;
        }

        @keyframes sweep {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        @media (max-width: 980px) {
            .hero-grid, .band {
                grid-template-columns: 1fr;
            }

            .hero-copy, .radar-core {
                min-height: auto;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_hero() -> None:
    email_state = st.session_state.email_api_status
    quarantine_count = len(st.session_state.quarantine_emails)
    safe_count = len(st.session_state.safe_emails)
    scans = st.session_state.scan_activity
    links_scanned = sum(int(item.get("links_scanned", 0) or 0) for item in scans)
    hero_html = f"""
    <section class="hero-shell">
      <div class="hero-grid">
        <div class="hero-copy">
          <div>
            <div class="eyebrow">Unified Security Console</div>
            <h1 class="hero-brand">anti-scam.ai</h1>
            <p class="hero-sub">
              One operator surface for inbox triage, link intelligence, human review,
              and scam investigation workflows.
            </p>
            <div class="hero-meta">
              <div class="hero-chip">Email API <strong>{html.escape(email_state)}</strong></div>
              <div class="hero-chip">Safe inbox <strong>{safe_count}</strong></div>
              <div class="hero-chip">Threat queue <strong>{quarantine_count}</strong></div>
            </div>
          </div>
          <div class="band">
            <div class="band-cell">
              <small>Scanned links</small>
              <strong>{links_scanned}</strong>
            </div>
            <div class="band-cell">
              <small>Manual review</small>
              <strong>{quarantine_count} pending</strong>
            </div>
            <div class="band-cell">
              <small>Operating mode</small>
              <strong>human in the loop</strong>
            </div>
          </div>
        </div>
        <div class="radar-panel">
          <div class="radar-sweep"></div>
          <div class="radar-core">
            <div>
              <div class="eyebrow">Threat Posture</div>
              <h3 style="margin: 0.8rem 0 0.35rem 0;">Email fraud detection</h3>
              <p style="color: var(--muted); max-width: 24rem;">
                Email scoring, SSL and browser checks, operator labeling, and manual
                investigation are presented in one control room.
              </p>
            </div>
            <div class="signal-stack">
              <div class="signal"><span>Inbox triage</span><small>{safe_count} messages cleared</small></div>
              <div class="signal"><span>Threat review</span><small>{quarantine_count} items held</small></div>
              <div class="signal"><span>Link verification</span><small>{links_scanned} URLs inspected</small></div>
            </div>
          </div>
        </div>
      </div>
    </section>
    """
    st.markdown(hero_html, unsafe_allow_html=True)


def load_quarantine() -> None:
    result = api_get("/risk/quarantine")
    st.session_state.quarantine_emails = result.get("emails", [])


def refresh_emails() -> None:
    result = api_get(
        "/gmail/emails",
        params={
            "email_address": st.session_state.account_email,
            "minutes_since": st.session_state.minutes_since,
            "include_read": st.session_state.include_read,
            "max_results": st.session_state.max_results,
        },
    )
    fetched_emails = result.get("emails", [])
    safe_emails: list[dict[str, Any]] = []
    risk_eval_failures = 0
    eval_by_id: dict[str, dict[str, Any]] = {}
    scan_activity: list[dict[str, Any]] = []
    total = len(fetched_emails)

    with st.status(f"Scanning {total} email(s)", expanded=True) as status:
        progress = st.progress(0, text="Preparing email risk analysis")
        for idx, email in enumerate(fetched_emails, start=1):
            subject = str(email.get("subject", "(no subject)"))
            message_id = str(email.get("id", ""))
            pct = idx / total if total else 1.0
            progress.progress(pct, text=f"Analyzing {idx}/{max(total, 1)} · {subject[:64]}")
            try:
                evaluation = api_post("/risk/emails/evaluate", {"email": email})
                eval_by_id[message_id] = evaluation
                decision = str(evaluation.get("decision", "unknown"))
                link_results = evaluation.get("link_results", []) or []
                scan_activity.append(
                    {
                        "id": message_id,
                        "subject": subject,
                        "decision": decision,
                        "risk_score": float(evaluation.get("risk_score", 0.0) or 0.0),
                        "links_found": int(evaluation.get("links_found", 0) or 0),
                        "links_scanned": int(evaluation.get("links_scanned", 0) or 0),
                        "link_scan_failed_closed": bool(evaluation.get("link_scan_failed_closed", False)),
                        "scanned_urls": [
                            str(link.get("final_url") or link.get("normalized_url") or link.get("original_url") or "")
                            for link in link_results
                            if str(link.get("final_url") or link.get("normalized_url") or link.get("original_url") or "")
                        ],
                        "preview_urls": [
                            str(link.get("yutori_preview_url") or "")
                            for link in link_results
                            if str(link.get("yutori_preview_url") or "")
                        ],
                        "yutori_executed_count": sum(
                            1 for link in link_results if bool(link.get("yutori_executed", False))
                        ),
                    }
                )
                if decision == "deliver":
                    safe_emails.append(email)
                st.write(f"{'CLEAR' if decision == 'deliver' else 'HOLD'} · {subject[:84]}")
            except requests.RequestException:
                risk_eval_failures += 1
                scan_activity.append(
                    {
                        "id": message_id,
                        "subject": subject,
                        "decision": "error",
                        "risk_score": 1.0,
                        "links_found": 0,
                        "links_scanned": 0,
                        "link_scan_failed_closed": True,
                        "scanned_urls": [],
                        "preview_urls": [],
                        "yutori_executed_count": 0,
                    }
                )
                st.write(f"ERROR · {subject[:84]}")

        progress.progress(1.0, text="Scan complete")
        status.update(label="Scan complete", state="complete", expanded=False)

    st.session_state.safe_emails = safe_emails
    st.session_state.eval_by_id = eval_by_id
    st.session_state.scan_activity = scan_activity
    st.session_state.risk_eval_failures = risk_eval_failures
    load_quarantine()


def render_record_meta(items: list[str]) -> None:
    pills = "".join(f'<span class="record-pill">{html.escape(item)}</span>' for item in items if item)
    st.markdown(f'<div class="record-meta">{pills}</div>', unsafe_allow_html=True)


def render_summary_band() -> None:
    activity = st.session_state.scan_activity
    safe_count = len(st.session_state.safe_emails)
    quarantine_count = len(st.session_state.quarantine_emails)
    risk_failures = int(st.session_state.risk_eval_failures)
    links_found = sum(int(item.get("links_found", 0) or 0) for item in activity)
    links_scanned = sum(int(item.get("links_scanned", 0) or 0) for item in activity)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Safe inbox", safe_count)
    c2.metric("Threat queue", quarantine_count)
    c3.metric("Links scanned", f"{links_scanned}/{links_found}")
    c4.metric("Risk failures", risk_failures)


def render_link_results(link_results: list[dict[str, Any]], key_prefix: str) -> None:
    if not link_results:
        st.caption("No link intelligence available for this item.")
        return

    for idx, link in enumerate(link_results, start=1):
        original = str(link.get("final_url") or link.get("normalized_url") or link.get("original_url") or "")
        verdict = str(link.get("yutori_verdict", "unknown"))
        ssl_state = str(link.get("ssl_state", "unknown"))
        scan_status = str(link.get("scan_status", "error"))
        risk_flags = link.get("risk_flags", []) or []
        task_id = str(link.get("yutori_task_id") or "")
        preview_url = str(link.get("yutori_preview_url") or "")
        title = f"Link {idx} · {original or '(missing url)'}"

        with st.expander(title, expanded=False):
            render_record_meta(
                [
                    f"verdict {verdict}",
                    f"ssl {ssl_state}",
                    f"scan {scan_status}",
                    f"reachable {link.get('reachable', False)}",
                ]
            )
            if risk_flags:
                st.markdown("**Risk flags**")
                st.markdown(
                    "<ul class='reason-list'>"
                    + "".join(f"<li>{html.escape(str(flag))}</li>" for flag in risk_flags)
                    + "</ul>",
                    unsafe_allow_html=True,
                )
            if task_id:
                st.caption(f"Yutori task: {task_id}")
            if preview_url:
                st.link_button("Open browser preview", preview_url, key=f"{key_prefix}_preview_{idx}")
            st.code(original or "(no url)")


def render_email_body(body: str, key: str) -> None:
    view = st.radio("Body view", ["Text", "Raw"], horizontal=True, key=f"{key}_body_view")
    if view == "Raw":
        st.code(body or "", language="html")
    else:
        st.write(body or "No body content.")


def render_inbox_tab() -> None:
    st.subheader("Email Triage")
    st.caption("Scan recent Gmail traffic, hold high-risk messages, and keep only cleared mail in the operator inbox.")

    top_left, top_right = st.columns([1.3, 1], gap="large")
    with top_left:
        st.markdown("### Scan Controls")
        st.session_state.account_email = st.text_input(
            "Gmail account",
            value=st.session_state.account_email,
            placeholder="your_email@gmail.com",
        )
        a, b, c = st.columns(3)
        st.session_state.minutes_since = a.number_input(
            "Window (min)",
            min_value=1,
            max_value=10080,
            value=st.session_state.minutes_since,
        )
        st.session_state.max_results = b.number_input(
            "Max results",
            min_value=1,
            max_value=100,
            value=st.session_state.max_results,
        )
        st.session_state.include_read = c.checkbox("Include read", value=st.session_state.include_read)
        scan_col, refresh_col = st.columns([1.1, 1])
        if scan_col.button("Scan inbox", use_container_width=True):
            if not st.session_state.account_email:
                st.error("Enter a Gmail account before scanning.")
            else:
                try:
                    refresh_emails()
                    st.toast("Inbox scan complete", icon="🛰️")
                except requests.RequestException as exc:
                    st.error(friendly_error(exc))
        if refresh_col.button("Refresh threat queue", use_container_width=True):
            try:
                load_quarantine()
                st.toast("Threat queue refreshed", icon="↺")
            except requests.RequestException as exc:
                st.error(friendly_error(exc))

    with top_right:
        st.markdown("### Send Test Email")
        with st.form("compose_form"):
            to = st.text_input("To", value=DEFAULT_TO, placeholder="recipient@example.com")
            subject = st.text_input("Subject", value="", placeholder="Subject")
            body = st.text_area("Body", value="", height=160, placeholder="Write a message")
            send_clicked = st.form_submit_button("Send email", use_container_width=True)
        if send_clicked:
            if not to:
                st.error("Recipient is required.")
            else:
                try:
                    result = api_post("/gmail/send", {"to": to, "subject": subject, "body": body})
                    st.success(f"Sent message {result.get('message_id')}")
                except requests.RequestException as exc:
                    st.error(friendly_error(exc))

    render_summary_band()
    if st.session_state.risk_eval_failures:
        st.warning(
            f"{st.session_state.risk_eval_failures} message(s) were hidden because evaluation failed and the system failed closed."
        )

    safe_emails = st.session_state.safe_emails
    if not safe_emails:
        st.info("No cleared inbox messages loaded yet. Run a scan to populate the workspace.")
        return

    query = st.text_input("Filter cleared inbox", placeholder="Search by sender, subject, or body")
    emails = filter_emails(safe_emails, query)
    st.caption(f"Showing {len(emails)} of {len(safe_emails)} cleared message(s)")

    for email in emails:
        message_id = str(email.get("id", ""))
        subject = str(email.get("subject", "(no subject)"))
        sender = str(email.get("from_email", ""))
        evaluation = st.session_state.eval_by_id.get(message_id, {})
        score = float(evaluation.get("risk_score", 0.0) or 0.0)
        decision = str(evaluation.get("decision", "deliver"))
        title = f"{risk_dot(score)} {subject} · {sender}"
        with st.expander(title, expanded=False):
            render_record_meta(
                [
                    f"score {fmt_pct(score)}",
                    f"decision {decision}",
                    f"sent {email.get('send_time', '')}",
                    f"links {evaluation.get('links_scanned', 0)}/{evaluation.get('links_found', 0)}",
                ]
            )
            if evaluation.get("risk_reasons"):
                st.markdown("**Risk rationale**")
                st.markdown(
                    "<ul class='reason-list'>"
                    + "".join(
                        f"<li>{html.escape(str(reason))}</li>" for reason in evaluation.get("risk_reasons", [])
                    )
                    + "</ul>",
                    unsafe_allow_html=True,
                )
            render_link_results(evaluation.get("link_results", []), key_prefix=f"inbox_{message_id}")
            render_email_body(str(email.get("body", "")), key=f"inbox_{message_id}")

            action_col, confirm_col = st.columns([1, 2])
            if action_col.button("Delete email", key=f"delete_{message_id}", use_container_width=True):
                st.session_state.delete_confirm_id = message_id
            if st.session_state.delete_confirm_id == message_id:
                confirm_col.warning("Delete this message from Gmail?")
                yes, no = st.columns(2)
                if yes.button("Confirm delete", key=f"confirm_delete_{message_id}", type="primary"):
                    try:
                        api_delete(f"/gmail/emails/{message_id}")
                        st.session_state.delete_confirm_id = ""
                        refresh_emails()
                        st.rerun()
                    except requests.RequestException as exc:
                        st.error(friendly_error(exc))
                if no.button("Cancel", key=f"cancel_delete_{message_id}"):
                    st.session_state.delete_confirm_id = ""
                    st.rerun()


def render_quarantine_tab() -> None:
    st.subheader("Threat Review")
    st.caption("Review quarantined mail, label confirmed scams, and release legitimate messages back to the inbox.")

    records = st.session_state.quarantine_emails
    if not records:
        st.info("Threat queue is empty.")
        return

    review_l, review_m, review_r = st.columns(3)
    review_l.metric("Held", len(records))
    review_m.metric("Labeled", sum(1 for r in records if r.get("label") is not None))
    review_r.metric("Confirmed scam", sum(1 for r in records if r.get("label") == 1))

    query = st.text_input("Filter threat queue", placeholder="Search by sender, subject, or risk reason")
    filtered = filter_quarantine(records, query)
    st.caption(f"Showing {len(filtered)} of {len(records)} quarantined message(s)")

    for record in filtered:
        email = record.get("email", {})
        message_id = str(record.get("id", ""))
        subject = str(email.get("subject", "(no subject)"))
        sender = str(email.get("from_email", ""))
        score = float(record.get("risk_score", 0.0) or 0.0)
        status = str(record.get("status", "pending_human_review"))
        label = record.get("label")
        label_text = "unlabeled" if label is None else ("scam" if label == 1 else "not scam")
        title = f"{risk_dot(score)} {subject} · {sender} · {status}"

        with st.expander(title, expanded=False):
            render_record_meta(
                [
                    f"risk {fmt_pct(score)}",
                    f"status {status}",
                    f"label {label_text}",
                    f"model {record.get('model_version', '')}",
                ]
            )
            description = str(record.get("description", "") or "")
            if description:
                st.write(description)
            reasons = record.get("risk_reasons", []) or []
            if reasons:
                st.markdown("**Risk reasons**")
                st.markdown(
                    "<ul class='reason-list'>"
                    + "".join(f"<li>{html.escape(str(reason))}</li>" for reason in reasons)
                    + "</ul>",
                    unsafe_allow_html=True,
                )

            if record.get("link_scan_failed_closed"):
                st.warning("This item was quarantined because link scanning failed closed.")

            render_link_results(record.get("link_results", []), key_prefix=f"quarantine_{message_id}")
            render_email_body(str(email.get("body", "")), key=f"quarantine_{message_id}")

            scam_col, legit_col, release_col = st.columns(3)
            if scam_col.button("Label scam", key=f"label_scam_{message_id}", use_container_width=True):
                st.session_state.scam_confirm_id = message_id
            if legit_col.button("Not scam + release", key=f"label_legit_{message_id}", use_container_width=True):
                try:
                    api_post(f"/risk/quarantine/{message_id}/label", {"label": 0})
                    api_post(f"/risk/quarantine/{message_id}/release", {})
                    load_quarantine()
                    st.rerun()
                except requests.RequestException as exc:
                    st.error(friendly_error(exc))
            if release_col.button("Release only", key=f"release_{message_id}", use_container_width=True):
                st.session_state.release_confirm_id = message_id

            if st.session_state.scam_confirm_id == message_id:
                st.warning("Label this message as scam? This writes training feedback.")
                yes, no = st.columns(2)
                if yes.button("Confirm scam label", key=f"confirm_scam_{message_id}", type="primary"):
                    try:
                        api_post(f"/risk/quarantine/{message_id}/label", {"label": 1})
                        st.session_state.scam_confirm_id = ""
                        load_quarantine()
                        st.rerun()
                    except requests.RequestException as exc:
                        st.error(friendly_error(exc))
                if no.button("Cancel", key=f"cancel_scam_{message_id}"):
                    st.session_state.scam_confirm_id = ""
                    st.rerun()

            if st.session_state.release_confirm_id == message_id:
                st.warning("Release this message without adding a label?")
                yes, no = st.columns(2)
                if yes.button("Confirm release", key=f"confirm_release_{message_id}", type="primary"):
                    try:
                        api_post(f"/risk/quarantine/{message_id}/release", {})
                        st.session_state.release_confirm_id = ""
                        load_quarantine()
                        st.rerun()
                    except requests.RequestException as exc:
                        st.error(friendly_error(exc))
                if no.button("Cancel", key=f"cancel_release_{message_id}"):
                    st.session_state.release_confirm_id = ""
                    st.rerun()


def render_scan_activity_tab() -> None:
    st.subheader("Link and Scan Activity")
    st.caption("Audit scan outcomes and run manual URL checks without waiting for an inbox fetch.")

    activity = st.session_state.scan_activity
    if activity:
        rows = [
            {
                "Subject": item.get("subject", "(no subject)"),
                "Decision": item.get("decision", "unknown"),
                "Risk": f"{float(item.get('risk_score', 0.0) or 0.0):.2f}",
                "Links": f"{item.get('links_scanned', 0)}/{item.get('links_found', 0)}",
                "Browser scans": item.get("yutori_executed_count", 0),
                "Fail closed": "yes" if item.get("link_scan_failed_closed") else "",
            }
            for item in activity
        ]
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("Run an inbox scan to populate activity.")

    st.markdown("### Manual Link Lab")
    with st.form("link_lab"):
        sender_email = st.text_input("Sender email", placeholder="alerts@bank-example.com")
        subject = st.text_input("Subject", placeholder="Urgent password reset")
        body = st.text_area("Body context", height=140, placeholder="Paste the suspicious message body")
        urls = st.text_area("URLs", height=120, placeholder="One URL per line")
        run_link_scan = st.form_submit_button("Run link analysis", use_container_width=True)
    if run_link_scan:
        try:
            result = api_post(
                "/risk/links/evaluate",
                {
                    "sender_email": sender_email,
                    "subject": subject,
                    "body": body,
                    "urls": [line.strip() for line in urls.splitlines() if line.strip()] or None,
                },
            )
            st.session_state.link_lab_result = result
        except requests.RequestException as exc:
            st.error(friendly_error(exc))

    result = st.session_state.link_lab_result
    if result:
        summary = result.get("email_risk_summary", {})
        score = float(summary.get("risk_score", 0.0) or 0.0)
        decision = str(summary.get("decision", "deliver"))
        st.markdown(
            f"""
            <div class="band">
              <div class="band-cell"><small>Decision</small><strong style="color:{decision_color(decision)};">{html.escape(decision)}</strong></div>
              <div class="band-cell"><small>Risk score</small><strong>{fmt_pct(score)}</strong></div>
              <div class="band-cell"><small>URLs found</small><strong>{summary.get('links_found', 0)}</strong></div>
              <div class="band-cell"><small>URLs scanned</small><strong>{summary.get('links_scanned', 0)}</strong></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        reasons = summary.get("risk_reasons", []) or []
        if reasons:
            st.markdown("**Summary reasons**")
            st.markdown(
                "<ul class='reason-list'>"
                + "".join(f"<li>{html.escape(str(reason))}</li>" for reason in reasons)
                + "</ul>",
                unsafe_allow_html=True,
            )
        render_link_results(result.get("link_results", []), key_prefix="link_lab")


st.set_page_config(page_title="anti-scam.ai", page_icon="🛡️", layout="wide")
init_state()
health_ping()
render_global_style()

if not st.session_state.quarantine_emails and st.session_state.email_api_status == "online":
    try:
        load_quarantine()
    except requests.RequestException:
        pass

render_hero()

st.markdown("## Operations")
st.markdown(
    "<p class='section-note'>Operator-first surface for triage, review, and investigation. The workflows below use the existing FastAPI email service without changing its contract.</p>",
    unsafe_allow_html=True,
)

email_tab, quarantine_tab, scans_tab = st.tabs(["Email Triage", "Threat Review", "Link Lab"])

with email_tab:
    render_inbox_tab()

with quarantine_tab:
    render_quarantine_tab()

with scans_tab:
    render_scan_activity_tab()
