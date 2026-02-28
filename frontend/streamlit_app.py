import os
from pathlib import Path
from typing import Any

import requests
import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

API_BASE = os.getenv("EMAIL_ASSISTANT_API", "http://127.0.0.1:8000")
DEFAULT_ACCOUNT = os.getenv("GMAIL_ACCOUNT", "")
DEFAULT_TO = os.getenv("EMAIL_DEFAULT_TO", "")


def api_get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    resp = requests.get(f"{API_BASE}{path}", params=params, timeout=60)
    resp.raise_for_status()
    return resp.json()


def api_post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    resp = requests.post(f"{API_BASE}{path}", json=payload, timeout=60)
    resp.raise_for_status()
    return resp.json()


def api_delete(path: str) -> dict[str, Any]:
    resp = requests.delete(f"{API_BASE}{path}", timeout=60)
    resp.raise_for_status()
    return resp.json()


def inject_ui_theme() -> None:
    st.markdown(
        """
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Manrope:wght@500;700;800&family=Space+Grotesk:wght@500;700&display=swap');

            :root {
                --bg: #f6fbff;
                --bg-grad-1: #fff3df;
                --bg-grad-2: #e8f8ff;
                --ink: #0f1e33;
                --muted: #5e6e85;
                --card: #ffffff;
                --card-border: #d8e6f7;
                --accent: #ff7b39;
                --accent-2: #1d87ff;
                --success: #0d9f6e;
                --warning: #d97706;
                --danger: #c81e1e;
            }

            .stApp {
                background:
                    radial-gradient(circle at 12% 10%, var(--bg-grad-1) 0%, transparent 30%),
                    radial-gradient(circle at 88% 18%, var(--bg-grad-2) 0%, transparent 34%),
                    var(--bg);
                color: var(--ink);
            }

            .block-container {
                padding-top: 1.8rem;
                padding-bottom: 3rem;
            }

            h1, h2, h3 {
                font-family: "Space Grotesk", sans-serif !important;
                letter-spacing: -0.02em;
                color: var(--ink);
            }

            p, div, span, label {
                font-family: "Manrope", sans-serif !important;
            }

            .hero-shell {
                background: linear-gradient(114deg, #ffffff 0%, #f7fbff 48%, #eef8ff 100%);
                border: 1px solid var(--card-border);
                border-radius: 18px;
                padding: 1.25rem 1.4rem;
                margin-bottom: 1rem;
                box-shadow: 0 8px 28px rgba(16, 70, 120, 0.08);
            }

            .hero-kicker {
                text-transform: uppercase;
                letter-spacing: 0.12em;
                font-size: 0.72rem;
                color: var(--accent-2);
                font-weight: 800;
                margin-bottom: 0.3rem;
            }

            .hero-title {
                margin: 0;
                font-size: 1.9rem;
                line-height: 1.16;
            }

            .hero-sub {
                margin: 0.35rem 0 0;
                color: var(--muted);
                font-size: 0.98rem;
            }

            .metric-card {
                background: var(--card);
                border: 1px solid var(--card-border);
                border-radius: 16px;
                padding: 0.9rem 1rem;
                box-shadow: 0 5px 18px rgba(26, 71, 132, 0.08);
                min-height: 118px;
            }

            .metric-label {
                font-size: 0.78rem;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                color: var(--muted);
                font-weight: 800;
                margin-bottom: 0.35rem;
            }

            .metric-value {
                font-family: "Space Grotesk", sans-serif !important;
                font-size: 1.85rem;
                line-height: 1;
                color: var(--ink);
                font-weight: 800;
                margin-bottom: 0.4rem;
            }

            .metric-note {
                font-size: 0.9rem;
                color: var(--muted);
            }

            .soft-panel {
                background: rgba(255, 255, 255, 0.74);
                border: 1px solid var(--card-border);
                border-radius: 16px;
                padding: 0.3rem 0.9rem 0.9rem;
            }

            [data-testid="stTextInput"] input,
            [data-testid="stNumberInput"] input,
            [data-testid="stTextArea"] textarea {
                background: linear-gradient(180deg, #ffffff 0%, #fff9ee 100%) !important;
                border: 1.5px solid #ffd49a !important;
                border-radius: 12px !important;
                color: var(--ink) !important;
                box-shadow: 0 2px 10px rgba(255, 170, 66, 0.12) !important;
            }

            [data-testid="stTextInput"] input::placeholder,
            [data-testid="stTextArea"] textarea::placeholder {
                color: #8b97a9 !important;
            }

            [data-testid="stTextInput"] input:focus,
            [data-testid="stNumberInput"] input:focus,
            [data-testid="stTextArea"] textarea:focus {
                border: 1.5px solid #ff8e42 !important;
                box-shadow: 0 0 0 0.22rem rgba(255, 142, 66, 0.2) !important;
            }

            .chip {
                display: inline-block;
                border-radius: 999px;
                font-size: 0.75rem;
                font-weight: 700;
                padding: 0.2rem 0.58rem;
                margin-right: 0.32rem;
                margin-bottom: 0.28rem;
                border: 1px solid transparent;
            }

            .chip-good {
                color: #086045;
                background: #e5fff5;
                border-color: #8bf0c9;
            }

            .chip-mid {
                color: #8a4b05;
                background: #fff6df;
                border-color: #ffd08d;
            }

            .chip-bad {
                color: #8f1212;
                background: #ffecec;
                border-color: #ffadad;
            }

            .chip-neutral {
                color: #243349;
                background: #edf3fb;
                border-color: #d2dff0;
            }

            [data-testid="stDataFrame"] {
                border: 1px solid var(--card-border);
                border-radius: 14px;
                overflow: hidden;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def tone_for_decision(decision: str) -> str:
    normalized = decision.strip().lower()
    if normalized in {"deliver", "safe", "allow"}:
        return "good"
    if normalized in {"error", "unknown"}:
        return "mid"
    return "bad"


def tone_for_ssl(is_valid: bool) -> str:
    return "good" if is_valid else "bad"


def tone_for_scan_status(status: str) -> str:
    normalized = status.strip().lower()
    if normalized in {"done", "success", "ok"}:
        return "good"
    if normalized in {"pending", "queued", "running"}:
        return "mid"
    return "bad"


def render_chip(label: str, tone: str) -> None:
    st.markdown(f"<span class='chip chip-{tone}'>{label}</span>", unsafe_allow_html=True)


def render_metric_card(label: str, value: int, note: str) -> None:
    st.markdown(
        (
            "<div class='metric-card'>"
            f"<div class='metric-label'>{label}</div>"
            f"<div class='metric-value'>{value}</div>"
            f"<div class='metric-note'>{note}</div>"
            "</div>"
        ),
        unsafe_allow_html=True,
    )


def render_yutori_link_results(link_results: list[dict[str, Any]], key_prefix: str) -> None:
    if not link_results:
        st.caption("No link-level details for this email.")
        return

    st.markdown("#### Link Intelligence")
    for idx, link in enumerate(link_results, start=1):
        url = str(link.get("final_url") or link.get("normalized_url") or link.get("original_url") or "")
        verdict = str(link.get("yutori_verdict", "unknown"))
        scan_status = str(link.get("scan_status", "error"))
        ssl_valid = bool(link.get("ssl_valid"))
        provider = str(link.get("yutori_provider", "yutori_api"))
        executed = bool(link.get("yutori_executed", False))
        task_id = str(link.get("yutori_task_id", "") or "")
        preview_url = str(link.get("yutori_preview_url", "") or "")
        summary = str(link.get("yutori_summary", "") or "")

        with st.expander(f"Link {idx}: {url or '(missing URL)'}", expanded=False):
            line_l, line_r = st.columns([5, 2])
            with line_l:
                st.write(f"Provider: `{provider}`")
                st.write(f"Executed: `{executed}`")
                if task_id:
                    st.write(f"Task ID: `{task_id}`")
                if summary:
                    st.caption(summary)
            with line_r:
                render_chip(f"verdict: {verdict}", tone_for_decision(verdict))
                render_chip(f"scan: {scan_status}", tone_for_scan_status(scan_status))
                render_chip(f"ssl: {'valid' if ssl_valid else 'invalid'}", tone_for_ssl(ssl_valid))

            if preview_url and executed:
                st.link_button("Open Yutori Preview", preview_url, key=f"{key_prefix}_preview_{idx}")
                with st.expander(f"Embedded Yutori Preview {idx}", expanded=False):
                    components.iframe(preview_url, height=520, scrolling=True)
            elif not executed:
                st.caption("Yutori was not executed for this link.")

            details = link.get("yutori_details")
            if details:
                with st.expander("Raw Yutori Execution", expanded=False):
                    st.json(details)


def init_state() -> None:
    if "account_email" not in st.session_state:
        st.session_state.account_email = DEFAULT_ACCOUNT
    if "minutes_since" not in st.session_state:
        st.session_state.minutes_since = 1440
    if "include_read" not in st.session_state:
        st.session_state.include_read = True
    if "max_results" not in st.session_state:
        st.session_state.max_results = 25
    if "safe_emails" not in st.session_state:
        st.session_state.safe_emails = []
    if "quarantine_emails" not in st.session_state:
        st.session_state.quarantine_emails = []
    if "delete_confirm_id" not in st.session_state:
        st.session_state.delete_confirm_id = ""
    if "risk_eval_failures" not in st.session_state:
        st.session_state.risk_eval_failures = 0
    if "eval_by_id" not in st.session_state:
        st.session_state.eval_by_id = {}
    if "scan_activity" not in st.session_state:
        st.session_state.scan_activity = []


def refresh_emails() -> None:
    try:
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
        progress = st.empty()
        total = len(fetched_emails)

        for idx, email in enumerate(fetched_emails, start=1):
            progress.info(f"Analyzing incoming email {idx}/{total}")
            msg_id = str(email.get("id", ""))
            subject = str(email.get("subject", "(no subject)"))
            try:
                evaluation = api_post("/risk/emails/evaluate", {"email": email})
                eval_by_id[msg_id] = evaluation
                link_results = evaluation.get("link_results", []) or []
                scanned_urls = [
                    str(link.get("final_url") or link.get("normalized_url") or link.get("original_url") or "")
                    for link in link_results
                ]
                preview_urls = [str(link.get("yutori_preview_url") or "") for link in link_results]
                scan_activity.append(
                    {
                        "id": msg_id,
                        "subject": subject,
                        "decision": evaluation.get("decision", "unknown"),
                        "risk_score": float(evaluation.get("risk_score", 0.0) or 0.0),
                        "links_found": int(evaluation.get("links_found", 0) or 0),
                        "links_scanned": int(evaluation.get("links_scanned", 0) or 0),
                        "link_scan_failed_closed": bool(evaluation.get("link_scan_failed_closed", False)),
                        "scanned_urls": [url for url in scanned_urls if url],
                        "preview_urls": [url for url in preview_urls if url],
                        "yutori_executed_count": sum(
                            1 for link in link_results if bool(link.get("yutori_executed", False))
                        ),
                    }
                )
                if evaluation.get("decision") == "deliver":
                    safe_emails.append(email)
            except requests.RequestException:
                # Fail closed: keep email out of inbox when risk verdict is unavailable.
                risk_eval_failures += 1
                scan_activity.append(
                    {
                        "id": msg_id,
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
        progress.empty()

        st.session_state.safe_emails = safe_emails
        st.session_state.risk_eval_failures = risk_eval_failures
        st.session_state.eval_by_id = eval_by_id
        st.session_state.scan_activity = scan_activity

        quarantine_result = api_get("/risk/quarantine")
        st.session_state.quarantine_emails = quarantine_result.get("emails", [])
    except requests.RequestException as exc:
        st.error(f"Failed to fetch emails: {exc}")


def render_summary_row() -> None:
    total_safe = len(st.session_state.safe_emails)
    total_quarantine = len(st.session_state.quarantine_emails)
    risk_failures = int(st.session_state.risk_eval_failures)
    activity = st.session_state.scan_activity
    links_found = sum(int(item.get("links_found", 0) or 0) for item in activity)
    links_scanned = sum(int(item.get("links_scanned", 0) or 0) for item in activity)
    yutori_executed = sum(int(item.get("yutori_executed_count", 0) or 0) for item in activity)

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        render_metric_card("Safe Inbox", total_safe, "deliverable emails")
    with m2:
        render_metric_card("Quarantine", total_quarantine, "held for review")
    with m3:
        render_metric_card("Links Scanned", links_scanned, f"out of {links_found} found")
    with m4:
        if risk_failures > 0:
            render_metric_card("Risk Failures", risk_failures, "fail-closed protections active")
        else:
            render_metric_card("Yutori Executed", yutori_executed, "browser scans performed")


def render_scan_activity_tab() -> None:
    st.subheader("Scan Activity")
    activity = st.session_state.scan_activity
    if not activity:
        st.info("No scan activity available yet. Refresh inbox to populate results.")
        return

    grid_rows = []
    for item in activity:
        grid_rows.append(
            {
                "Subject": item.get("subject", "(no subject)"),
                "Decision": item.get("decision", "unknown"),
                "Risk": f"{float(item.get('risk_score', 0.0) or 0.0):.2f}",
                "Links": f"{item.get('links_scanned', 0)}/{item.get('links_found', 0)}",
                "Fail Closed": "yes" if item.get("link_scan_failed_closed") else "no",
                "Yutori Tasks": item.get("yutori_executed_count", 0),
            }
        )
    st.dataframe(grid_rows, use_container_width=True, hide_index=True)

    with st.expander("Detailed Activity", expanded=False):
        for item in activity:
            st.markdown("---")
            st.write(
                f"**{item.get('subject', '(no subject)')}** | decision={item.get('decision', 'unknown')} | "
                f"links={item.get('links_scanned', 0)}/{item.get('links_found', 0)} | "
                f"yutori={item.get('yutori_executed_count', 0)}"
            )
            for idx, url in enumerate(item.get("scanned_urls", []), start=1):
                st.caption(f"Scanned URL {idx}: {url}")
            for idx, url in enumerate(item.get("preview_urls", []), start=1):
                st.link_button(
                    f"Open Yutori Preview ({idx})",
                    url,
                    key=f"activity_preview_{item.get('id', 'unknown')}_{idx}",
                )


st.set_page_config(page_title="Aegis Mail Console", page_icon="📬", layout="wide")
inject_ui_theme()
init_state()

st.markdown(
    f"""
    <section class="hero-shell">
        <div class="hero-kicker">Secure Mail Workspace</div>
        <h1 class="hero-title">Aegis Mail Console</h1>
        <p class="hero-sub">Bright operational dashboard for sending, triaging, and validating emails with AI risk controls and human-in-the-loop feedback.</p>
        <p class="hero-sub"><strong>API:</strong> {API_BASE}</p>
    </section>
    """,
    unsafe_allow_html=True,
)

col_left, col_right = st.columns([1.2, 1])

with col_left:
    st.markdown("<div class='soft-panel'>", unsafe_allow_html=True)
    st.subheader("Compose Email")
    with st.form("compose_form"):
        to = st.text_input("To", value=DEFAULT_TO, placeholder="recipient@example.com")
        subject = st.text_input("Subject", value="hello")
        body = st.text_area("Message", value="hello", height=140)
        send_clicked = st.form_submit_button("Send Email", use_container_width=True)

    if send_clicked:
        try:
            result = api_post("/gmail/send", {"to": to, "subject": subject, "body": body})
            st.success(f"Sent. Message ID: {result.get('message_id')}")
        except requests.RequestException as exc:
            st.error(f"Send failed: {exc}")
    st.markdown("</div>", unsafe_allow_html=True)

with col_right:
    st.markdown("<div class='soft-panel'>", unsafe_allow_html=True)
    st.subheader("Inbox Controls")
    st.session_state.account_email = st.text_input(
        "Gmail Account",
        value=st.session_state.account_email,
        placeholder="your_email@gmail.com",
    )
    st.session_state.minutes_since = st.number_input(
        "Minutes Since",
        min_value=1,
        max_value=10080,
        value=st.session_state.minutes_since,
    )
    st.session_state.include_read = st.checkbox("Include Read Emails", value=st.session_state.include_read)
    st.session_state.max_results = st.number_input(
        "Max Results",
        min_value=1,
        max_value=100,
        value=st.session_state.max_results,
    )

    if st.button("Refresh Inbox + Risk Scan", use_container_width=True, type="primary"):
        if not st.session_state.account_email:
            st.error("Enter Gmail account first.")
        else:
            refresh_emails()
    st.markdown("</div>", unsafe_allow_html=True)

st.markdown("")
render_summary_row()
st.divider()

inbox_tab, quarantine_tab, scans_tab = st.tabs(["Inbox", "Quarantine", "Scan Activity"])

with inbox_tab:
    st.subheader("Safe Inbox")
    emails = st.session_state.safe_emails
    if st.session_state.risk_eval_failures:
        st.warning(
            f"{st.session_state.risk_eval_failures} email(s) were hidden because risk evaluation failed."
        )
    if not emails:
        st.info("No safe emails loaded. Use Refresh Inbox + Risk Scan.")
    else:
        st.caption(f"Loaded {len(emails)} safe email(s).")
        for email in emails:
            msg_id = str(email.get("id", ""))
            evaluation = st.session_state.eval_by_id.get(msg_id, {})
            decision = str(evaluation.get("decision", "unknown"))
            risk_score = float(evaluation.get("risk_score", 0.0) or 0.0)
            title = (
                f"{email.get('subject', '(no subject)')} | {email.get('from_email', '')} | "
                f"decision={decision} | risk={risk_score:.2f}"
            )

            with st.expander(title, expanded=False):
                metadata_l, metadata_r = st.columns([2, 2])
                with metadata_l:
                    st.write(f"From: {email.get('from_email', '')}")
                    st.write(f"To: {email.get('to_email', '')}")
                    st.write(f"Date: {email.get('send_time', '')}")
                with metadata_r:
                    render_chip(f"decision: {decision}", tone_for_decision(decision))
                    render_chip(f"risk: {risk_score:.2f}", tone_for_decision(decision))
                    render_chip(
                        f"links: {evaluation.get('links_scanned', 0)}/{evaluation.get('links_found', 0)}",
                        "neutral",
                    )

                if evaluation:
                    render_yutori_link_results(
                        link_results=evaluation.get("link_results", []),
                        key_prefix=f"inbox_{msg_id}",
                    )
                    with st.expander("Raw Risk Evaluation", expanded=False):
                        st.json(evaluation)

                st.markdown("#### Email Body")
                st.code(email.get("body", ""))
                c1, c2 = st.columns([1, 2])
                if c1.button("Delete", key=f"delete_{msg_id}"):
                    st.session_state.delete_confirm_id = msg_id

                if st.session_state.delete_confirm_id == msg_id:
                    c2.warning("HITL confirm: delete this email?")
                    c3, c4 = st.columns([1, 1])
                    if c3.button("Confirm Delete", key=f"confirm_{msg_id}"):
                        try:
                            api_delete(f"/gmail/emails/{msg_id}")
                            st.success("Email moved to trash.")
                            st.session_state.delete_confirm_id = ""
                            refresh_emails()
                            st.rerun()
                        except requests.RequestException as exc:
                            st.error(f"Delete failed: {exc}")
                    if c4.button("Cancel", key=f"cancel_{msg_id}"):
                        st.session_state.delete_confirm_id = ""
                        st.rerun()

with quarantine_tab:
    st.subheader("Quarantine Review")
    quarantine_emails = st.session_state.quarantine_emails
    if not quarantine_emails:
        st.info("No quarantined emails.")
    else:
        st.caption(f"Loaded {len(quarantine_emails)} quarantined email(s).")
        for record in quarantine_emails:
            email = record.get("email", {})
            msg_id = record.get("id", "")
            risk_score = float(record.get("risk_score", 0.0) or 0.0)
            label = record.get("label")
            label_text = "unlabeled" if label is None else str(label)
            title = (
                f"{email.get('subject', '(no subject)')} | {email.get('from_email', '')} | "
                f"risk={risk_score:.2f} | label={label_text}"
            )

            with st.expander(title, expanded=False):
                summary_l, summary_r = st.columns([2, 2])
                with summary_l:
                    st.write(f"Status: {record.get('status', '')}")
                    st.write(f"Label: {label_text}")
                    st.write(f"Description: {record.get('description', '')}")
                    if record.get("link_scan_failed_closed"):
                        st.warning("Fail-closed triggered during link scan.")
                with summary_r:
                    render_chip(f"risk: {risk_score:.2f}", "bad")
                    render_chip(f"status: {record.get('status', 'unknown')}", "mid")
                    render_chip(f"label: {label_text}", "neutral")

                reasons = record.get("risk_reasons", [])
                if reasons:
                    st.markdown("#### Risk Reasons")
                    for reason in reasons:
                        st.write(f"- {reason}")

                link_results = record.get("link_results", [])
                render_yutori_link_results(link_results=link_results, key_prefix=f"quarantine_{msg_id}")

                st.markdown("#### Email Body")
                st.code(email.get("body", ""))

                c1, c2, c3 = st.columns([1, 1, 1])
                if c1.button("Label Scam", key=f"scam_{msg_id}", use_container_width=True):
                    try:
                        api_post(f"/risk/quarantine/{msg_id}/label", {"label": 1})
                        st.success("Labeled as scam.")
                        refresh_emails()
                        st.rerun()
                    except requests.RequestException as exc:
                        st.error(f"Failed to label scam: {exc}")

                if c2.button("Label Not Scam + Release", key=f"not_scam_{msg_id}", use_container_width=True):
                    try:
                        api_post(f"/risk/quarantine/{msg_id}/label", {"label": 0})
                        api_post(f"/risk/quarantine/{msg_id}/release", {})
                        st.success("Labeled not scam and released to inbox.")
                        refresh_emails()
                        st.rerun()
                    except requests.RequestException as exc:
                        st.error(f"Failed to label not scam: {exc}")

                if c3.button("Release Only", key=f"release_{msg_id}", use_container_width=True):
                    try:
                        api_post(f"/risk/quarantine/{msg_id}/release", {})
                        st.success("Released to inbox.")
                        refresh_emails()
                        st.rerun()
                    except requests.RequestException as exc:
                        st.error(f"Failed to release email: {exc}")

                with st.expander("Raw Quarantine Record", expanded=False):
                    st.json(record)

with scans_tab:
    render_scan_activity_tab()
