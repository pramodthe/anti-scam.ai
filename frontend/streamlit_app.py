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

        for email in fetched_emails:
            try:
                evaluation = api_post("/risk/emails/evaluate", {"email": email})
                if evaluation.get("decision") == "deliver":
                    safe_emails.append(email)
            except requests.RequestException:
                # Risk service failures should not fully block inbox rendering.
                safe_emails.append(email)

        st.session_state.safe_emails = safe_emails

        quarantine_result = api_get("/risk/quarantine")
        st.session_state.quarantine_emails = quarantine_result.get("emails", [])
    except requests.RequestException as exc:
        st.error(f"Failed to fetch emails: {exc}")


st.set_page_config(page_title="Basic Gmail App", page_icon="✉️", layout="wide")
st.title("Basic Gmail App")
st.caption("Send, view, and delete emails with AI quarantine and HITL scam labeling.")

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

col_left, col_right = st.columns([1, 1])

with col_left:
    st.subheader("Compose Email")
    with st.form("compose_form"):
        to = st.text_input("To", value=DEFAULT_TO)
        subject = st.text_input("Subject", value="hello")
        body = st.text_area("Message", value="hello", height=120)
        send_clicked = st.form_submit_button("Send")

    if send_clicked:
        try:
            result = api_post("/gmail/send", {"to": to, "subject": subject, "body": body})
            st.success(f"Sent. Message ID: {result.get('message_id')}")
        except requests.RequestException as exc:
            st.error(f"Send failed: {exc}")

with col_right:
    st.subheader("Inbox Settings")
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
    if st.button("Refresh Inbox", use_container_width=True):
        if not st.session_state.account_email:
            st.error("Enter Gmail account first.")
        else:
            refresh_emails()

st.divider()
inbox_tab, quarantine_tab = st.tabs(["Inbox", "Quarantine"])

with inbox_tab:
    st.subheader("Inbox")
    emails = st.session_state.safe_emails
    if not emails:
        st.info("No safe emails loaded. Click 'Refresh Inbox'.")
    else:
        st.write(f"Loaded {len(emails)} safe email(s).")
        for email in emails:
            title = f"{email.get('subject', '(no subject)')} | {email.get('from_email', '')}"
            with st.expander(title, expanded=False):
                st.write(f"From: {email.get('from_email', '')}")
                st.write(f"To: {email.get('to_email', '')}")
                st.write(f"Date: {email.get('send_time', '')}")
                st.code(email.get("body", ""))

                msg_id = email.get("id", "")
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
    st.subheader("Quarantine")
    quarantine_emails = st.session_state.quarantine_emails
    if not quarantine_emails:
        st.info("No quarantined emails.")
    else:
        st.write(f"Loaded {len(quarantine_emails)} quarantined email(s).")
        for record in quarantine_emails:
            email = record.get("email", {})
            msg_id = record.get("id", "")
            risk_score = float(record.get("risk_score", 0.0))
            title = f"{email.get('subject', '(no subject)')} | {email.get('from_email', '')} | risk={risk_score:.2f}"

            with st.expander(title, expanded=False):
                st.write(f"Status: {record.get('status', '')}")
                label = record.get("label")
                st.write(f"Label: {'unlabeled' if label is None else label}")
                st.write(f"Description: {record.get('description', '')}")
                reasons = record.get("risk_reasons", [])
                st.write("Reasons:")
                for reason in reasons:
                    st.write(f"- {reason}")
                st.code(email.get("body", ""))

                c1, c2, c3 = st.columns([1, 1, 1])
                if c1.button("Scam", key=f"scam_{msg_id}"):
                    try:
                        api_post(f"/risk/quarantine/{msg_id}/label", {"label": 1})
                        st.success("Labeled as scam.")
                        refresh_emails()
                        st.rerun()
                    except requests.RequestException as exc:
                        st.error(f"Failed to label scam: {exc}")

                if c2.button("Not Scam", key=f"not_scam_{msg_id}"):
                    try:
                        api_post(f"/risk/quarantine/{msg_id}/label", {"label": 0})
                        api_post(f"/risk/quarantine/{msg_id}/release", {})
                        st.success("Labeled not scam and released to inbox.")
                        refresh_emails()
                        st.rerun()
                    except requests.RequestException as exc:
                        st.error(f"Failed to label not scam: {exc}")

                if c3.button("Release", key=f"release_{msg_id}"):
                    try:
                        api_post(f"/risk/quarantine/{msg_id}/release", {})
                        st.success("Released to inbox.")
                        refresh_emails()
                        st.rerun()
                    except requests.RequestException as exc:
                        st.error(f"Failed to release email: {exc}")
