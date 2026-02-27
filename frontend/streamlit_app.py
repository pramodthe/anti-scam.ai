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
        st.session_state.emails = result.get("emails", [])
    except requests.RequestException as exc:
        st.error(f"Failed to fetch emails: {exc}")


st.set_page_config(page_title="Basic Gmail App", page_icon="✉️", layout="wide")
st.title("Basic Gmail App")
st.caption("Send, view, and delete emails. HITL is manual review before delete.")

if "account_email" not in st.session_state:
    st.session_state.account_email = DEFAULT_ACCOUNT
if "minutes_since" not in st.session_state:
    st.session_state.minutes_since = 1440
if "include_read" not in st.session_state:
    st.session_state.include_read = True
if "max_results" not in st.session_state:
    st.session_state.max_results = 25
if "emails" not in st.session_state:
    st.session_state.emails = []
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
st.subheader("Inbox")

emails = st.session_state.emails
if not emails:
    st.info("No emails loaded. Click 'Refresh Inbox'.")
else:
    st.write(f"Loaded {len(emails)} email(s).")
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
