"""Browser-based Google OAuth (authorization code) for local Gmail setup."""

from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import requests
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

import os

from dotenv import load_dotenv

from backend.app.gmail_client import gmail_token_path
from backend.app.gmail_oauth_config import oauth_app_json_path

GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"

GMAIL_OAUTH_SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
]


def _repo_root_for_env() -> None:
    load_dotenv(oauth_app_json_path().resolve().parent.parent / ".env")


def oauth_redirect_uri() -> str:
    _repo_root_for_env()
    return os.getenv(
        "GMAIL_OAUTH_REDIRECT_URI",
        "http://127.0.0.1:8000/auth/google/callback",
    ).strip()


def frontend_base_url() -> str:
    _repo_root_for_env()
    return os.getenv("FRONTEND_URL", "http://127.0.0.1:3000").rstrip("/")


_oauth_state_ttl_seconds = 600
_pending_states: dict[str, float] = {}


def _cleanup_states() -> None:
    now = time.time()
    for key, exp in list(_pending_states.items()):
        if exp < now:
            del _pending_states[key]


def create_oauth_state() -> str:
    _cleanup_states()
    state = secrets.token_urlsafe(32)
    _pending_states[state] = time.time() + _oauth_state_ttl_seconds
    return state


def consume_oauth_state(state: str) -> bool:
    _cleanup_states()
    exp = _pending_states.pop(state, None)
    return exp is not None and exp >= time.time()


def build_authorization_url(*, client_id: str, redirect_uri: str, state: str) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(GMAIL_OAUTH_SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return f"{GOOGLE_AUTH_URI}?{urlencode(params)}"


def exchange_authorization_code(*, code: str, client_id: str, client_secret: str, redirect_uri: str) -> dict[str, Any]:
    response = requests.post(
        GOOGLE_TOKEN_URI,
        data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        timeout=45,
    )
    response.raise_for_status()
    return response.json()


def persist_token_from_code_response(
    tok: dict[str, Any],
    *,
    client_id: str,
    client_secret: str,
) -> str:
    scope_raw = tok.get("scope")
    if isinstance(scope_raw, str) and scope_raw.strip():
        scopes_list = scope_raw.strip().split()
    else:
        scopes_list = list(GMAIL_OAUTH_SCOPES)

    creds = Credentials(
        token=tok["access_token"],
        refresh_token=tok.get("refresh_token"),
        token_uri=GOOGLE_TOKEN_URI,
        client_id=client_id,
        client_secret=client_secret,
        scopes=scopes_list,
    )
    service = build("gmail", "v1", credentials=creds)
    profile = service.users().getProfile(userId="me").execute()
    email_address = str(profile.get("emailAddress") or "")

    expires_in = int(tok.get("expires_in") or 3600)
    expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    token_data = {
        "token": tok["access_token"],
        "refresh_token": tok.get("refresh_token"),
        "token_uri": GOOGLE_TOKEN_URI,
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": creds.scopes or GMAIL_OAUTH_SCOPES,
        "universe_domain": "googleapis.com",
        "account": email_address,
        "expiry": expiry.isoformat().replace("+00:00", "Z"),
    }

    path = gmail_token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(token_data, indent=2))
    return email_address
