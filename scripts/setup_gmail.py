#!/usr/bin/env python3
"""
Setup Gmail OAuth for this app.

OAuth client configuration (pick one):
  1) Set in .env at repo root:
       GMAIL_OAUTH_CLIENT_ID
       GMAIL_OAUTH_CLIENT_SECRET
  2) Or copy Google's downloaded Desktop client JSON to .secrets/secrets.json

Writes the refresh token to GMAIL_TOKEN_PATH (see .env) or default .secrets/token.json.
After login, the signed-in Gmail address is stored in the token file (optional GMAIL_ACCOUNT in .env).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Repo root (parent of scripts/)
ROOT = Path(__file__).resolve().parents[1]

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
]


def _env_client_config() -> dict[str, Any] | None:
    cid = os.getenv("GMAIL_OAUTH_CLIENT_ID", "").strip()
    csec = os.getenv("GMAIL_OAUTH_CLIENT_SECRET", "").strip()
    if not cid or not csec:
        return None
    return {
        "installed": {
            "client_id": cid,
            "client_secret": csec,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["http://localhost"],
        }
    }


def _load_oauth_client_config() -> tuple[dict[str, Any], str]:
    env_cfg = _env_client_config()
    if env_cfg is not None:
        return env_cfg, "GMAIL_OAUTH_CLIENT_ID / GMAIL_OAUTH_CLIENT_SECRET from .env"

    secrets_path = ROOT / ".secrets" / "secrets.json"
    if secrets_path.exists():
        return json.loads(secrets_path.read_text()), str(secrets_path)

    print("Missing Gmail OAuth client configuration.")
    print()
    print("Option A — add to .env (repo root):")
    print("  GMAIL_OAUTH_CLIENT_ID=your-client-id.apps.googleusercontent.com")
    print("  GMAIL_OAUTH_CLIENT_SECRET=...")
    print()
    print("Option B — place Google's Desktop OAuth JSON at:")
    print(f"  {secrets_path}")
    raise SystemExit(1)


def main() -> int:
    sys.path.insert(0, str(ROOT))
    load_dotenv(ROOT / ".env")

    client_config, source = _load_oauth_client_config()
    print(f"Using OAuth client from: {source}")

    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
    credentials = flow.run_local_server(port=0)

    service = build("gmail", "v1", credentials=credentials)
    profile = service.users().getProfile(userId="me").execute()
    email_address = str(profile.get("emailAddress") or "")

    token_data = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": list(credentials.scopes or SCOPES),
        "universe_domain": "googleapis.com",
        "account": email_address,
        "expiry": credentials.expiry.isoformat() + "Z" if credentials.expiry else "",
    }

    from backend.app.gmail_client import gmail_token_path

    token_path = gmail_token_path()
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(json.dumps(token_data, indent=2))
    print(f"OAuth complete. Token written to: {token_path}")
    if email_address:
        print(f"Signed in as: {email_address}")
        print("(Optional) Set GMAIL_ACCOUNT in .env to the same address, or leave unset to use the token.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
