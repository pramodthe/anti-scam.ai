#!/usr/bin/env python3
"""
Setup Gmail OAuth for this app.

Reads:  .secrets/secrets.json
Writes: .secrets/token.json
"""

import json
from pathlib import Path

from google_auth_oauthlib.flow import InstalledAppFlow


SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    secrets_dir = root / ".secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)

    secrets_path = secrets_dir / "secrets.json"
    if not secrets_path.exists():
        print(f"Missing OAuth client file: {secrets_path}")
        print("Copy your downloaded client secret JSON to .secrets/secrets.json and rerun.")
        return 1

    flow = InstalledAppFlow.from_client_secrets_file(str(secrets_path), SCOPES)
    credentials = flow.run_local_server(port=0)

    token_data = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
        "universe_domain": "googleapis.com",
        "account": "",
        "expiry": credentials.expiry.isoformat() + "Z",
    }

    token_path = secrets_dir / "token.json"
    token_path.write_text(json.dumps(token_data))
    print(f"OAuth complete. Token written to: {token_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
