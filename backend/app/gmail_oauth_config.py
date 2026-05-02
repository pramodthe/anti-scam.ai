"""Shared Gmail OAuth client ID/secret resolution (.env or saved setup file)."""

import json
import os
from pathlib import Path

from dotenv import load_dotenv


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def oauth_app_json_path() -> Path:
    return _repo_root() / ".secrets" / "oauth_app.json"


def save_oauth_client(client_id: str, client_secret: str) -> None:
    path = oauth_app_json_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {"client_id": client_id.strip(), "client_secret": client_secret.strip()},
            indent=2,
        )
    )


def load_oauth_client_pair() -> tuple[str, str]:
    load_dotenv(_repo_root() / ".env")
    cid = os.getenv("GMAIL_OAUTH_CLIENT_ID", "").strip()
    csec = os.getenv("GMAIL_OAUTH_CLIENT_SECRET", "").strip()
    if cid and csec:
        return cid, csec
    path = oauth_app_json_path()
    if not path.exists():
        return "", ""
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return "", ""
    return (data.get("client_id") or "").strip(), (data.get("client_secret") or "").strip()
