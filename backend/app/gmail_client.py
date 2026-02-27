import base64
import json
import os
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


class GmailClient:
    """Minimal Gmail API client for list/send/delete."""

    def __init__(self) -> None:
        root = Path(__file__).resolve().parents[2]
        load_dotenv(root / ".env")
        secrets_dir = root / ".secrets"
        self._token_path = secrets_dir / "token.json"

    def _load_credentials(self) -> Credentials:
        env_token = os.getenv("GMAIL_TOKEN")
        if env_token:
            token_data = json.loads(env_token)
        elif self._token_path.exists():
            token_data = json.loads(self._token_path.read_text())
        else:
            raise RuntimeError(
                "Gmail token not found. Run scripts/setup_gmail.py or set GMAIL_TOKEN in environment."
            )

        return Credentials(
            token=token_data.get("token"),
            refresh_token=token_data.get("refresh_token"),
            token_uri=token_data.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=token_data.get("client_id"),
            client_secret=token_data.get("client_secret"),
            scopes=token_data.get(
                "scopes",
                [
                    "https://www.googleapis.com/auth/gmail.modify",
                    "https://www.googleapis.com/auth/gmail.send",
                ],
            ),
        )

    def _gmail_service(self) -> Any:
        return build("gmail", "v1", credentials=self._load_credentials())

    @staticmethod
    def _extract_message_part(payload: dict[str, Any]) -> str:
        if payload.get("body", {}).get("data"):
            data = payload["body"]["data"]
            return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")

        if payload.get("parts"):
            parts = []
            for part in payload["parts"]:
                content = GmailClient._extract_message_part(part)
                if content:
                    parts.append(content)
            return "\n".join(parts)

        return ""

    def list_emails(
        self, email_address: str, minutes_since: int = 1440, include_read: bool = True, max_results: int = 25
    ) -> list[dict[str, Any]]:
        service = self._gmail_service()
        after = int((datetime.now() - timedelta(minutes=minutes_since)).timestamp())
        query = f"(to:{email_address} OR from:{email_address}) after:{after}"
        if not include_read:
            query += " is:unread"

        results = (
            service.users()
            .messages()
            .list(userId="me", q=query, maxResults=max_results)
            .execute()
        )
        messages = results.get("messages", [])

        parsed: list[dict[str, Any]] = []
        for m in messages:
            msg = service.users().messages().get(userId="me", id=m["id"], format="full").execute()
            headers = msg.get("payload", {}).get("headers", [])
            subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "")
            from_email = next((h["value"] for h in headers if h["name"].lower() == "from"), "")
            to_email = next((h["value"] for h in headers if h["name"].lower() == "to"), "")
            date = next((h["value"] for h in headers if h["name"].lower() == "date"), "")
            body = self._extract_message_part(msg.get("payload", {}))

            parsed.append(
                {
                    "id": msg["id"],
                    "thread_id": msg.get("threadId", ""),
                    "from_email": from_email,
                    "to_email": to_email,
                    "subject": subject,
                    "send_time": date,
                    "body": body,
                }
            )

        return parsed

    def send_email(self, to: str, subject: str, body: str) -> dict[str, Any]:
        service = self._gmail_service()
        msg = MIMEText(body)
        msg["to"] = to
        msg["subject"] = subject
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
        result = service.users().messages().send(userId="me", body={"raw": raw}).execute()
        return {"message_id": result.get("id", ""), "thread_id": result.get("threadId")}

    def delete_email(self, message_id: str) -> None:
        service = self._gmail_service()
        service.users().messages().trash(userId="me", id=message_id).execute()
