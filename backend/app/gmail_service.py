from backend.app.gmail_client import GmailClient
from backend.app.schemas import DeleteEmailResponse, GmailEmail, ListEmailsResponse, SendEmailResponse


class GmailService:
    """Service layer for Gmail operations."""

    def __init__(self) -> None:
        self.client = GmailClient()

    def list_emails(
        self, email_address: str, minutes_since: int = 1440, include_read: bool = True, max_results: int = 25
    ) -> ListEmailsResponse:
        emails = self.client.list_emails(
            email_address=email_address,
            minutes_since=minutes_since,
            include_read=include_read,
            max_results=max_results,
        )
        return ListEmailsResponse(count=len(emails), emails=[GmailEmail(**e) for e in emails])

    def send_email(self, to: str, subject: str, body: str) -> SendEmailResponse:
        result = self.client.send_email(to=to, subject=subject, body=body)
        return SendEmailResponse(**result)

    def delete_email(self, message_id: str) -> DeleteEmailResponse:
        self.client.delete_email(message_id=message_id)
        return DeleteEmailResponse(message_id=message_id, status="trashed")
