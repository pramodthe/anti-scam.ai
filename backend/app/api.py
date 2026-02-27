from fastapi import FastAPI, HTTPException, Query

from backend.app.gmail_service import GmailService
from backend.app.schemas import DeleteEmailResponse, ListEmailsResponse, SendEmailRequest, SendEmailResponse

app = FastAPI(title="Basic Gmail App API", version="1.0.0")
gmail = GmailService()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/gmail/emails", response_model=ListEmailsResponse)
def list_emails(
    email_address: str = Query(..., description="Account email to query"),
    minutes_since: int = Query(1440, ge=1, le=10080),
    include_read: bool = Query(True),
    max_results: int = Query(25, ge=1, le=100),
) -> ListEmailsResponse:
    try:
        return gmail.list_emails(
            email_address=email_address,
            minutes_since=minutes_since,
            include_read=include_read,
            max_results=max_results,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to list emails: {exc}") from exc


@app.post("/gmail/send", response_model=SendEmailResponse)
def send_email(payload: SendEmailRequest) -> SendEmailResponse:
    try:
        return gmail.send_email(to=payload.to, subject=payload.subject, body=payload.body)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {exc}") from exc


@app.delete("/gmail/emails/{message_id}", response_model=DeleteEmailResponse)
def delete_email(message_id: str) -> DeleteEmailResponse:
    try:
        return gmail.delete_email(message_id=message_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete email: {exc}") from exc
