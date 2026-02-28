from fastapi import FastAPI, HTTPException, Query

from backend.app.gmail_service import GmailService
from backend.app.risk_agent import RiskService
from backend.app.schemas import (
    DeleteEmailResponse,
    LabelRequest,
    LabelResponse,
    LinkEvaluateRequest,
    LinkEvaluateResponse,
    ListEmailsResponse,
    ListQuarantineResponse,
    QuarantineRecord,
    ReleaseResponse,
    RiskEvaluateRequest,
    RiskEvaluateResponse,
    SendEmailRequest,
    SendEmailResponse,
)

app = FastAPI(title="Basic Gmail App API", version="1.0.0")
gmail = GmailService()
risk = RiskService()


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


@app.post("/risk/emails/evaluate", response_model=RiskEvaluateResponse)
def evaluate_email(payload: RiskEvaluateRequest) -> RiskEvaluateResponse:
    try:
        return risk.evaluate_email(payload.email)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to evaluate risk: {exc}") from exc


@app.post("/risk/links/evaluate", response_model=LinkEvaluateResponse)
def evaluate_links(payload: LinkEvaluateRequest) -> LinkEvaluateResponse:
    try:
        return risk.evaluate_links(
            sender_email=payload.sender_email,
            subject=payload.subject,
            body=payload.body,
            urls=payload.urls,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to evaluate links: {exc}") from exc


@app.get("/risk/quarantine", response_model=ListQuarantineResponse)
def list_quarantine() -> ListQuarantineResponse:
    try:
        return risk.list_quarantine()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to list quarantine: {exc}") from exc


@app.get("/risk/quarantine/{message_id}", response_model=QuarantineRecord)
def get_quarantine(message_id: str) -> QuarantineRecord:
    try:
        return risk.get_quarantine(message_id=message_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to get quarantine: {exc}") from exc


@app.post("/risk/quarantine/{message_id}/label", response_model=LabelResponse)
def label_quarantine(message_id: str, payload: LabelRequest) -> LabelResponse:
    try:
        return risk.label_quarantine(message_id=message_id, label=payload.label)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to label quarantine: {exc}") from exc


@app.post("/risk/quarantine/{message_id}/release", response_model=ReleaseResponse)
def release_quarantine(message_id: str) -> ReleaseResponse:
    try:
        return risk.release_quarantine(message_id=message_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to release quarantine: {exc}") from exc
