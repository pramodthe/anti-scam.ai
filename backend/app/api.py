from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.app.gmail_service import GmailService
from backend.app.risk_agent import RiskService
from backend.app.schemas import (
    DashboardSummaryResponse,
    DeleteEmailResponse,
    LabelRequest,
    LabelResponse,
    LinkEvaluateRequest,
    LinkEvaluateResponse,
    ListEmailReviewItemsResponse,
    ListEmailsResponse,
    ListQuarantineResponse,
    ManualCheckRequest,
    ManualCheckResponse,
    QuarantineRecord,
    ReleaseResponse,
    RiskEvaluateRequest,
    RiskEvaluateResponse,
    SendEmailRequest,
    SendEmailResponse,
)

app = FastAPI(title="Basic Gmail App API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

gmail = GmailService()
risk = RiskService()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.on_event("startup")
def startup_background_screening() -> None:
    risk.start_background_screening()


@app.on_event("shutdown")
def shutdown_background_screening() -> None:
    risk.stop_background_screening()


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


@app.post("/manual-check", response_model=ManualCheckResponse)
def manual_check(payload: ManualCheckRequest) -> ManualCheckResponse:
    try:
        return risk.manual_check(
            sender_email=payload.sender_email,
            company_name=payload.company_name,
            subject=payload.subject,
            body=payload.body,
            urls=payload.urls,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to run manual check: {exc}") from exc


@app.get("/dashboard/summary", response_model=DashboardSummaryResponse)
def dashboard_summary() -> DashboardSummaryResponse:
    try:
        return risk.dashboard_summary()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load dashboard summary: {exc}") from exc


@app.post("/screening/run")
def screening_run_once() -> dict[str, int | str]:
    try:
        return risk.screen_inbox_once()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to run screening: {exc}") from exc


@app.get("/emails/quarantine", response_model=ListEmailReviewItemsResponse)
def emails_quarantine() -> ListEmailReviewItemsResponse:
    try:
        return risk.list_quarantine_review()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load quarantine emails: {exc}") from exc


@app.get("/emails/scam", response_model=ListEmailReviewItemsResponse)
def emails_scam() -> ListEmailReviewItemsResponse:
    try:
        return risk.list_scam()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load scam emails: {exc}") from exc


@app.post("/emails/{message_id}/mark-scam", response_model=LabelResponse)
def mark_scam(message_id: str) -> LabelResponse:
    try:
        return risk.mark_scam(message_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to mark scam: {exc}") from exc


@app.post("/emails/{message_id}/mark-non-scam", response_model=ReleaseResponse)
def mark_non_scam(message_id: str) -> ReleaseResponse:
    try:
        return risk.mark_non_scam(message_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to mark non-scam: {exc}") from exc


@app.post("/emails/{message_id}/remove-from-scam", response_model=ReleaseResponse)
def remove_from_scam(message_id: str) -> ReleaseResponse:
    try:
        return risk.remove_from_scam(message_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to remove scam email: {exc}") from exc


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


FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend" / "web"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
