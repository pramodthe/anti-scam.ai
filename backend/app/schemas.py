from typing import Any, Literal

from pydantic import BaseModel, Field


class SendEmailRequest(BaseModel):
    to: str = Field(..., description="Recipient email address")
    subject: str = Field(default="(no subject)")
    body: str = Field(..., description="Email body")


class SendEmailResponse(BaseModel):
    message_id: str
    thread_id: str | None = None


class GmailEmail(BaseModel):
    id: str
    thread_id: str
    from_email: str
    to_email: str
    subject: str
    send_time: str
    body: str


class ListEmailsResponse(BaseModel):
    count: int
    emails: list[GmailEmail]


class DeleteEmailResponse(BaseModel):
    message_id: str
    status: str


RiskDecision = Literal["quarantine", "deliver"]
RiskStatus = Literal["pending_human_review", "confirmed_scam", "confirmed_legit", "released"]
LinkVerdict = Literal["safe", "suspicious", "malicious", "unknown"]
LinkScanStatus = Literal["ok", "timeout", "error"]


class RiskEmailInput(BaseModel):
    id: str
    thread_id: str
    from_email: str
    to_email: str
    subject: str
    body: str
    send_time: str
    headers: dict[str, Any] | None = None


class RiskEvaluateRequest(BaseModel):
    email: RiskEmailInput


class LinkScanResult(BaseModel):
    original_url: str
    normalized_url: str
    final_url: str = ""
    reachable: bool = False
    http_status: int | None = None
    ssl_valid: bool = False
    ssl_issuer: str = ""
    ssl_subject: str = ""
    ssl_expires_at: str | None = None
    ssl_hostname_match: bool = False
    yutori_verdict: LinkVerdict = "unknown"
    yutori_summary: str = ""
    yutori_provider: str = "yutori_api"
    yutori_executed: bool = False
    yutori_task_id: str | None = None
    yutori_preview_url: str | None = None
    yutori_details: dict[str, Any] | None = None
    risk_flags: list[str] = Field(default_factory=list)
    scan_status: LinkScanStatus = "error"


class RiskEvaluateResponse(BaseModel):
    id: str
    decision: RiskDecision
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_reasons: list[str]
    description: str
    model_version: str
    status: RiskStatus
    links_found: int = 0
    links_scanned: int = 0
    link_results: list[LinkScanResult] = Field(default_factory=list)
    link_risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    link_scan_failed_closed: bool = False


class QuarantineRecord(BaseModel):
    id: str
    sender_name: str = ""
    sender_email: str = ""
    subject: str = ""
    description: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_reasons: list[str]
    model_version: str
    status: RiskStatus
    label: Literal[0, 1] | None = None
    created_at: str
    updated_at: str
    email: RiskEmailInput
    link_results: list[LinkScanResult] = Field(default_factory=list)
    link_risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    link_scan_failed_closed: bool = False


class ListQuarantineResponse(BaseModel):
    count: int
    emails: list[QuarantineRecord]


class LabelRequest(BaseModel):
    label: Literal[0, 1]


class LabelResponse(BaseModel):
    id: str
    label: Literal[0, 1]
    status: RiskStatus
    updated_at: str


class ReleaseResponse(BaseModel):
    id: str
    status: RiskStatus
    updated_at: str


class LinkEvaluateRequest(BaseModel):
    sender_email: str
    subject: str = ""
    body: str = ""
    urls: list[str] | None = None


class EmailRiskSummary(BaseModel):
    decision: RiskDecision
    risk_score: float = Field(..., ge=0.0, le=1.0)
    links_found: int
    links_scanned: int
    link_risk_score: float | None = Field(default=None, ge=0.0, le=1.0)
    link_scan_failed_closed: bool = False
    risk_reasons: list[str] = Field(default_factory=list)


class LinkEvaluateResponse(BaseModel):
    email_risk_summary: EmailRiskSummary
    link_results: list[LinkScanResult] = Field(default_factory=list)
