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


class RiskEvaluateResponse(BaseModel):
    id: str
    decision: RiskDecision
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_reasons: list[str]
    description: str
    model_version: str
    status: RiskStatus


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
