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
