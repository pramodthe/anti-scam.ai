import logging
import os
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path

from dotenv import load_dotenv

from backend.app.risk_agent.graph import EmailRiskGraph, normalize_decision_mode
from backend.app.risk_agent.llm import RiskLLMScorer
from backend.app.risk_agent.store import QuarantineStore
from backend.app.schemas import (
    EmailRiskSummary,
    LabelResponse,
    LinkEvaluateResponse,
    ListQuarantineResponse,
    QuarantineRecord,
    ReleaseResponse,
    RiskEmailInput,
    RiskEvaluateResponse,
)

logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class RiskService:
    def __init__(self) -> None:
        load_dotenv(Path(__file__).resolve().parents[3] / ".env")
        threshold = float(os.getenv("RISK_THRESHOLD", "0.65"))
        model_version = os.getenv("RISK_MODEL_VERSION", "risk-agent-v1")
        llm_model = os.getenv("RISK_LLM_MODEL", "gpt-4.1-mini")
        llm_enabled = _env_bool("RISK_LLM_ENABLED", True)
        decision_mode = normalize_decision_mode(os.getenv("RISK_DECISION_MODE", "hybrid"))
        fail_closed = _env_bool("RISK_FAIL_CLOSED", False)
        link_scan_enabled = _env_bool("RISK_LINK_SCAN_ENABLED", True)
        link_scan_max_urls = int(os.getenv("RISK_LINK_SCAN_MAX_URLS", "3"))
        link_scan_timeout_seconds = int(os.getenv("RISK_LINK_SCAN_TIMEOUT_SECONDS", "20"))
        link_scan_fail_closed = _env_bool("RISK_LINK_SCAN_FAIL_CLOSED", True)
        link_scan_allow_http = _env_bool("RISK_LINK_SCAN_ALLOW_HTTP", False)
        yutori_browse_max_steps = int(os.getenv("YUTORI_BROWSE_MAX_STEPS", "20"))
        quarantine_path = os.getenv("RISK_QUARANTINE_PATH", "data/quarantine.jsonl")
        feedback_path = os.getenv("RISK_FEEDBACK_PATH", "data/training_feedback.jsonl")

        self.store = QuarantineStore(quarantine_path=quarantine_path, feedback_path=feedback_path)
        self.graph = EmailRiskGraph(
            threshold=threshold,
            model_version=model_version,
            llm_scorer=RiskLLMScorer(model=llm_model, enabled=llm_enabled),
            decision_mode=decision_mode,
            fail_closed=fail_closed,
            link_scan_enabled=link_scan_enabled,
            link_scan_max_urls=link_scan_max_urls,
            link_scan_timeout_seconds=link_scan_timeout_seconds,
            link_scan_fail_closed=link_scan_fail_closed,
            link_scan_allow_http=link_scan_allow_http,
            yutori_browse_max_steps=yutori_browse_max_steps,
        )

    def _from_record(self, record: QuarantineRecord, decision: str) -> RiskEvaluateResponse:
        return RiskEvaluateResponse(
            id=record.id,
            decision=decision,
            risk_score=record.risk_score,
            risk_reasons=record.risk_reasons,
            description=record.description,
            model_version=record.model_version,
            status=record.status,
            links_found=len(record.link_results),
            links_scanned=len(record.link_results),
            link_results=record.link_results,
            link_risk_score=record.link_risk_score,
            link_scan_failed_closed=record.link_scan_failed_closed,
        )

    @staticmethod
    def _sender_fields(from_email: str, subject: str) -> tuple[str, str, str]:
        sender_name, sender_addr = parseaddr(from_email)
        return sender_name.strip(), sender_addr.strip() or from_email.strip(), subject.strip()

    def evaluate_email(self, email: RiskEmailInput) -> RiskEvaluateResponse:
        existing = self.store.get(email.id)
        if existing and existing.status in {"pending_human_review", "confirmed_scam"}:
            return self._from_record(existing, "quarantine")
        if existing and existing.status in {"confirmed_legit", "released"}:
            return self._from_record(existing, "deliver")

        result = self.graph.evaluate(email.model_dump())
        response = RiskEvaluateResponse(**result)

        if response.decision == "quarantine":
            now = _utc_now_iso()
            sender_name, sender_email, subject = self._sender_fields(email.from_email, email.subject)
            record = QuarantineRecord(
                id=response.id,
                sender_name=sender_name,
                sender_email=sender_email,
                subject=subject,
                description=response.description,
                risk_score=response.risk_score,
                risk_reasons=response.risk_reasons,
                model_version=response.model_version,
                status="pending_human_review",
                label=None,
                created_at=now,
                updated_at=now,
                email=email,
                link_results=response.link_results,
                link_risk_score=response.link_risk_score,
                link_scan_failed_closed=response.link_scan_failed_closed,
            )
            self.store.upsert(record)

        logger.info(
            "risk_evaluated id=%s decision=%s risk_score=%.3f",
            response.id,
            response.decision,
            response.risk_score,
        )
        return response

    def list_quarantine(self) -> ListQuarantineResponse:
        emails = self.store.list(include_released=False)
        return ListQuarantineResponse(count=len(emails), emails=emails)

    def get_quarantine(self, message_id: str) -> QuarantineRecord:
        record = self.store.get(message_id)
        if record is None:
            raise KeyError(f"Message {message_id} not found in quarantine")
        return record

    def label_quarantine(self, message_id: str, label: int) -> LabelResponse:
        record = self.get_quarantine(message_id)
        updated_at = _utc_now_iso()
        status = "confirmed_scam" if label == 1 else "confirmed_legit"
        sender_name, sender_email, subject = self._sender_fields(record.email.from_email, record.email.subject)

        updated_record = record.model_copy(
            update={
                "label": label,
                "status": status,
                "updated_at": updated_at,
                "sender_name": sender_name,
                "sender_email": sender_email,
                "subject": subject,
            }
        )
        self.store.upsert(updated_record)
        self.store.append_feedback(
            {
                "id": record.id,
                "sender_name": sender_name,
                "sender_email": sender_email,
                "subject": subject,
                "description": updated_record.description,
                "risk_score": updated_record.risk_score,
                "label": label,
                "reviewed_at": updated_at,
            }
        )

        logger.info("risk_labeled id=%s label=%s status=%s", record.id, label, status)
        return LabelResponse(id=record.id, label=label, status=status, updated_at=updated_at)

    def release_quarantine(self, message_id: str) -> ReleaseResponse:
        record = self.get_quarantine(message_id)
        updated_at = _utc_now_iso()
        sender_name, sender_email, subject = self._sender_fields(record.email.from_email, record.email.subject)
        updated_record = record.model_copy(
            update={
                "status": "released",
                "updated_at": updated_at,
                "sender_name": sender_name,
                "sender_email": sender_email,
                "subject": subject,
            }
        )
        self.store.upsert(updated_record)

        logger.info("risk_released id=%s", record.id)
        return ReleaseResponse(id=record.id, status="released", updated_at=updated_at)

    def evaluate_links(
        self,
        sender_email: str,
        subject: str,
        body: str,
        urls: list[str] | None = None,
    ) -> LinkEvaluateResponse:
        link_results, assessment = self.graph.evaluate_links(
            sender_email=sender_email,
            subject=subject,
            body=body,
            urls=urls,
        )
        score = float(assessment.risk_score or 0.0)
        decision = "quarantine" if assessment.force_quarantine else "deliver"
        summary = EmailRiskSummary(
            decision=decision,  # type: ignore[arg-type]
            risk_score=score,
            links_found=len(link_results),
            links_scanned=len(link_results),
            link_risk_score=assessment.risk_score,
            link_scan_failed_closed=assessment.failed_closed,
            risk_reasons=assessment.risk_flags,
        )
        return LinkEvaluateResponse(email_risk_summary=summary, link_results=link_results)
