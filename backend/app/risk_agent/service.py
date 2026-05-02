import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from backend.app.gmail_client import resolve_gmail_account_email
from backend.app.gmail_service import GmailService
from backend.app.risk_agent.email_parsing import parse_sender
from backend.app.risk_agent.graph import EmailRiskGraph, normalize_decision_mode
from backend.app.risk_agent.llm import RiskLLMScorer
from backend.app.risk_agent.store import ProcessedMessageStore, QuarantineStore
from backend.app.schemas import (
    DashboardRecentItem,
    DashboardSummaryResponse,
    EmailReviewItem,
    EmailRiskSummary,
    LabelResponse,
    LinkEvaluateResponse,
    ListEmailReviewItemsResponse,
    ListQuarantineResponse,
    ManualCheckResponse,
    ManualResearchSummary,
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
        llm_model = os.getenv("RISK_LLM_MODEL", "936565b3-dfac-4ebf-bb8c-d4ec98ad8039")
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
        processed_messages_path = os.getenv("RISK_PROCESSED_MESSAGES_PATH", "data/processed_messages.jsonl")
        screening_enabled_env = _env_bool("RISK_SCREENING_ENABLED", True)
        screening_interval_seconds = int(os.getenv("RISK_SCREENING_INTERVAL_SECONDS", "60"))
        screening_batch_size = int(os.getenv("RISK_SCREENING_MAX_BATCH_SIZE", "25"))
        screening_minutes_since = int(os.getenv("RISK_SCREENING_LOOKBACK_MINUTES", "240"))
        screening_account = (resolve_gmail_account_email() or "").strip()

        self.store = QuarantineStore(quarantine_path=quarantine_path, feedback_path=feedback_path)
        self.processed_store = ProcessedMessageStore(state_path=processed_messages_path)
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
        self.gmail_service = GmailService()
        self._screening_enabled_by_env = screening_enabled_env
        self.screening_enabled = screening_enabled_env and bool(screening_account)
        self.screening_interval_seconds = max(15, screening_interval_seconds)
        self.screening_batch_size = max(1, screening_batch_size)
        self.screening_minutes_since = max(1, screening_minutes_since)
        self.screening_account = screening_account
        self._scanner_state = "disabled" if not self.screening_enabled else "idle"
        self._scanner_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def refresh_screening_account(self) -> dict[str, bool | str]:
        """Re-read mailbox from env/token (call after OAuth saves token.json while API is running)."""
        load_dotenv(Path(__file__).resolve().parents[3] / ".env")
        self.screening_account = (resolve_gmail_account_email() or "").strip()
        self.screening_enabled = self._screening_enabled_by_env and bool(self.screening_account)
        self._scanner_state = "disabled" if not self.screening_enabled else "idle"
        if self.screening_enabled and self._scanner_thread is None:
            self.start_background_screening()
        return {"screening_enabled": self.screening_enabled, "mailbox": self.screening_account}

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
    def _body_preview(body: str) -> str:
        preview = " ".join(body.split())
        return preview[:220]

    def _review_item_from_record(self, record: QuarantineRecord) -> EmailReviewItem:
        email = record.email
        return EmailReviewItem(
            id=record.id,
            sender_name=record.sender_name,
            sender_email=record.sender_email or email.from_email,
            subject=record.subject or email.subject,
            received_at=email.send_time,
            body_preview=self._body_preview(email.body),
            body_full=email.body,
            description=record.description,
            risk_score=record.risk_score,
            risk_reasons=record.risk_reasons,
            model_version=record.model_version,
            status=record.status,
            label=record.label,
            link_results=record.link_results,
            link_scan_failed_closed=record.link_scan_failed_closed,
        )

    def _mark_processed(self, message_id: str, *, decision: str, status: str) -> None:
        self.processed_store.upsert(
            {
                "id": message_id,
                "decision": decision,
                "status": status,
                "updated_at": _utc_now_iso(),
            }
        )

    @staticmethod
    def _sender_fields(from_email: str, subject: str) -> tuple[str, str, str]:
        sender_name, sender_addr = parse_sender(from_email)
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
        self._mark_processed(response.id, decision=response.decision, status=response.status)
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
        self._mark_processed(record.id, decision="quarantine", status=status)
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
        self._mark_processed(record.id, decision="deliver", status="released")
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

    def manual_check(
        self,
        *,
        sender_email: str,
        company_name: str,
        subject: str,
        body: str,
        urls: list[str] | None = None,
    ) -> ManualCheckResponse:
        link_response = self.evaluate_links(
            sender_email=sender_email,
            subject=subject,
            body=body,
            urls=urls,
        )
        research = self.graph.yutori_client.research_text(
            sender_email=sender_email,
            company_name=company_name,
            subject=subject,
            body=body,
        )
        return ManualCheckResponse(
            email_risk_summary=link_response.email_risk_summary,
            link_results=link_response.link_results,
            research=ManualResearchSummary(
                query=research.query,
                summary=research.summary,
                provider=research.provider,
                executed=research.executed,
                preview_url=research.preview_url,
                task_id=research.task_id,
                details=research.details,
            ),
        )

    def list_review_items(self, *, statuses: set[str]) -> ListEmailReviewItemsResponse:
        records = [
            self._review_item_from_record(record)
            for record in self.store.list(include_released=True)
            if record.status in statuses
        ]
        return ListEmailReviewItemsResponse(count=len(records), emails=records)

    def list_scam(self) -> ListEmailReviewItemsResponse:
        return self.list_review_items(statuses={"confirmed_scam"})

    def list_quarantine_review(self) -> ListEmailReviewItemsResponse:
        return self.list_review_items(statuses={"pending_human_review"})

    def mark_scam(self, message_id: str) -> LabelResponse:
        return self.label_quarantine(message_id, 1)

    def mark_non_scam(self, message_id: str) -> ReleaseResponse:
        self.label_quarantine(message_id, 0)
        return self.release_quarantine(message_id)

    def remove_from_scam(self, message_id: str) -> ReleaseResponse:
        return self.mark_non_scam(message_id)

    def dashboard_summary(self) -> DashboardSummaryResponse:
        records = self.store.list(include_released=True)
        recent = sorted(records, key=lambda item: item.updated_at, reverse=True)[:5]
        false_positive_count = sum(1 for item in records if item.status in {"confirmed_legit", "released"})
        return DashboardSummaryResponse(
            screened_count=self.processed_store.count(),
            quarantined_count=sum(1 for item in records if item.status == "pending_human_review"),
            confirmed_scam_count=sum(1 for item in records if item.status == "confirmed_scam"),
            false_positive_count=false_positive_count,
            last_scan_at=self.processed_store.latest_timestamp(),
            screening_enabled=self.screening_enabled,
            gmail_connected_email=resolve_gmail_account_email(),
            scanner_status=self._scanner_state,  # type: ignore[arg-type]
            recent_high_risk=[
                DashboardRecentItem(
                    id=item.id,
                    subject=item.subject,
                    sender_name=item.sender_name,
                    sender_email=item.sender_email,
                    risk_score=item.risk_score,
                    status=item.status,
                    updated_at=item.updated_at,
                )
                for item in recent
            ],
        )

    def screen_inbox_once(self) -> dict[str, int | str]:
        if not self.screening_account:
            return {"processed": 0, "quarantined": 0, "delivered": 0, "skipped": 0, "status": "disabled"}

        emails = self.gmail_service.list_emails(
            email_address=self.screening_account,
            minutes_since=self.screening_minutes_since,
            include_read=True,
            max_results=self.screening_batch_size,
            inbox_wide=True,
        ).emails
        processed = quarantined = delivered = skipped = 0

        for email in emails:
            if self.processed_store.contains(email.id):
                skipped += 1
                continue
            result = self.evaluate_email(
                RiskEmailInput(
                    id=email.id,
                    thread_id=email.thread_id,
                    from_email=email.from_email,
                    to_email=email.to_email,
                    subject=email.subject,
                    body=email.body,
                    send_time=email.send_time,
                    headers=None,
                )
            )
            processed += 1
            if result.decision == "quarantine":
                quarantined += 1
            else:
                delivered += 1

        return {
            "processed": processed,
            "quarantined": quarantined,
            "delivered": delivered,
            "skipped": skipped,
            "status": "ok",
        }

    def _screening_loop(self) -> None:
        while not self._stop_event.is_set():
            self._scanner_state = "running"
            try:
                self.screen_inbox_once()
            except Exception:
                logger.exception("background_screening_failed")
            self._scanner_state = "idle" if self.screening_enabled else "disabled"
            self._stop_event.wait(self.screening_interval_seconds)

    def start_background_screening(self) -> None:
        if not self.screening_enabled or self._scanner_thread is not None:
            return
        self._stop_event.clear()
        self._scanner_thread = threading.Thread(target=self._screening_loop, name="risk-screening-loop", daemon=True)
        self._scanner_thread.start()

    def stop_background_screening(self) -> None:
        self._stop_event.set()
        self._scanner_thread = None
        self._scanner_state = "disabled" if not self.screening_enabled else "idle"
