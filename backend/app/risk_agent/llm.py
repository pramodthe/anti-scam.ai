import os
from typing import Any

import requests
from pydantic import BaseModel, Field


class LLMRiskOutput(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_reasons: list[str] = Field(default_factory=list)
    description: str = Field(default="")


class RiskLLMScorer:
    def __init__(self, model: str, enabled: bool) -> None:
        self.model = model
        self.enabled = enabled
        self.api_url = os.getenv("RISK_LLM_API_URL", "https://api.pioneer.ai/gliner-2/custom").strip()
        self.api_key = os.getenv("RISK_LLM_API_KEY", "").strip()
        self.job_id = os.getenv("RISK_LLM_JOB_ID", model).strip()
        self.task = os.getenv("RISK_LLM_TASK", "classify_text").strip()
        self.timeout_seconds = float(os.getenv("RISK_LLM_TIMEOUT_SECONDS", "20"))
        categories = os.getenv("RISK_LLM_SCHEMA_CATEGORIES", "scam,legitimate")
        self.schema_categories = [item.strip() for item in categories.split(",") if item.strip()]
        self.threshold = float(os.getenv("RISK_LLM_THRESHOLD", "0.5"))
        self._available = False

        if not enabled:
            return
        if not self.api_url.startswith("https://"):
            return
        if not self.api_key or not self.job_id:
            return
        if not self.schema_categories:
            return
        self._available = True

    @staticmethod
    def _compose_text(email: dict[str, Any], features: dict[str, Any]) -> str:
        sender = email.get("from_email", "")
        subject = email.get("subject", "")
        body = email.get("body", "")
        return (
            f"From: {sender}\n"
            f"Subject: {subject}\n"
            f"Body: {body}\n\n"
            f"Derived features: {features}"
        )

    @staticmethod
    def _parse_score(result: dict[str, Any], category: str) -> float:
        score_raw = result.get("score", result.get("confidence"))
        if isinstance(score_raw, (int, float)):
            bounded = max(0.0, min(1.0, float(score_raw)))
            if category == "scam":
                return bounded
            if category == "legitimate":
                return 1.0 - bounded
        if category == "scam":
            return 1.0
        if category == "legitimate":
            return 0.0
        return 0.5

    def score(self, email: dict[str, Any], features: dict[str, Any]) -> LLMRiskOutput:
        if not self.enabled:
            raise RuntimeError("llm_disabled")
        if not self._available:
            raise RuntimeError("llm_unavailable")

        payload = {
            "job_id": self.job_id,
            "task": self.task,
            "text": self._compose_text(email=email, features=features),
            "schema": {"categories": self.schema_categories},
            "threshold": self.threshold,
        }

        try:
            response = requests.post(
                self.api_url,
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": self.api_key,
                },
                json=payload,
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError):
            raise RuntimeError("llm_unavailable") from None

        result = body.get("result") if isinstance(body, dict) else None
        if not isinstance(result, dict):
            raise RuntimeError("llm_unavailable")

        category_raw = str(result.get("category", "unknown")).strip().lower()
        risk_score = self._parse_score(result=result, category=category_raw)
        reason = f"pioneer_category:{category_raw or 'unknown'}"
        description = f"Pioneer classifier labeled this email as {category_raw or 'unknown'}."

        return LLMRiskOutput(
            risk_score=risk_score,
            risk_reasons=[reason],
            description=description,
        )

