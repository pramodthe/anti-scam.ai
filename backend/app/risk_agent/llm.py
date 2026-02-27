import os
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field


class LLMRiskOutput(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=1.0)
    risk_reasons: list[str] = Field(default_factory=list)
    description: str = Field(default="")


class RiskLLMScorer:
    def __init__(self, model: str, enabled: bool) -> None:
        self.model = model
        self.enabled = enabled
        self._client: ChatOpenAI | None = None

        if not enabled:
            return
        if not os.getenv("OPENAI_API_KEY"):
            return

        self._client = ChatOpenAI(model=model, temperature=0)

    def score(self, email: dict[str, Any], features: dict[str, Any]) -> LLMRiskOutput:
        if not self.enabled:
            raise RuntimeError("llm_disabled")
        if self._client is None:
            raise RuntimeError("llm_unavailable")

        structured = self._client.with_structured_output(LLMRiskOutput)
        messages = [
            SystemMessage(
                content=(
                    "You are an email scam detection assistant. "
                    "Return a risk score from 0.0 to 1.0, concise reasons, and a one-line description."
                )
            ),
            HumanMessage(
                content=(
                    "Evaluate this email.\n"
                    f"Email: {email}\n"
                    f"Derived features: {features}\n"
                    "Focus on phishing, impersonation, credential theft, and payment fraud patterns."
                )
            ),
        ]

        return structured.invoke(messages)

