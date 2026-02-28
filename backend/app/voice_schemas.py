"""Pydantic schemas for the Voice Threat Monitor feature."""

from typing import Any, Literal

from pydantic import BaseModel, Field


VoiceDecision = Literal["safe", "suspicious", "threat"]
VoiceSignalType = Literal["pii", "emotion", "scam_pattern", "urgency", "credential_phishing", "payment_fraud"]


class VoiceUtterance(BaseModel):
    """A single transcribed utterance from Velma-2."""

    utterance_uuid: str = ""
    text: str = ""
    speaker: int = 0
    emotion: str = "neutral"
    accent: str | None = None
    start_ms: int = 0
    duration_ms: int = 0
    language: str = "en"
    pii_detected: bool = False
    pii_tags: list[str] = Field(default_factory=list)


class VoiceRiskSignal(BaseModel):
    """An individual risk signal detected during voice analysis."""

    timestamp_ms: int = 0
    signal_type: VoiceSignalType
    detail: str
    severity: float = Field(0.0, ge=0.0, le=1.0)


class VoiceRiskUpdate(BaseModel):
    """Sent to the client on each utterance with running risk state."""

    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    decision: VoiceDecision = "safe"
    risk_reasons: list[str] = Field(default_factory=list)
    alerts: list[VoiceRiskSignal] = Field(default_factory=list)


class VoiceAnalysisResult(BaseModel):
    """Full analysis result returned by the batch /voice/analyze endpoint."""

    transcript_text: str = ""
    utterances: list[VoiceUtterance] = Field(default_factory=list)
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    risk_reasons: list[str] = Field(default_factory=list)
    alerts: list[VoiceRiskSignal] = Field(default_factory=list)
    decision: VoiceDecision = "safe"
    duration_ms: int = 0
    speaker_count: int = 0
    emotions_detected: list[str] = Field(default_factory=list)


class VoiceSessionSummary(BaseModel):
    """Aggregated summary sent when a streaming session ends."""

    session_duration_ms: int = 0
    total_utterances: int = 0
    transcript_text: str = ""
    risk_score: float = Field(0.0, ge=0.0, le=1.0)
    decision: VoiceDecision = "safe"
    risk_reasons: list[str] = Field(default_factory=list)
    alerts: list[VoiceRiskSignal] = Field(default_factory=list)
    speaker_count: int = 0
    emotions_detected: list[str] = Field(default_factory=list)


# ── WebSocket message envelope ──────────────────────────────────────────

class WSMessage(BaseModel):
    """Envelope for all WebSocket messages sent from server to client."""

    type: Literal["utterance", "alert", "risk_update", "session_summary", "error", "connected"]
    data: dict[str, Any] = Field(default_factory=dict)
