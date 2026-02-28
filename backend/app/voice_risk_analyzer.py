"""Voice risk analyzer — reuses the email rule engine on voice transcripts.

Applies the same keyword/pattern detections from risk_agent.rules to transcribed
text, and layers on voice-specific signals (emotion, PII/PHI) from Velma-2.
"""

from __future__ import annotations

from backend.app.modulate_client import ModulateUtterance
from backend.app.risk_agent.rules import (
    CREDENTIAL_KEYWORDS,
    IMPERSONATION_KEYWORDS,
    PAYMENT_KEYWORDS,
    PROMO_SCAM_KEYWORDS,
    URGENCY_KEYWORDS,
)
from backend.app.voice_schemas import (
    VoiceAnalysisResult,
    VoiceDecision,
    VoiceRiskSignal,
    VoiceRiskUpdate,
    VoiceUtterance,
)

# Emotions that suggest coercion, pressure, or social engineering
HIGH_RISK_EMOTIONS = {"angry", "fearful", "urgent", "aggressive", "distressed"}
MODERATE_RISK_EMOTIONS = {"anxious", "frustrated", "nervous", "sad"}

QUARANTINE_THRESHOLD = 0.65
THREAT_THRESHOLD = 0.85


def _decision_for_score(score: float) -> VoiceDecision:
    if score >= THREAT_THRESHOLD:
        return "threat"
    if score >= QUARANTINE_THRESHOLD:
        return "suspicious"
    return "safe"


class VoiceRiskAnalyzer:
    """Stateful analyzer that accumulates transcript text and scores risk."""

    def __init__(self) -> None:
        self.running_transcript: str = ""
        self.utterances: list[VoiceUtterance] = []
        self.alerts: list[VoiceRiskSignal] = []
        self.risk_reasons: set[str] = set()
        self._emotions_seen: set[str] = set()
        self._speakers_seen: set[int] = set()

    # ── Per-utterance processing (streaming) ────────────────────────────

    def process_utterance(self, utt: ModulateUtterance) -> VoiceRiskUpdate:
        """Ingest one utterance, update running state, return risk update."""
        self.running_transcript += f" {utt.text}"
        self._speakers_seen.add(utt.speaker)

        voice_utt = VoiceUtterance(
            utterance_uuid=utt.utterance_uuid,
            text=utt.text,
            speaker=utt.speaker,
            emotion=utt.emotion,
            accent=utt.accent,
            start_ms=utt.start_ms,
            duration_ms=utt.duration_ms,
            language=utt.language,
        )
        self.utterances.append(voice_utt)

        new_alerts = self._check_utterance(utt)
        self.alerts.extend(new_alerts)

        score = self._compute_score()
        decision = _decision_for_score(score)

        return VoiceRiskUpdate(
            risk_score=score,
            decision=decision,
            risk_reasons=sorted(self.risk_reasons),
            alerts=new_alerts,
        )

    def _check_utterance(self, utt: ModulateUtterance) -> list[VoiceRiskSignal]:
        """Check a single utterance for risk signals."""
        alerts: list[VoiceRiskSignal] = []
        text_lower = utt.text.lower()
        emotion_lower = utt.emotion.lower() if utt.emotion else ""

        # ── Voice-specific: Emotion signals ─────────────────────────────
        if emotion_lower:
            self._emotions_seen.add(emotion_lower)
        if emotion_lower in HIGH_RISK_EMOTIONS:
            self.risk_reasons.add("high_risk_emotion")
            alerts.append(VoiceRiskSignal(
                timestamp_ms=utt.start_ms,
                signal_type="emotion",
                detail=f"High-risk emotion detected: {utt.emotion}",
                severity=0.3,
            ))
        elif emotion_lower in MODERATE_RISK_EMOTIONS:
            self.risk_reasons.add("elevated_emotion")
            alerts.append(VoiceRiskSignal(
                timestamp_ms=utt.start_ms,
                signal_type="emotion",
                detail=f"Elevated emotion detected: {utt.emotion}",
                severity=0.15,
            ))

        # ── Voice-specific: PII/PHI mentions ────────────────────────────
        pii_keywords = {"social security", "ssn", "date of birth", "credit card",
                        "bank account", "routing number", "medical record", "insurance id"}
        for kw in pii_keywords:
            if kw in text_lower:
                voice_utt = self.utterances[-1] if self.utterances else None
                if voice_utt and not voice_utt.pii_detected:
                    voice_utt.pii_detected = True
                    voice_utt.pii_tags.append(kw)
                self.risk_reasons.add("pii_mention")
                alerts.append(VoiceRiskSignal(
                    timestamp_ms=utt.start_ms,
                    signal_type="pii",
                    detail=f"PII/PHI keyword detected: '{kw}'",
                    severity=0.4,
                ))

        # ── Reused email rules on transcript text ───────────────────────
        if any(kw in text_lower for kw in URGENCY_KEYWORDS):
            self.risk_reasons.add("urgency_language")
            alerts.append(VoiceRiskSignal(
                timestamp_ms=utt.start_ms,
                signal_type="urgency",
                detail="Urgency language detected in speech",
                severity=0.15,
            ))

        if any(kw in text_lower for kw in CREDENTIAL_KEYWORDS):
            self.risk_reasons.add("credential_phishing_pattern")
            alerts.append(VoiceRiskSignal(
                timestamp_ms=utt.start_ms,
                signal_type="credential_phishing",
                detail="Credential phishing pattern detected in speech",
                severity=0.25,
            ))

        if any(kw in text_lower for kw in PAYMENT_KEYWORDS):
            self.risk_reasons.add("payment_request_pattern")
            alerts.append(VoiceRiskSignal(
                timestamp_ms=utt.start_ms,
                signal_type="payment_fraud",
                detail="Payment fraud pattern detected in speech",
                severity=0.20,
            ))

        if any(kw in text_lower for kw in PROMO_SCAM_KEYWORDS):
            self.risk_reasons.add("promo_lure_pattern")
            alerts.append(VoiceRiskSignal(
                timestamp_ms=utt.start_ms,
                signal_type="scam_pattern",
                detail="Promotional scam pattern detected in speech",
                severity=0.35,
            ))

        if any(kw in text_lower for kw in IMPERSONATION_KEYWORDS):
            self.risk_reasons.add("impersonation_pattern")
            alerts.append(VoiceRiskSignal(
                timestamp_ms=utt.start_ms,
                signal_type="scam_pattern",
                detail="Impersonation pattern detected in speech",
                severity=0.10,
            ))

        return alerts

    def _compute_score(self) -> float:
        """Compute aggregated risk score from all reasons (mirrors rules.score_features)."""
        score = 0.0
        if "urgency_language" in self.risk_reasons:
            score += 0.15
        if "promo_lure_pattern" in self.risk_reasons:
            score += 0.35
        if "credential_phishing_pattern" in self.risk_reasons:
            score += 0.25
        if "payment_request_pattern" in self.risk_reasons:
            score += 0.20
        if "impersonation_pattern" in self.risk_reasons:
            score += 0.10
        if "pii_mention" in self.risk_reasons:
            score += 0.30
        if "high_risk_emotion" in self.risk_reasons:
            score += 0.20
        if "elevated_emotion" in self.risk_reasons:
            score += 0.10
        return min(score, 1.0)

    # ── Full transcript analysis (batch) ────────────────────────────────

    def analyze_full(
        self,
        transcript_text: str,
        utterances: list[ModulateUtterance],
        duration_ms: int = 0,
    ) -> VoiceAnalysisResult:
        """Analyze a complete transcript at once (used by batch endpoint)."""
        for utt in utterances:
            self.process_utterance(utt)

        score = self._compute_score()
        decision = _decision_for_score(score)

        return VoiceAnalysisResult(
            transcript_text=self.running_transcript.strip(),
            utterances=self.utterances,
            risk_score=score,
            risk_reasons=sorted(self.risk_reasons),
            alerts=self.alerts,
            decision=decision,
            duration_ms=duration_ms,
            speaker_count=len(self._speakers_seen),
            emotions_detected=sorted(self._emotions_seen),
        )

    # ── Session summary (streaming) ─────────────────────────────────────

    def get_session_summary(self) -> dict:
        """Return a summary dict suitable for the session_summary WS message."""
        score = self._compute_score()
        return {
            "total_utterances": len(self.utterances),
            "transcript_text": self.running_transcript.strip(),
            "risk_score": score,
            "decision": _decision_for_score(score),
            "risk_reasons": sorted(self.risk_reasons),
            "alerts": [a.model_dump() for a in self.alerts],
            "speaker_count": len(self._speakers_seen),
            "emotions_detected": sorted(self._emotions_seen),
        }
