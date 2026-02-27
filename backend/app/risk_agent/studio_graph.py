import os

from backend.app.risk_agent.graph import EmailRiskGraph, normalize_decision_mode
from backend.app.risk_agent.llm import RiskLLMScorer


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def build_graph():
    threshold = float(os.getenv("RISK_THRESHOLD", "0.65"))
    model_version = os.getenv("RISK_MODEL_VERSION", "risk-agent-v1")
    llm_model = os.getenv("RISK_LLM_MODEL", "gpt-4.1-mini")
    llm_enabled = _env_bool("RISK_LLM_ENABLED", True)
    decision_mode = normalize_decision_mode(os.getenv("RISK_DECISION_MODE", "hybrid"))
    fail_closed = _env_bool("RISK_FAIL_CLOSED", False)

    risk_graph = EmailRiskGraph(
        threshold=threshold,
        model_version=model_version,
        llm_scorer=RiskLLMScorer(model=llm_model, enabled=llm_enabled),
        decision_mode=decision_mode,
        fail_closed=fail_closed,
    )
    return risk_graph.compiled_graph


graph = build_graph()
