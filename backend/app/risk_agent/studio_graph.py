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
    link_scan_enabled = _env_bool("RISK_LINK_SCAN_ENABLED", True)
    link_scan_max_urls = int(os.getenv("RISK_LINK_SCAN_MAX_URLS", "3"))
    link_scan_timeout_seconds = int(os.getenv("RISK_LINK_SCAN_TIMEOUT_SECONDS", "20"))
    link_scan_fail_closed = _env_bool("RISK_LINK_SCAN_FAIL_CLOSED", True)
    link_scan_allow_http = _env_bool("RISK_LINK_SCAN_ALLOW_HTTP", False)
    yutori_browse_max_steps = int(os.getenv("YUTORI_BROWSE_MAX_STEPS", "20"))

    risk_graph = EmailRiskGraph(
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
    return risk_graph.compiled_graph


graph = build_graph()
