from typing import Any, Literal, TypedDict


class EmailRiskState(TypedDict, total=False):
    email: dict[str, Any]
    features: dict[str, Any]
    extracted_links: list[dict[str, str]]
    links_found: int
    links_scanned: int
    link_results: list[dict[str, Any]]
    link_risk_score: float | None
    link_risk_flags: list[str]
    link_force_quarantine: bool
    link_scan_failed_closed: bool
    risk_score: float
    risk_reasons: list[str]
    description: str
    decision: Literal["quarantine", "deliver"]
    status: Literal["pending_human_review", "released"]
    model_version: str
