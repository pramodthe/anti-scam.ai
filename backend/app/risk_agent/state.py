from typing import Any, Literal, TypedDict


class EmailRiskState(TypedDict, total=False):
    email: dict[str, Any]
    features: dict[str, Any]
    risk_score: float
    risk_reasons: list[str]
    description: str
    decision: Literal["quarantine", "deliver"]
    status: Literal["pending_human_review", "released"]
    model_version: str

