from typing import Any

from langgraph.graph import END, StateGraph

from backend.app.risk_agent.llm import RiskLLMScorer
from backend.app.risk_agent.rules import extract_features, score_features
from backend.app.risk_agent.state import EmailRiskState


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def combine_scores(rules_score: float, llm_score: float) -> float:
    score = (0.4 * rules_score) + (0.6 * llm_score)
    return min(max(score, 0.0), 1.0)


def decision_from_score(risk_score: float, threshold: float) -> str:
    return "quarantine" if risk_score >= threshold else "deliver"


class EmailRiskGraph:
    def __init__(self, threshold: float, model_version: str, llm_scorer: RiskLLMScorer) -> None:
        self.threshold = threshold
        self.model_version = model_version
        self.llm_scorer = llm_scorer
        self._graph = self._build_graph()

    def _build_graph(self) -> Any:
        workflow = StateGraph(EmailRiskState)
        workflow.add_node("extract_features", self._extract_features_node)
        workflow.add_node("score_risk", self._score_risk_node)
        workflow.add_node("quarantine", self._quarantine_node)
        workflow.add_node("deliver", self._deliver_node)
        workflow.set_entry_point("extract_features")
        workflow.add_edge("extract_features", "score_risk")
        workflow.add_conditional_edges(
            "score_risk",
            self._route_node,
            {"quarantine": "quarantine", "deliver": "deliver"},
        )
        workflow.add_edge("quarantine", END)
        workflow.add_edge("deliver", END)
        return workflow.compile()

    @staticmethod
    def _extract_features_node(state: EmailRiskState) -> EmailRiskState:
        email = state["email"]
        return {"features": extract_features(email)}

    def _score_risk_node(self, state: EmailRiskState) -> EmailRiskState:
        email = state["email"]
        features = state["features"]
        rules_score, rules_reasons, rules_description = score_features(features)

        llm_score = rules_score
        llm_reasons: list[str] = []
        llm_description = ""
        llm_failed = False

        try:
            llm_result = self.llm_scorer.score(email=email, features=features)
            llm_score = llm_result.risk_score
            llm_reasons = llm_result.risk_reasons
            llm_description = llm_result.description
        except Exception:
            llm_failed = True
            llm_reasons = ["llm_unavailable"]

        final_score = rules_score if llm_failed else combine_scores(rules_score, llm_score)
        reasons = _dedupe(rules_reasons + llm_reasons)
        description = llm_description.strip() or rules_description
        decision = decision_from_score(final_score, self.threshold)
        status = "pending_human_review" if decision == "quarantine" else "released"

        return {
            "risk_score": final_score,
            "risk_reasons": reasons,
            "description": description,
            "decision": decision,
            "status": status,
            "model_version": self.model_version,
        }

    @staticmethod
    def _route_node(state: EmailRiskState) -> str:
        return str(state["decision"])

    @staticmethod
    def _quarantine_node(state: EmailRiskState) -> EmailRiskState:
        return {"status": "pending_human_review"}

    @staticmethod
    def _deliver_node(state: EmailRiskState) -> EmailRiskState:
        return {"status": "released"}

    def evaluate(self, email: dict[str, Any]) -> dict[str, Any]:
        result: EmailRiskState = self._graph.invoke({"email": email})
        return {
            "id": email.get("id", ""),
            "decision": result["decision"],
            "risk_score": float(result["risk_score"]),
            "risk_reasons": list(result["risk_reasons"]),
            "description": str(result["description"]),
            "model_version": str(result["model_version"]),
            "status": str(result["status"]),
        }

    @property
    def compiled_graph(self) -> Any:
        return self._graph
