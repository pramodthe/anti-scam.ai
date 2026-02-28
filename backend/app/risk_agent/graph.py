from email.utils import parseaddr
from typing import Any

from langgraph.graph import END, StateGraph

from backend.app.risk_agent.link_scoring import LinkRiskAssessment, assess_link_risk
from backend.app.risk_agent.links import ExtractedLink, extract_links_from_email
from backend.app.risk_agent.llm import RiskLLMScorer
from backend.app.risk_agent.rules import extract_features, score_features
from backend.app.risk_agent.ssl_check import check_ssl_certificate
from backend.app.risk_agent.state import EmailRiskState
from backend.app.risk_agent.yutori_client import YutoriBrowserClient
from backend.app.schemas import LinkScanResult


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _sender_domain(from_email: str) -> str:
    _, addr = parseaddr(from_email)
    sender = (addr or from_email).lower().strip()
    if "@" not in sender:
        return ""
    return sender.split("@", maxsplit=1)[1]


def combine_scores(rules_score: float, llm_score: float) -> float:
    score = (0.4 * rules_score) + (0.6 * llm_score)
    return min(max(score, 0.0), 1.0)


def decision_from_score(risk_score: float, threshold: float) -> str:
    return "quarantine" if risk_score >= threshold else "deliver"


def normalize_decision_mode(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in {"rules_only", "hybrid", "llm_only"}:
        return normalized
    return "hybrid"


class EmailRiskGraph:
    def __init__(
        self,
        threshold: float,
        model_version: str,
        llm_scorer: RiskLLMScorer,
        decision_mode: str = "hybrid",
        fail_closed: bool = False,
        link_scan_enabled: bool = False,
        link_scan_max_urls: int = 3,
        link_scan_timeout_seconds: int = 20,
        link_scan_fail_closed: bool = True,
        link_scan_allow_http: bool = False,
        yutori_browse_max_steps: int = 20,
        yutori_client: YutoriBrowserClient | None = None,
    ) -> None:
        self.threshold = threshold
        self.model_version = model_version
        self.llm_scorer = llm_scorer
        self.decision_mode = normalize_decision_mode(decision_mode)
        self.fail_closed = fail_closed
        self.link_scan_enabled = link_scan_enabled
        self.link_scan_max_urls = max(1, link_scan_max_urls)
        self.link_scan_timeout_seconds = max(1, link_scan_timeout_seconds)
        self.link_scan_fail_closed = link_scan_fail_closed
        self.link_scan_allow_http = link_scan_allow_http
        self.yutori_client = yutori_client or YutoriBrowserClient.from_env(
            timeout_seconds=self.link_scan_timeout_seconds,
            browse_max_steps=max(1, yutori_browse_max_steps),
        )
        self._graph = self._build_graph()

    def _build_graph(self) -> Any:
        workflow = StateGraph(EmailRiskState)
        workflow.add_node("extract_features", self._extract_features_node)
        workflow.add_node("extract_links", self._extract_links_node)
        workflow.add_node("scan_links", self._scan_links_node)
        workflow.add_node("score_risk", self._score_risk_node)
        workflow.add_node("quarantine", self._quarantine_node)
        workflow.add_node("deliver", self._deliver_node)
        workflow.set_entry_point("extract_features")
        workflow.add_edge("extract_features", "extract_links")
        workflow.add_edge("extract_links", "scan_links")
        workflow.add_edge("scan_links", "score_risk")
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

    def _extract_links_node(self, state: EmailRiskState) -> EmailRiskState:
        email = state["email"]
        extracted_links, links_found = extract_links_from_email(
            email=email,
            max_urls=self.link_scan_max_urls,
            allow_http=self.link_scan_allow_http,
        )
        serialized = [
            {"original_url": item.original_url, "normalized_url": item.normalized_url}
            for item in extracted_links
        ]
        return {"extracted_links": serialized, "links_found": links_found}

    def _scan_one_link(self, sender_domain: str, extracted: ExtractedLink) -> LinkScanResult:
        yutori = self.yutori_client.scan_url(url=extracted.normalized_url, sender_domain=sender_domain)
        ssl_target = yutori.final_url or extracted.normalized_url
        ssl_result = check_ssl_certificate(url=ssl_target, timeout_seconds=float(self.link_scan_timeout_seconds))

        risk_flags = list(yutori.risk_flags)
        if ssl_result.error:
            risk_flags.append(ssl_result.error)

        return LinkScanResult(
            original_url=extracted.original_url,
            normalized_url=extracted.normalized_url,
            final_url=yutori.final_url,
            reachable=yutori.reachable,
            http_status=yutori.http_status,
            ssl_valid=ssl_result.ssl_valid,
            ssl_issuer=ssl_result.ssl_issuer,
            ssl_subject=ssl_result.ssl_subject,
            ssl_expires_at=ssl_result.ssl_expires_at,
            ssl_hostname_match=ssl_result.ssl_hostname_match,
            yutori_verdict=yutori.verdict,  # type: ignore[arg-type]
            yutori_summary=yutori.summary,
            yutori_provider=yutori.provider,
            yutori_executed=yutori.executed,
            yutori_task_id=yutori.task_id,
            yutori_preview_url=yutori.preview_url,
            yutori_details=yutori.details,
            risk_flags=_dedupe(risk_flags),
            scan_status=yutori.scan_status,  # type: ignore[arg-type]
        )

    def _scan_links_node(self, state: EmailRiskState) -> EmailRiskState:
        if not self.link_scan_enabled:
            return {
                "links_scanned": 0,
                "link_results": [],
                "link_risk_score": None,
                "link_risk_flags": [],
                "link_force_quarantine": False,
                "link_scan_failed_closed": False,
            }

        email = state["email"]
        sender_domain = _sender_domain(str(email.get("from_email", "")))
        extracted = [
            ExtractedLink(original_url=item["original_url"], normalized_url=item["normalized_url"])
            for item in state.get("extracted_links", [])
        ]
        link_results = [self._scan_one_link(sender_domain=sender_domain, extracted=item) for item in extracted]
        assessment = assess_link_risk(link_results=link_results, fail_closed=self.link_scan_fail_closed)
        return {
            "links_scanned": len(link_results),
            "link_results": [item.model_dump() for item in link_results],
            "link_risk_score": assessment.risk_score,
            "link_risk_flags": assessment.risk_flags,
            "link_force_quarantine": assessment.force_quarantine,
            "link_scan_failed_closed": assessment.failed_closed,
        }

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

        if self.decision_mode == "rules_only":
            base_score = rules_score
        elif self.decision_mode == "llm_only":
            if llm_failed and self.fail_closed:
                base_score = 1.0
                llm_reasons.append("fail_closed")
                llm_description = "LLM unavailable; quarantined by fail-closed policy."
            else:
                base_score = rules_score if llm_failed else llm_score
        else:
            base_score = rules_score if llm_failed else combine_scores(rules_score, llm_score)

        link_risk_score = state.get("link_risk_score")
        final_score = base_score
        if link_risk_score is not None:
            final_score = max(base_score, float(link_risk_score))

        link_flags = state.get("link_risk_flags", [])
        reasons = _dedupe(rules_reasons + llm_reasons + list(link_flags))
        description = llm_description.strip() or rules_description

        if state.get("link_force_quarantine", False):
            decision = "quarantine"
        else:
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
            "links_found": int(result.get("links_found", 0)),
            "links_scanned": int(result.get("links_scanned", 0)),
            "link_results": list(result.get("link_results", [])),
            "link_risk_score": result.get("link_risk_score"),
            "link_scan_failed_closed": bool(result.get("link_scan_failed_closed", False)),
        }

    def evaluate_links(
        self,
        sender_email: str,
        subject: str,
        body: str,
        urls: list[str] | None = None,
    ) -> tuple[list[LinkScanResult], LinkRiskAssessment]:
        if not self.link_scan_enabled:
            return [], assess_link_risk(link_results=[], fail_closed=self.link_scan_fail_closed)

        email = {
            "id": "link-eval",
            "thread_id": "link-eval",
            "from_email": sender_email,
            "to_email": "",
            "subject": subject,
            "body": body,
            "send_time": "",
            "headers": None,
        }
        extracted_links, _ = extract_links_from_email(
            email=email,
            max_urls=self.link_scan_max_urls,
            allow_http=self.link_scan_allow_http,
            explicit_urls=urls,
        )
        sender_domain = _sender_domain(sender_email)
        results = [self._scan_one_link(sender_domain=sender_domain, extracted=item) for item in extracted_links]
        assessment = assess_link_risk(link_results=results, fail_closed=self.link_scan_fail_closed)
        return results, assessment

    @property
    def compiled_graph(self) -> Any:
        return self._graph
