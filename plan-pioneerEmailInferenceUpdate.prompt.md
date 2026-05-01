## Plan: Switch Email Inference to Pioneer HTTP API (DRAFT)

This plan replaces the email LLM call path with direct HTTP inference while preserving the existing scorer contract and graph fallback behavior. The safest minimal path is to keep the existing scorer interface unchanged (RiskLLMScorer.score → LLMRiskOutput), swap internals to POST to the Pioneer endpoint, and keep llm_disabled / llm_unavailable semantics so the decision-mode fallback in the graph remains intact. Your selected endpoint is https://api.pioneer.ai/inference, and the model_id to send is https://api.pioneer.ai/gliner-2. The provided API token should be stored in environment configuration only (not committed), and referenced via a new env variable.

**Steps**
1. Update scorer internals in [backend/app/risk_agent/llm.py](backend/app/risk_agent/llm.py) (RiskLLMScorer.__init__, RiskLLMScorer.score) to call Pioneer inference HTTP API with Bearer auth, model_id payload, timeout, response parsing, and existing exception mapping.
2. Preserve all upstream wiring in [backend/app/risk_agent/service.py](backend/app/risk_agent/service.py) and [backend/app/risk_agent/studio_graph.py](backend/app/risk_agent/studio_graph.py) so constructor and graph behavior stay unchanged.
3. Add and document env configuration in [.env.example](.env.example), [README.md](README.md), and [WEBAPP.md](WEBAPP.md): RISK_LLM_API_URL=https://api.pioneer.ai/inference, RISK_LLM_API_TOKEN=(secret), RISK_LLM_MODEL=https://api.pioneer.ai/gliner-2, optional RISK_LLM_TIMEOUT_SECONDS.
4. Add URL and transport safety validation in scorer initialization (absolute https URL, no embedded credentials, bounded timeout, predictable error mapping to llm_unavailable).
5. Add focused scorer tests for HTTP success/failure/timeout/invalid payload handling, and keep existing graph/service tests unchanged except for any env fixture updates in [tests/test_risk_service.py](tests/test_risk_service.py), [tests/test_risk_graph.py](tests/test_risk_graph.py), and [tests/test_api_risk.py](tests/test_api_risk.py).

**Verification**
- Run targeted tests first: pytest tests/test_risk_graph.py tests/test_risk_service.py tests/test_api_risk.py
- Run scorer-focused tests after adding them: pytest tests/test_risk_llm.py
- Run broader risk suite: pytest tests/test_risk_*.py
- Manual API smoke check via existing backend endpoint to confirm llm_unavailable fallback still behaves per decision mode.

**Decisions**
- Chose minimal internal replacement in [backend/app/risk_agent/llm.py](backend/app/risk_agent/llm.py) over graph/service rewiring to reduce blast radius.
- Chose to retain existing scorer interface and error semantics for compatibility with [backend/app/risk_agent/graph.py](backend/app/risk_agent/graph.py).
- Chose env-driven secret management for API token and avoided embedding credentials in code or docs.
