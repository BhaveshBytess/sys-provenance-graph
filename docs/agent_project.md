# agent_project.md - Project Constraints and Domain Rules

## 1. Project Context

Project: System Behavior Analyzer

Purpose:
- Analyze Sysmon process-create telemetry to detect baseline deviations.

Operator goals:
- Detect unknown and statistically rare process relationships.
- Preserve explainability through causal chain reconstruction.
- Produce machine-consumable reports for CLI and API consumers.

Expected outcomes:
- Valid canonical events as analysis input.
- Deterministic analysis behavior for equivalent inputs.
- Contract-compliant analysis reports.

---

## 2. Non-Negotiable Constraints

- Budget constraints: No external ML/graph stack for V1.
- Runtime constraints: Python 3.10+; batch analysis mode.
- Service/API constraints: FastAPI + Typer wrappers only; no core logic in interfaces.
- Security/secrets constraints: No hardcoded secrets; no raw sensitive telemetry in logs.
- Data retention and privacy constraints: Baseline/report artifacts only; avoid unnecessary PII exposure.
- Determinism and explainability constraints: Every anomaly must have a clear textual rationale and chain.

---

## 3. Domain Rules

- Target selection rules: Analyze only process-create events (Sysmon EventId 1 in V1).
- Safety and compliance rules: Reject malformed or unsupported events early.
- Communication/content rules: Reports are factual and non-interpretive.
- Dedup/retry rules: Baseline relationships are frequency-counted tuples.
- Severity/risk mapping rules: Unknown -> CRITICAL; rare -> HIGH/MEDIUM by thresholds.
- Identity and lineage rules: Process identity is GUID-based; PID is informational only.

---

## 4. Out of Scope

- Malware classification labels.
- Real-time streaming and distributed pipeline orchestration.
- UI/visualization layers.
- Database-backed persistence in V1.
- Hardcoded signature rules replacing baseline deviation logic.

---

## 5. Operational Guardrails

- Define production safety thresholds: configurable rarity thresholds in analyzer module.
- Define fallback behavior: if baseline unavailable, API returns service unavailable.
- Define stop conditions: stop and escalate when contract ambiguity or repeated unresolved failure occurs.

---

## 6. Interfaces and Ownership

- Core logic ownership: `src/core`.
- API ownership: `src/api` as transport and validation boundary.
- CLI ownership: `src/cli` as operator interface.
- Persistence/storage ownership: baseline JSON and report JSON artifacts.

---

## 7. Validation Policy

- Minimum required tests per change: at least one unit test for each new behavior in core path.
- Required checks before merge: contract compliance checks and relevant test suite pass.
- Failure-handling policy for invalid input: fail fast with specific exceptions/status codes.
