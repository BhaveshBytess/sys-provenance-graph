# decisions.md - Architecture Decision Records

## Purpose

Tracks non-obvious technical decisions, rationale, and consequences.
Use one record per significant decision.

Status values:
- Accepted
- Superseded by DXXX
- Rejected
- Proposed

---

## D001: Initial Architecture Baseline
Date: {{TODAY}}
Context: Establish baseline architecture and governance flow for {{PROJECT_NAME}}.
Decision: Follow governance hierarchy and contract-first implementation.
Consequence: Safer changes, more explicit tradeoffs, slower but reliable evolution.
Status: Accepted

---

## D002: Standards Alignment Baseline
Date: {{TODAY}}
Context: Define external references for secure SDLC and decision traceability.
Decision: Align governance language and controls with SSDF, SLSA, and ADR practices.
Consequence: Better auditability and clearer quality/security gates.
Status: Accepted

---

## Template For New Decisions

## DXXX: Title
Date: YYYY-MM-DD
Context: Why this decision is needed.
Decision: What was chosen.
Consequence: Tradeoffs and impact.
Status: Accepted | Superseded by DXXX | Rejected
Owners: Team or role accountable.
Alternatives considered:
- Option A:
- Option B:
Validation evidence:
- Tests, metrics, or review outcomes.
