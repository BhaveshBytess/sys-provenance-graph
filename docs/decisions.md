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
Date: 2026-04-06
Context: Establish baseline architecture and governance flow for System Behavior Analyzer.
Decision: Follow governance hierarchy and contract-first implementation.
Consequence: Safer changes, more explicit tradeoffs, slower but reliable evolution.
Status: Accepted

---

## D002: Standards Alignment Baseline
Date: 2026-04-06
Context: Define external references for secure SDLC and decision traceability.
Decision: Align governance language and controls with SSDF, SLSA, and ADR practices.
Consequence: Better auditability and clearer quality/security gates.
Status: Accepted

---

## D003: Migrate to 7-file Governance Framework
Date: 2026-04-06
Context: Legacy governance was split across top-level files with overlapping concerns.
Decision: Consolidate workflow governance into root `active_context.md` and `docs/*.md` generated from `governance/templates`.
Consequence: Clear authority hierarchy, reusable templates, and easier governance reuse across projects.
Status: Accepted

---

## D004: Retire Legacy Workflow Documents
Date: 2026-04-06
Context: Legacy workflow files (`agent.md`, `CONTRACTS.md`, `EXECUTION_PLAN.md`, `STARTING_PROMPT.md`) were superseded by the new framework.
Decision: Remove superseded legacy workflow files after migrating relevant policy content into 7-file governance docs.
Consequence: Reduced confusion and single source of governance truth in `active_context.md` and `docs/`.
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
