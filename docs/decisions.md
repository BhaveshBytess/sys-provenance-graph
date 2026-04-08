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

## D005: Mordor Validation with Explicit Dataset Arguments
Date: 2026-04-09
Context: `examples/mordor` now contains generated report `.json` files in addition to source JSONL telemetry files.
Decision: Perform validation using explicit dataset arguments for `scripts/mordor_smoke_test.py` and `scripts/mordor_split_test.py` to ensure JSONL inputs are used.
Consequence: Validation remains reliable while default auto-selection behavior in smoke script is documented as a caveat.
Status: Accepted
Owners: Maintainers
Alternatives considered:
- Option A: Keep relying on default auto-selection in smoke script.
- Option B: Explicitly pass source JSONL paths during validation.
Validation evidence:
- `python -m pytest -q tests/test_mordor_adapter.py` -> 5 passed
- `python scripts/mordor_smoke_test.py --baseline-file ... --test-file ...` -> pass
- `python scripts/mordor_split_test.py --input-file ...` -> pass

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
