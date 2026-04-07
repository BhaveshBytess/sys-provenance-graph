# active_context.md - Session Control

## Instructions

Paste this file at the beginning of every coding session.
Before pasting, update Current Focus.

This file is the session entrypoint. Other governance docs are referenced by name.

Normative terms (MUST, MUST NOT, SHOULD, MAY) follow RFC 2119 usage.

---

## Role

You are a professional engineer implementing a pre-designed system.

You must follow governance in this order:

1. `docs/contracts.md`
2. `docs/agent_project.md`
3. `docs/agent_core.md`
4. `docs/build_plan.md`
5. `docs/decisions.md`
6. `docs/state.md`

Conflict resolution is absolute:
`contracts.md > agent_project.md > agent_core.md > build_plan.md > code`

---

## Project Summary

Project: System Behavior Analyzer

This project detects anomalous operating system behavior from Sysmon process
creation telemetry by learning a statistical baseline of parent-child-user
relationships and flagging deviations with explainable parent GUID chains.
The system is backend-only (CLI and API), deterministic by contract, and
designed for strict schema enforcement and auditability.

Security posture:
- Treat all external input as untrusted by default.
- Preserve deterministic behavior for reproducibility.
- Keep auditability of decisions and changes.

---

## Current State

Current Module: Module 8 - Governance Migration
Completed: Modules 0-7 implemented; governance migration in progress.
Known Issues: Determinism drift in runtime IDs/timestamps still open.
Open Decisions: None pending for current session.

---

## Current Focus

Task: Integrate 7-file governance framework

What exists:
- Full analysis engine implemented in `src/core`.
- CLI and FastAPI wrappers implemented and tested.
- Governance templates and scaffold script implemented in `governance`.

What must happen this session:
- Replace legacy workflow docs with 7-file governance framework.
- Preserve contractual and execution discipline from legacy docs.
- Update repository references to the new governance locations.
- Remove superseded legacy workflow docs after migration.

Relevant contract sections:
- `docs/contracts.md` section 3 (canonical input contract)
- `docs/contracts.md` section 4 (analysis report contract)
- `docs/contracts.md` section 5 (core invariants)

Constraints:
- No architecture changes without explicit approval.
- No new dependency unless justified and approved.
- Preserve scope discipline.
- Changes MUST keep contracts and tests aligned.

---

## Session Rules

1. Work only on current focus.
2. Do not refactor unrelated code.
3. Validate changes with tests/runtime checks.
4. Update `docs/state.md` when session ends.
5. Update `docs/decisions.md` for any non-obvious new decision.
6. Record evidence for critical changes (test output, reasoning, references).

---

## Human Checklist

- [ ] Run tests locally
- [ ] Verify behavior manually if needed
- [ ] Update `docs/state.md`
- [ ] Update `docs/decisions.md` (if needed)
- [ ] Commit and push
- [ ] Confirm legacy workflow files are removed
