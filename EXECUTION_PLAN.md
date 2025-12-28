# What this document is (important framing)

**Name:** `EXECUTION_PLAN.md`
**Audience:** Agent (primary), Human (secondary)
**Purpose:** Enforce *modular, phased execution* with verification gates
**Authority:**

* Below `agent.md`
* Below `CONTRACTS.md`
* Below `SPEC.md`
* Above all implementation

If there is a conflict:

* `CONTRACTS.md` wins
* then `SPEC.md`
* then `EXECUTION_PLAN.md`

---

# Design principles of this execution plan

This document enforces:

* **One phase at a time**
* **Explicit stop points**
* **Verification before progress**
* **No parallel implementation**
* **No scope creep**

It is intentionally **strict**.

---

# Execution Plan — Phased Implementation Strategy

## Purpose

This document defines the **mandatory execution order** for implementing the
System Behavior Analyzer.

The system must be built **incrementally**, one phase at a time.
Each phase must be completed, verified, and frozen before proceeding.

Skipping phases or implementing multiple phases simultaneously is forbidden.

---

## Global Execution Rules

---

## Mandatory Verification Rule

For any phase that introduces executable logic:

- You MUST create at least one minimal unit test that verifies the phase goal.
- Tests must live in the `tests/` directory.
- A phase is NOT considered complete unless its tests pass.

If a test fails:
- Fix the implementation, not the test (unless the test is incorrect).

Declaring success without a passing test is forbidden.

---

These rules apply to **all phases**:

1. Implement **only the files listed for the current phase**.
2. Do NOT modify files from future phases.
3. Do NOT redesign architecture or contracts.
4. Before writing code:
   - Restate the goal of the phase.
   - Outline a short task list.
5. After completing a phase:
   - Verify correctness.
   - Stop and report completion.
   - Wait for explicit approval to continue.

---

## Phase 0 — Project Initialization

### Goal
Prepare the repository skeleton without implementing logic.

### Scope
- Create directory structure
- Create empty files
- No code logic

### Files Allowed
- Folder structure
- Empty `.py` files
- `requirements.txt`
- `README.md` (placeholder)

### Environment & Dependency Discipline
- The project MUST use an isolated Python environment.
- Dependencies MUST be declared in `requirements.txt`.
- No global or system-level Python dependencies are allowed.
- The runtime Python version must be compatible with Python 3.10+.
- The agent must not assume any preinstalled packages beyond the standard library.

### Stop Condition
All files exist. No logic implemented.

---

## Phase 1 — Data Contracts & Schemas

### Goal
Lock canonical data models and enforce schema boundaries.

### Scope
- Implement Pydantic models only
- No IO
- No detection logic

### Files Allowed
- `src/core/events.py`

### Requirements
- Must conform exactly to `CONTRACTS.md`
- Use GUIDs for identity
- Treat nodes/events as immutable where applicable
- Add docstrings explaining intent

### Forbidden
- Parsing logic
- Baseline logic
- Chain traversal

### Stop Condition
Schemas validate sample inputs correctly, verified by at least one unit test.

---

## Phase 2 — Data Ingestion (Loader)

### Goal
Convert raw Sysmon logs into canonical events.

### Scope
- Parsing
- Validation
- Normalization

### Files Allowed
- `src/core/loader.py`

### Requirements
- Reject malformed input early
- Produce only valid canonical events
- No anomaly detection

### Forbidden
- Risk scoring
- Chain reconstruction
- Baseline usage

### Stop Condition
Loader converts raw logs into valid canonical events, verified by a unit test using representative input.

---

## Phase 3 — Baseline Construction (Training Mode)

### Goal
Learn normal execution behavior.

### Scope
- Build baseline profile
- Persist baseline

### Files Allowed
- `src/core/analyzer.py` (baseline logic only)

### Requirements
- Extract execution relationships
- Store baseline deterministically
- No anomaly detection

### Forbidden
- Risk assignment
- Chain reconstruction
- Reporting logic

### Stop Condition
Baseline can be built and reloaded consistently, verified by a unit test.

---

## Phase 4 — Anomaly Detection

### Goal
Identify deviations from baseline behavior.

### Scope
- Detection logic only

### Files Allowed
- `src/core/analyzer.py`

### Requirements
- Compare new events against baseline
- Flag unknown or rare relationships
- Assign preliminary risk levels

### Forbidden
- Chain reconstruction
- Report assembly

### Stop Condition
Anomalous events are correctly identified, verified by a unit test with known baseline and input.

---

## Phase 5 — Chain Reconstruction

### Goal
Provide causal context for anomalies.

### Scope
- Parent traversal logic

### Files Allowed
- `src/core/analyzer.py`

### Requirements
- Reconstruct execution chains
- Enforce depth limits
- Terminate safely

### Forbidden
- Modifying detection logic
- Output formatting

### Stop Condition
Valid, bounded chains are produced, verified by a unit test enforcing depth limits.

---

## Phase 6 — Report Assembly

### Goal
Produce structured analysis reports.

### Scope
- Report construction only

### Files Allowed
- `src/core/analyzer.py`
- (optional) report helper module

### Requirements
- Conform exactly to output contract
- Include explanations and chains
- Deterministic output

### Forbidden
- Printing
- UI formatting

### Stop Condition
Reports conform to CONTRACTS.md, verified by a unit test asserting schema compliance.

---

## Phase 7 — Interfaces (CLI & API)

### Goal
Expose the analysis engine.

### Scope
- Thin wrappers only

### Files Allowed
- `src/cli/`
- `src/api/`

### Requirements
- No business logic
- Delegate to core engine
- Stateless behavior

### Forbidden
- Re-implementing logic
- Modifying core behavior

### Stop Condition
CLI and API invoke the core engine correctly, verified by smoke tests.

---

## Phase 8 — Containerization & Deployment

### Goal
Enable reproducible execution.

### Scope
- Packaging only

### Files Allowed
- `Dockerfile`
- `docker-compose.yml`

### Requirements
- No logic changes
- Deterministic startup

### Forbidden
- Environment-specific assumptions

### Stop Condition
System runs successfully in a container.

---

## Completion Criteria

The project is considered complete only when:
- All phases are implemented in order
- All contracts are respected
- No phase was skipped or merged

---

## Final Rule

If unsure which phase you are in:
**STOP and ask before proceeding.**
```


