# build_plan.md - Module Plan and Dependency Graph

## 1. Purpose

Defines module-level build order, dependencies, deliverables, and exit criteria.
This document is execution control, not narrative documentation.

---

## 2. Dependency Graph

1. Module 0: Project initialization and structure
2. Module 1: Data contracts and schemas
3. Module 2: Data ingestion and normalization
4. Module 3: Baseline construction and persistence
5. Module 4: Anomaly detection
6. Module 5: Chain reconstruction
7. Module 6: Report assembly
8. Module 7: CLI/API interfaces and deployment packaging
9. Module 8: Governance integration and documentation migration

Rules:
- Downstream modules MUST NOT start before upstream exit criteria are satisfied.
- Each module MUST have objective verification evidence.
- Scope changes MUST be logged in `docs/decisions.md`.

---

## 3. Module Specifications

### Module 0
- Upstream dependencies: None
- Objective: establish project skeleton and dependencies.
- Deliverables: repository structure and base packaging files.
- Exit criteria: folders and base files exist.
- Verification evidence: repository tree and startup readiness.

### Module 1
- Upstream dependencies: Module 0
- Objective: lock canonical data contracts.
- Deliverables: Pydantic schemas for input/output.
- Exit criteria: schema validation tests pass.
- Verification evidence: `tests/test_events.py`.

### Module 2
- Upstream dependencies: Module 1
- Objective: parse and normalize raw Sysmon events.
- Deliverables: loader with strict boundary validation.
- Exit criteria: valid canonical events produced from representative input.
- Verification evidence: `tests/test_loader.py`.

### Module 3
- Upstream dependencies: Module 2
- Objective: learn baseline relationship frequencies.
- Deliverables: baseline profile build, save, and load.
- Exit criteria: deterministic baseline serialization and reload.
- Verification evidence: `tests/test_analyzer.py` baseline tests.

### Module 4
- Upstream dependencies: Module 3
- Objective: detect unknown and rare deviations.
- Deliverables: statistical anomaly detection with risk levels.
- Exit criteria: anomaly detection tests pass for known/unknown/rare cases.
- Verification evidence: `tests/test_analyzer.py` detection tests.

### Module 5
- Upstream dependencies: Module 4
- Objective: reconstruct explainable execution chains.
- Deliverables: GUID event index, bounded traversal, cycle handling.
- Exit criteria: chain tests pass with depth/cycle/root conditions.
- Verification evidence: `tests/test_analyzer_chain.py`.

### Module 6
- Upstream dependencies: Modules 4 and 5
- Objective: assemble canonical analysis report.
- Deliverables: report creation with summary, anomalies, metadata.
- Exit criteria: report contract compliance verified.
- Verification evidence: `tests/test_report_assembly.py`.

### Module 7
- Upstream dependencies: Modules 2 through 6
- Objective: expose engine via CLI, API, and container runtime.
- Deliverables: Typer CLI, FastAPI app, Docker assets.
- Exit criteria: interface smoke tests and health path pass.
- Verification evidence: `tests/test_cli.py`, `tests/test_api.py`.

### Module 8
- Upstream dependencies: Module 7
- Objective: migrate to 7-file governance framework and retire legacy workflow docs.
- Deliverables: root `active_context.md` + `docs/` governance files, updated references.
- Exit criteria: no remaining active references to retired legacy workflow files.
- Verification evidence: repository grep and documentation updates.

---

## 4. Global Exit Gates

- Contract gate: output/input contracts remain valid.
- Test gate: required tests pass.
- Security gate: no new unmanaged secrets or high-risk dependency changes.
- Documentation gate: `docs/state.md` and `docs/decisions.md` updated.
