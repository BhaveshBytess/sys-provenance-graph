# build_plan.md - Module Plan and Dependency Graph

## 1. Purpose

Defines module-level build order, dependencies, deliverables, and exit criteria.
This document is execution control, not narrative documentation.

---

## 2. Dependency Graph

List dependency order from foundational modules to orchestration.

Example:
1. Module 0: Data layer
2. Module 1: Ingestion
3. Module 2: Processing
4. Module 3: Delivery
5. Module 4: Orchestration

Rules:
- Downstream modules MUST NOT start before upstream exit criteria are satisfied.
- Each module MUST have objective verification evidence.
- Scope changes MUST be logged in `docs/decisions.md`.

---

## 3. Module Specifications

### Module 0
- Upstream dependencies:
- Objective:
- Deliverables:
- Exit criteria:
- Verification evidence:

### Module 1
- Upstream dependencies:
- Objective:
- Deliverables:
- Exit criteria:
- Verification evidence:

### Module 2
- Upstream dependencies:
- Objective:
- Deliverables:
- Exit criteria:
- Verification evidence:

Add modules as needed.

---

## 4. Global Exit Gates

- Contract gate: output/input contracts remain valid.
- Test gate: required tests pass.
- Security gate: no new unmanaged secrets or high-risk dependency changes.
- Documentation gate: `docs/state.md` and `docs/decisions.md` updated.
