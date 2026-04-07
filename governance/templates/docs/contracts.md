# contracts.md - System Contracts and Invariants

## 1. Purpose

This document defines hard contracts for data models, interfaces, invariants,
failure behavior, and test expectations.

Normative terms MUST, MUST NOT, SHOULD, MAY are interpreted per RFC 2119.

Authority order:
1. `docs/contracts.md`
2. `docs/agent_project.md`
3. `docs/agent_core.md`
4. `docs/build_plan.md`
5. Code

---

## 2. Versioning

- Current Version: V1
- Last Updated: {{TODAY}}
- Any contract change requires:
  1. Version bump
  2. Change date
  3. Rationale
  4. Affected modules
  5. Related decision record in `docs/decisions.md`

---

## 3. Data Contracts

Define tables, schemas, enums, and field-level constraints.

### 3.1 Entity/Table A
- schema
- unique keys
- dedup rules

### 3.2 Entity/Table B
- schema
- status transitions
- retention rules

### 3.3 Enumerated Values
- allowed values
- defaults
- validation rules

### 3.4 Identity and Deduplication Rules
- Primary identifiers:
- Deduplication keys:
- Uniqueness scope:

---

## 4. Data Flow Contract

Document exact ordered pipeline flow and ownership boundaries.

Invariants:
- [example invariant 1]
- [example invariant 2]
- [determinism and explainability invariants]

---

## 5. Failure Contracts

For each failure mode, specify mandatory behavior.

FC-01:
- Trigger:
- Required behavior:
- Not acceptable:

FC-02:
- Trigger:
- Required behavior:
- Not acceptable:

FC-03:
- Trigger:
- Required behavior:
- Not acceptable:

FC-04:
- Trigger:
- Required behavior:
- Not acceptable:

---

## 6. Test Specifications

Define minimum test coverage required per module.

Module tests:
- test_x:
- test_y:

Required policy:
- Contract changes MUST include updated tests.
- Critical-path modules SHOULD include negative tests and boundary tests.
- Build and release flow SHOULD preserve provenance metadata when available.
