# contracts.md - System Contracts and Invariants (Authoritative)

## 1. Purpose

This document defines immutable contracts for the System Behavior Analyzer.
All implementation and operational decisions MUST conform to this file.

Normative terms MUST, MUST NOT, SHOULD, MAY are interpreted per RFC 2119.

Authority order:
1. `docs/contracts.md`
2. `docs/agent_project.md`
3. `docs/agent_core.md`
4. `docs/build_plan.md`
5. Code

## 2. Versioning and Change Control

- Current Version: V1
- Last Updated: 2026-04-06
- Any contract change requires:
1. Version bump
2. Change date
3. Rationale
4. Affected modules and tests
5. Decision record in `docs/decisions.md`

## 3. Terminology (Canonical)

Event:
- A normalized representation of one system action derived from telemetry.

Subject:
- The active entity performing an action.
- In V1, subject is always a process.

Parent:
- The immediate causal predecessor of the subject process.

Object:
- The target acted upon by subject.
- In V1: process, file, network, or null.

Chain:
- Ordered process lineage through parent relationships.

Anomaly:
- A process relationship or chain that deviates from the learned baseline.

Baseline:
- Learned profile of normal parent-child-user execution relationships.

## 4. Input Contract (Canonical Event)

All telemetry MUST be normalized to this schema before analysis:

```json
{
  "event_id": "uuid-v4",
  "timestamp": "ISO-8601",
  "host": {
    "hostname": "string",
    "boot_id": "uuid"
  },
  "event_type": "PROCESS_CREATE",
  "subject": {
    "type": "process",
    "guid": "string",
    "pid": "integer",
    "image": "string"
  },
  "parent": {
    "guid": "string",
    "image": "string"
  },
  "object": {
    "type": "process | file | network | null",
    "guid": "string | null",
    "path_or_address": "string | null"
  },
  "metadata": {
    "command_line": "string",
    "user": "string",
    "cwd": "string"
  }
}
```

Identity rules (non-negotiable):
- `subject.guid` is primary process identifier.
- `pid` is informational only and MUST NOT be used for identity.
- `boot_id` scopes identity to a system lifecycle.
- Same PID with different GUID means different process.

Event scope (V1):
- Only Sysmon for Linux EventId 1 (process create) is supported.
- Other event types are out of scope.

## 5. Output Contract (Analysis Report)

All analysis output MUST conform to this schema:

```json
{
  "analysis_id": "uuid-v4",
  "timestamp": "ISO-8601",
  "global_risk_score": 0,
  "summary": "string",
  "anomalies": [
    {
      "id": "string",
      "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
      "confidence": 0.0,
      "description": "string",
      "chain": ["process-guid-1", "process-guid-2"],
      "involved_entities": [
        {
          "guid": "string",
          "image": "string",
          "role": "parent | child"
        }
      ]
    }
  ],
  "metadata": {
    "events_processed": 0,
    "model_version": "string"
  }
}
```

Output guarantees:
- Every anomaly MUST include explanation text.
- Every anomaly MUST include at least one chain element.
- `global_risk_score` MUST be consistent with anomaly severities.

## 6. Detection and Baseline Contract

Baseline construction:
- Baseline relationship key MUST be tuple: `(parent_image, child_image, user)`.
- Relationship frequencies MUST be counted deterministically.

Detection semantics (V1):
- Unknown relationship (count 0) MUST be flagged anomalous.
- Rare relationship MAY be flagged based on configured thresholds.
- Hardcoded attack signatures MUST NOT replace baseline-deviation logic.

## 7. Chain Contract

Chain reconstruction MUST:
- Use O(1) lookup index keyed by process GUID.
- Enforce bounded traversal depth.
- Detect and terminate on cycles.
- Terminate on missing parent or recognized root condition.

## 8. Core Invariants

1. Determinism:
- Given identical inputs and baseline, behavior and severity outcomes MUST be reproducible.

2. Explainability:
- Anomalies MUST be explainable in plain language.

3. Chain validity:
- Chains MUST follow parent lineage semantics and termination rules.

4. Baseline respect:
- Anomalies MUST represent deviation from learned baseline behavior.

5. Contract enforcement:
- Invalid input MUST be rejected at boundary.
- Invalid output MUST NOT be emitted.

## 9. Failure Contracts

FC-01 Invalid or malformed input:
- Trigger: invalid JSON or required fields absent/unparseable.
- Required behavior: fail fast with specific error.
- Not acceptable: silent coercion that hides invalid critical fields.

FC-02 Unsupported event type:
- Trigger: non-process-create event in V1.
- Required behavior: reject with explicit unsupported-event error.
- Not acceptable: partial processing of unsupported types.

FC-03 Baseline unavailable in API runtime:
- Trigger: baseline missing or load failure at startup/runtime.
- Required behavior: reject analysis with service unavailable semantics.
- Not acceptable: proceeding with null or implicit empty baseline silently.

FC-04 Internal analysis failure:
- Trigger: unexpected exception in detection/report path.
- Required behavior: sanitized error response and internal logging.
- Not acceptable: leaking stack traces to API consumers.

## 10. Test Obligations

- Contract changes MUST include aligned tests.
- Critical-path modules SHOULD include negative and boundary tests.
- Regression tests SHOULD be added for bug fixes affecting contracts/invariants.

Reference suites:
- `tests/test_events.py`
- `tests/test_loader.py`
- `tests/test_analyzer.py`
- `tests/test_analyzer_chain.py`
- `tests/test_report_assembly.py`
- `tests/test_api.py`
- `tests/test_cli.py`

## 11. External Alignment Notes

This contract set aligns with:
- NIST SSDF risk-based secure development outcomes.
- SLSA build/provenance consistency principles.
- ADR-based decision traceability.
