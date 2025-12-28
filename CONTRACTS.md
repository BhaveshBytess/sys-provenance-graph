# What `CONTRACTS.md` is (important framing)

**Audience:** Humans + Agents
**Purpose:** Define what must NOT change without an explicit redesign
**Scope:** Data contracts, invariants, terminology

This file is **NOT**:

* an architecture overview
* an implementation guide
* a tutorial

That will go into `SPEC.md` later.

---

# What belongs in `CONTRACTS.md`

Only **three things** belong here:

1. **Terminology (shared language)**
2. **Input Contract (Canonical Event Schema)**
3. **Output Contract (Analysis Report Schema)**
4. **Core Invariants (must always hold)**

Nothing else.

---

# `CONTRACTS.md` (Authoritative)

Below is the **full, final version**.
Read it carefully — this is the system’s constitution.

---

## `CONTRACTS.md`

**System Contracts & Invariants — Authoritative**

---

## 1. Purpose of This Document

This document defines the **immutable contracts** of the System Behavior Analyzer.

Any component, agent, or developer interacting with this system **MUST** obey these contracts.

Changes to this file constitute a **breaking redesign** and must not be made casually.

---

## 2. Terminology (Canonical Definitions)

These terms have **precise meanings** within this system.

### Event

A normalized representation of a single system action derived from OS telemetry.

An event is **semantic**, not raw (e.g., “process created”, not “syscall 59”).

---

### Subject

The **active entity** performing an action.

In V1, the subject is always a **process**.

---

### Parent

The **immediate causal predecessor** of the subject.

Parent relationships define **execution lineage**.

---

### Object

The **target entity** acted upon by the subject.

In V1, this may be:

* another process
* a file
* a network endpoint
* `null` (if not applicable)

---

### Chain

An **ordered sequence of processes** connected through parent relationships.

Chains represent **causal execution paths**.

---

### Anomaly

A process relationship or chain that **violates the learned baseline of normal behavior**.

---

### Baseline

A learned profile of **normal parent → child execution relationships** derived from historical data.

---

## 3. Input Contract — Canonical Event Schema

All input telemetry **MUST** be normalized into the following canonical JSON schema before analysis.

### 3.1 Canonical Event (V1)

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

---

### 3.2 Identity Rules (Non-Negotiable)

* `subject.guid` is the **primary identifier** for a process.
* PIDs (`pid`) are **informational only** and must never be used for identity.
* `boot_id` scopes process identity to a system lifecycle.
* Two events with the same PID but different GUIDs represent **different processes**.

---

### 3.3 Event Scope (V1)

* Only **Sysmon for Linux — Event ID 1 (Process Create)** is supported in V1.
* Other event types are explicitly **out of scope**.

---

## 4. Output Contract — Analysis Report Schema

All analysis results **MUST** conform to the following schema.

### 4.1 Analysis Report (V1)

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

      "chain": [
        "process-guid-1",
        "process-guid-2",
        "process-guid-3"
      ],

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

---

### 4.2 Output Guarantees

* Every anomaly **MUST** include an explanation.
* Every anomaly **MUST** reference at least one process chain.
* `global_risk_score` MUST be consistent with individual anomalies.

---

## 5. Core Invariants (Must Always Hold)

These rules **MUST NEVER** be violated.

### 5.1 Determinism

Given identical input events and baseline, the output **MUST** be identical.

---

### 5.2 Explainability

Every anomaly must be explainable in plain language.

If an anomaly cannot be explained, it must not be emitted.

---

### 5.3 Chain Validity

All chains must:

* follow valid parent relationships
* respect traversal depth limits
* terminate at a known root or depth limit

---

### 5.4 Baseline Respect

An anomaly is defined **only** as a deviation from the learned baseline.

No hardcoded attack rules are allowed in V1.

---

### 5.5 Contract Enforcement

* Invalid input MUST be rejected early.
* Invalid output MUST never be emitted.

Fail fast is mandatory.

---

## 6. Versioning Discipline

* This document defines **Contract V1**.
* Any modification requires:

  * explicit version bump
  * documented migration rationale
  * corresponding test updates

---

## 7. Final Statement

This document is **authoritative**.

If implementation, agent behavior, or documentation conflicts with this file, **this file wins**.

---



