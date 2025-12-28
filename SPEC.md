# What `SPEC.md` is (important framing)

**Audience:** Humans + Agents
**Purpose:** Describe **how the system works**, not what the data looks like
**Authority level:** Below `CONTRACTS.md`, above code

### `SPEC.md` answers:

* What is the system?
* What are its components?
* How does data flow?
* What are responsibilities of each module?
* How do users interact with it?

### `SPEC.md` does NOT:

* redefine schemas
* embed Python code
* describe algorithms line-by-line
* override contracts

Think of it as **the map**, not the law.

---

# What belongs in `SPEC.md`

We will include exactly these sections:

1. System Overview
2. Goals & Non-Goals
3. High-Level Architecture
4. Component Responsibilities
5. Data Flow
6. Interfaces (CLI & API)
7. Operational Assumptions
8. Out-of-Scope (Explicit)

Nothing more.

---

# `SPEC.md`

**System Specification — Authoritative**

---

## 1. System Overview

The **System Behavior Analyzer** is a backend analysis engine that detects **suspicious process execution chains** from OS-level telemetry.

The system consumes **normalized Sysmon for Linux process creation events**, learns a **baseline of normal execution behavior**, and flags **deviations** as explainable anomalies.

The primary output is a **structured analysis report** suitable for:

* human inspection (CLI)
* programmatic consumption (API)

The system is **deterministic**, **explainable**, and **deployment-ready**.

---

## 2. Goals & Non-Goals

### 2.1 Goals

* Detect anomalous parent → child process relationships
* Reconstruct causal execution chains
* Produce explainable, structured reports
* Operate as a backend service (CLI + API)
* Enforce strict input/output contracts

---

### 2.2 Non-Goals

The system explicitly does **not**:

* Perform malware classification
* Use black-box deep learning in V1
* Provide a graphical UI
* Perform real-time streaming analysis
* Persist data in databases
* Replace full EDR solutions

---

## 3. High-Level Architecture

```
Raw Sysmon Logs
        ↓
   Loader / Normalizer
        ↓
 Canonical Events (Contract)
        ↓
   Core Analysis Engine
        ↓
 Structured Analysis Report
        ↓
   CLI        API
```

**Key principle:**
The **Core Analysis Engine** is completely independent of interfaces.

---

## 4. Component Responsibilities

### 4.1 Loader (`src/core/loader.py`)

**Responsibility:**

* Parse raw Sysmon logs
* Validate required fields
* Normalize data into canonical events (per `CONTRACTS.md`)
* Reject malformed input early

**Must NOT:**

* Perform detection logic
* Assign risk
* Build chains

---

### 4.2 Core Analysis Engine (`src/core/analyzer.py`)

**Responsibility:**

* Accept canonical events
* Load baseline profile
* Identify anomalous parent → child relationships
* Reconstruct execution chains
* Assemble structured analysis reports

This module owns **all system intelligence**.

---

#### Detection Strategy (V1)

The Core Analysis Engine uses a **Statistical Baseline Profiling** approach to anomaly detection.

During a baseline-building phase, the system observes historical process creation events and learns normal execution relationships. These relationships are defined primarily by parent → child process interactions and may be conditioned on additional contextual attributes such as the executing user.

During analysis, newly observed execution relationships are compared against the learned baseline. Relationships that have not been previously observed, or that are extremely rare relative to the baseline, are treated as anomalous.

When an anomalous relationship is identified, the system reconstructs its **execution chain** by traversing parent process relationships backward to provide causal context. This traversal is depth-limited to ensure determinism and safety.

This strategy prioritizes:
- explainability over prediction
- determinism over probabilistic inference
- system behavior modeling over signature-based detection

---

### 4.3 Schema Enforcement (`src/core/events.py`)

**Responsibility:**

* Define canonical event models
* Define analysis report models
* Enforce identity rules (GUID over PID)
* Serve as the contract boundary

---

### 4.4 CLI Interface (`src/cli/`)

**Responsibility:**

* Accept file-based input
* Invoke core analysis engine
* Render reports for humans

**Must NOT:**

* Contain business logic
* Modify analysis results

---

### 4.5 API Interface (`src/api/`)

**Responsibility:**

* Accept JSON payloads
* Invoke core analysis engine
* Return structured JSON responses

**Must NOT:**

* Transform analysis logic
* Reinterpret results

---

## 5. Data Flow

1. Raw Sysmon logs are ingested
2. Logs are normalized into canonical events
3. Events are passed to the analysis engine
4. Baseline is consulted
5. Anomalies are detected
6. Chains are reconstructed
7. Report is generated
8. Output is returned via CLI or API

At no point are raw logs used directly by detection logic.

---

## 6. Interfaces

### 6.1 CLI

* Intended for local analysis and demos
* Accepts file paths or directories
* Outputs human-readable summaries
* Optional JSON output mode

---

### 6.2 API

* Intended for service deployment
* Accepts canonical events as JSON
* Returns structured analysis reports
* Stateless by design

---

## 7. Operational Assumptions

* Input telemetry may be malformed or adversarial
* Baseline profile exists before detection
* Analysis is batch-oriented in V1
* Deterministic output is required

---

## 8. Out-of-Scope (Explicit)

The following are intentionally excluded from V1:

* Graph databases
* Streaming pipelines
* Advanced ML models
* Distributed execution
* Visualization layers

These may be considered in future versions but are not part of this specification.

---

## 9. Authority & Change Control

* `CONTRACTS.md` overrides this document
* This document overrides code-level assumptions
* Any changes require explicit review

---

