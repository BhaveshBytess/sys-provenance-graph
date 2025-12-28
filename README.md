# System Behavior Analyzer

A backend analysis engine that detects suspicious process execution chains from OS-level telemetry.

## Overview

This system:
- Consumes normalized Sysmon for Linux process creation events
- Learns a baseline of normal execution behavior
- Flags deviations as explainable anomalies
- Produces structured analysis reports

## Status

🚧 **Work in Progress** — Phase 0 (Project Initialization)

## Documentation

- `CONTRACTS.md` — Immutable data contracts
- `SPEC.md` — System architecture and responsibilities
- `EXECUTION_PLAN.md` — Phased implementation strategy
- `agent.md` — Agent operating manual

## Requirements

- Python 3.10+
- See `requirements.txt` for dependencies

## License

Internal use only.
