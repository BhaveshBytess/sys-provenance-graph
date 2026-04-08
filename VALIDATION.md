# Validation Report

Date: 2026-04-09
Project: System Behavior Analyzer
Scope: Mordor adapter and smoke-test workflow validation

## Summary

This validation pass confirms that:
- The Mordor adapter test suite passes.
- The end-to-end Mordor smoke workflow executes successfully when explicit JSONL dataset paths are provided.
- The split-baseline smoke workflow executes successfully.
- Report artifacts are generated in examples/mordor.

## Commands Executed

### 1) Adapter unit tests

Command:
```bash
python -m pytest -q tests/test_mordor_adapter.py
```

Observed result:
- 5 passed in 1.61s

### 2) End-to-end Mordor smoke test (explicit dataset paths)

Command:
```bash
python scripts/mordor_smoke_test.py \
  --baseline-file examples/mordor/psh_python_webserver_2020-10-2900161507.json \
  --test-file examples/mordor/metasploit_logonpasswords_lsass_memory_dump.json \
  --output examples/mordor/smoke_test_report.json
```

Observed result summary:
- Total events loaded (baseline + test): 272
- Events passed validation: 272
- Events failed validation: 0
- Anomalies detected: 269
- Unknown relationships: 269
- Rare relationships: 0
- Top flagged pairs include:
  - C:\Windows\System32\cmd.exe -> C:\Windows\System32\conhost.exe (77)
  - C:\Windows\System32\cscript.exe -> C:\Windows\System32\cmd.exe (75)

### 3) Split-baseline Mordor smoke test

Command:
```bash
python scripts/mordor_split_test.py \
  --input-file examples/mordor/metasploit_logonpasswords_lsass_memory_dump.json \
  --output examples/mordor/split_test_report.json
```

Observed result summary:
- Total events loaded (baseline + test): 269
- Events passed validation: 269
- Events failed validation: 0
- Anomalies detected: 1
- Unknown relationships: 1
- Rare relationships: 0
- Top flagged pair:
  - C:\Windows\System32\cmd.exe -> C:\Windows\System32\dxdiag.exe (1)

## Artifacts Verified

- examples/mordor/smoke_test_report.json
- examples/mordor/split_test_report.json

## Known Validation Caveat

Running `python scripts/mordor_smoke_test.py` with no arguments currently fails in environments where non-JSONL `.json` files (such as generated report files) exist in examples/mordor. The default file auto-selection logic includes all `.json` files by size, not only source JSONL telemetry.

Workaround used in this validation:
- Provide explicit `--baseline-file` and `--test-file` arguments that point to JSONL telemetry datasets.
