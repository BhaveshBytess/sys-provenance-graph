# System Behavior Analyzer

A backend analysis engine that detects suspicious process execution chains from OS-level telemetry.

## Overview

This system:
- Consumes normalized Sysmon for Linux process creation events (Event ID 1)
- Learns a baseline of normal execution behavior
- Flags deviations as explainable anomalies
- Produces structured analysis reports

## Status

✅ **Complete** — All 8 phases implemented

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/BhaveshBytess/sys-provenance-graph.git
cd sys-provenance-graph

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: .\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### CLI Usage

```bash
# Train baseline from events
python -m src.cli.main train -i events.json -o baseline.json

# Analyze events against baseline
python -m src.cli.main analyze -i events.json -b baseline.json

# Output to file
python -m src.cli.main analyze -i events.json -b baseline.json -o report.json

# Pretty-print JSON
python -m src.cli.main analyze -i events.json -b baseline.json --pretty
```

### API Usage

```bash
# Start API server
BASELINE_PATH=baseline.json uvicorn src.api.main:app --host 0.0.0.0 --port 8000

# Health check
curl http://localhost:8000/health

# Analyze events
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"events": [...]}'
```

## Docker Deployment

### Build Image

```bash
docker build -t sba:latest .
```

### Run API Container

```bash
docker run -p 8000:8000 \
  -v $(pwd)/baseline.json:/data/baseline.json:ro \
  -e BASELINE_PATH=/data/baseline.json \
  sba:latest
```

### Docker Compose

```bash
# Create data directory with baseline
mkdir -p data
# (place baseline.json in data/)

# Start services
docker-compose up --build -d

# View logs
docker-compose logs -f api

# Stop
docker-compose down
```

## Project Structure

```
sys-provenance-graph/
├── active_context.md       # Session control entrypoint
├── docs/                   # 7-file governance framework (project-level)
│   ├── contracts.md
│   ├── agent_project.md
│   ├── agent_core.md
│   ├── build_plan.md
│   ├── decisions.md
│   └── state.md
├── governance/             # Reusable templates and bootstrap tools
├── src/
│   ├── core/
│   │   ├── events.py      # Pydantic data models
│   │   ├── loader.py      # Sysmon event parser
│   │   ├── analyzer.py    # Detection engine
│   │   └── pipeline.py    # Shared analysis pipeline
│   ├── adapters/
│   │   └── mordor_adapter.py  # Mordor JSONL -> CanonicalEvent adapter
│   ├── cli/
│   │   └── main.py        # CLI interface (Typer)
│   └── api/
│       └── main.py        # REST API (FastAPI)
├── scripts/
│   ├── mordor_smoke_test.py   # Baseline/test smoke run against Mordor datasets
│   └── mordor_split_test.py   # 70/30 split-baseline smoke run
├── tests/                  # Unit tests
├── Dockerfile              # Production container
├── docker-compose.yml      # Deployment config
├── requirements.txt        # Python dependencies
├── VALIDATION.md            # Latest validation evidence and outcomes
└── README.md
```

## Documentation

- `active_context.md` — Session entrypoint and governance order
- `docs/contracts.md` — Immutable system contracts and invariants
- `docs/agent_project.md` — Project-specific constraints and domain rules
- `docs/agent_core.md` — Reusable execution and debugging discipline
- `docs/build_plan.md` — Module dependency graph and exit gates
- `docs/decisions.md` — Architecture decision records
- `docs/state.md` — Current system state and session log
- `SPEC.md` — System architecture and responsibilities
- `governance/` — 7-file framework templates and bootstrap tools
- `VALIDATION.md` — Validation runbook and latest execution evidence

## Mordor Validation

Run adapter tests:
```bash
python -m pytest -q tests/test_mordor_adapter.py
```

Run smoke test with explicit dataset paths:
```bash
python scripts/mordor_smoke_test.py \
  --baseline-file examples/mordor/psh_python_webserver_2020-10-2900161507.json \
  --test-file examples/mordor/metasploit_logonpasswords_lsass_memory_dump.json \
  --output examples/mordor/smoke_test_report.json
```

Run split-baseline smoke test:
```bash
python scripts/mordor_split_test.py \
  --input-file examples/mordor/metasploit_logonpasswords_lsass_memory_dump.json \
  --output examples/mordor/split_test_report.json
```

## Test Results

| Phase | Component | Tests |
|-------|-----------|-------|
| 1 | Data Contracts | 20 |
| 2 | Loader | 27 |
| 3 | Baseline | 28 |
| 4 | Detection | 19 |
| 5 | Chain Reconstruction | 21 |
| 6 | Report Assembly | 17 |
| 7 | CLI & API | 21 |
| **Total** | | **153** |

Run all tests:
```bash
pytest -v
```

## Requirements

- Python 3.10+
- See `requirements.txt` for dependencies

## License

Internal use only.
