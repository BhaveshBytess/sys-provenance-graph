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
├── src/
│   ├── core/
│   │   ├── events.py      # Pydantic data models
│   │   ├── loader.py      # Sysmon event parser
│   │   ├── analyzer.py    # Detection engine
│   │   └── pipeline.py    # Shared analysis pipeline
│   ├── cli/
│   │   └── main.py        # CLI interface (Typer)
│   └── api/
│       └── main.py        # REST API (FastAPI)
├── tests/                  # Unit tests
├── Dockerfile             # Production container
├── docker-compose.yml     # Deployment config
├── requirements.txt       # Python dependencies
└── README.md
```

## Documentation

- `CONTRACTS.md` — Immutable data contracts
- `SPEC.md` — System architecture and responsibilities
- `EXECUTION_PLAN.md` — Phased implementation strategy
- `agent.md` — Agent operating manual

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
