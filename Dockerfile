# =============================================================================
# System Behavior Analyzer - Production Dockerfile
# =============================================================================
# Multi-stage build for minimal production image
# Uses Python 3.11 slim as base

# -----------------------------------------------------------------------------
# Stage 1: Builder - Install dependencies
# -----------------------------------------------------------------------------
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# -----------------------------------------------------------------------------
# Stage 2: Runtime - Minimal production image
# -----------------------------------------------------------------------------
FROM python:3.11-slim as runtime

WORKDIR /app

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY src/ ./src/
COPY README.md ./

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Environment variables
# BASELINE_PATH must be set at runtime (e.g., via docker-compose or -e flag)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()" || exit 1

# Default command: Run API server
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]


# =============================================================================
# Usage Examples
# =============================================================================
#
# Build:
#   docker build -t sba:latest .
#
# Run API (requires baseline file):
#   docker run -p 8000:8000 \
#     -v /path/to/baseline.json:/data/baseline.json:ro \
#     -e BASELINE_PATH=/data/baseline.json \
#     sba:latest
#
# Run CLI train:
#   docker run -v /path/to/events.json:/data/events.json:ro \
#     -v /path/to/output:/output \
#     sba:latest \
#     python -m src.cli.main train -i /data/events.json -o /output/baseline.json
#
# Run CLI analyze:
#   docker run -v /path/to/events.json:/data/events.json:ro \
#     -v /path/to/baseline.json:/data/baseline.json:ro \
#     sba:latest \
#     python -m src.cli.main analyze -i /data/events.json -b /data/baseline.json
# =============================================================================
