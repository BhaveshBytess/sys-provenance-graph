"""
API Interface for System Behavior Analyzer

This module provides the REST API using FastAPI.
Endpoints:
- POST /analyze: Submit events for analysis
- GET /health: Health check

The baseline is loaded ONCE at startup from BASELINE_PATH environment variable.
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.core.analyzer import BaselineProfile
from src.core.events import AnalysisReport
from src.core.loader import (
    InvalidEventError,
    MalformedInputError,
    UnsupportedEventTypeError,
    load_events,
)
from src.core.pipeline import load_baseline_from_file, run_pipeline


# =============================================================================
# Application State
# =============================================================================


class AppState:
    """
    Application state container.
    
    Holds the baseline profile loaded at startup.
    """
    baseline: BaselineProfile | None = None
    baseline_path: str | None = None


app_state = AppState()


# =============================================================================
# Lifespan Management
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    
    Loads the baseline at startup from BASELINE_PATH environment variable.
    If not set, the API will return 503 for analysis requests.
    """
    baseline_path = os.environ.get("BASELINE_PATH")
    
    if baseline_path:
        try:
            path = Path(baseline_path)
            app_state.baseline = load_baseline_from_file(path)
            app_state.baseline_path = baseline_path
            print(f"Baseline loaded from {baseline_path}")
            print(f"  - Relationships: {app_state.baseline.get_unique_relationship_count()}")
        except FileNotFoundError:
            print(f"Warning: Baseline file not found: {baseline_path}")
        except Exception as e:
            print(f"Warning: Failed to load baseline: {e}")
    else:
        print("Warning: BASELINE_PATH not set. Analysis endpoint will return 503.")
    
    yield  # Application runs here
    
    # Cleanup (if needed)
    app_state.baseline = None


# =============================================================================
# FastAPI App
# =============================================================================


app = FastAPI(
    title="System Behavior Analyzer API",
    description="Detect anomalous process behavior by comparing against learned baselines",
    version="1.0.0",
    lifespan=lifespan,
)


# =============================================================================
# Request/Response Models
# =============================================================================


class AnalyzeRequest(BaseModel):
    """
    Request body for the analyze endpoint.
    
    Events can be provided as either:
    - A list of event dictionaries
    - A raw JSON string
    """
    events: list[dict[str, Any]] = Field(
        ...,
        description="List of Sysmon events to analyze",
        min_length=1,
    )


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Service status")
    baseline_loaded: bool = Field(..., description="Whether baseline is loaded")
    baseline_path: str | None = Field(None, description="Path to loaded baseline")


class ErrorResponse(BaseModel):
    """Error response model."""
    detail: str = Field(..., description="Error description")


# =============================================================================
# Endpoints
# =============================================================================


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check if the service is running and baseline is loaded",
)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.
    
    Returns service status and baseline loading state.
    """
    return HealthResponse(
        status="healthy",
        baseline_loaded=app_state.baseline is not None,
        baseline_path=app_state.baseline_path,
    )


@app.post(
    "/analyze",
    response_model=dict,  # Return raw dict to avoid serialization issues
    summary="Analyze events",
    description="Detect anomalies in submitted events",
    responses={
        400: {"model": ErrorResponse, "description": "Invalid input"},
        503: {"model": ErrorResponse, "description": "Baseline not loaded"},
    },
)
async def analyze_events(request: AnalyzeRequest) -> dict:
    """
    Analyze events and detect anomalies.
    
    Compares submitted events against the loaded baseline
    and returns an analysis report.
    """
    # Check baseline is loaded
    if app_state.baseline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Baseline not loaded. Set BASELINE_PATH environment variable.",
        )
    
    try:
        # Parse and validate events
        events = load_events(request.events)
        
        # Run analysis pipeline
        report = run_pipeline(events, app_state.baseline)
        
        # Return as dict (Pydantic v2 model_dump with JSON mode)
        return report.model_dump(mode="json")
        
    except MalformedInputError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed input: {e}",
        )
    except UnsupportedEventTypeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported event type: {e}",
        )
    except InvalidEventError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event: {e}",
        )
    except Exception as e:
        # Log the actual error but don't expose stack trace
        print(f"Analysis error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during analysis",
        )


# =============================================================================
# Error Handlers
# =============================================================================


@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    """
    Generic exception handler.
    
    Catches unhandled exceptions and returns a clean error response
    without exposing stack traces.
    """
    print(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )
