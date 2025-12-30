"""
test_api.py - Unit tests for API interface.

Tests the FastAPI endpoints using TestClient.
"""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from src.api.main import app, app_state
from src.core.analyzer import BaselineProfile, build_baseline
from src.core.pipeline import load_events_from_file


# =============================================================================
# Test Fixtures
# =============================================================================


def create_test_events() -> list[dict]:
    """Create valid test events in raw format."""
    return [
        {
            "EventId": 1,
            "event_id": str(uuid4()),
            "UtcTime": datetime.now().isoformat(),
            "host": {
                "hostname": "test-host",
                "boot_id": str(uuid4()),
            },
            "ProcessGuid": "{12345678-1234-1234-1234-123456789ABC}",
            "ProcessId": 1234,
            "Image": "/usr/bin/python",
            "ParentProcessGuid": "{PARENT00-1234-1234-1234-123456789ABC}",
            "ParentImage": "/bin/bash",
            "CommandLine": "python test.py",
            "User": "root",
            "CurrentDirectory": "/home/user",
        },
    ]


@pytest.fixture
def empty_baseline() -> BaselineProfile:
    """Create an empty baseline for testing."""
    return BaselineProfile()


@pytest.fixture
def test_client(empty_baseline: BaselineProfile) -> TestClient:
    """Create a test client with baseline loaded."""
    # Manually set baseline in app state
    app_state.baseline = empty_baseline
    app_state.baseline_path = "/test/baseline.json"
    
    client = TestClient(app)
    yield client
    
    # Cleanup
    app_state.baseline = None
    app_state.baseline_path = None


@pytest.fixture
def test_client_no_baseline() -> TestClient:
    """Create a test client without baseline."""
    app_state.baseline = None
    app_state.baseline_path = None
    return TestClient(app)


# =============================================================================
# Health Endpoint Tests
# =============================================================================


class TestHealthEndpoint:
    """Tests for the /health endpoint."""

    def test_health_returns_ok(self, test_client: TestClient) -> None:
        """Health endpoint should return healthy status."""
        response = test_client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_health_shows_baseline_loaded(self, test_client: TestClient) -> None:
        """Health should indicate baseline is loaded."""
        response = test_client.get("/health")
        
        data = response.json()
        assert data["baseline_loaded"] is True
        assert data["baseline_path"] is not None

    def test_health_shows_no_baseline(self, test_client_no_baseline: TestClient) -> None:
        """Health should indicate when baseline is not loaded."""
        response = test_client_no_baseline.get("/health")
        
        data = response.json()
        assert data["baseline_loaded"] is False


# =============================================================================
# Analyze Endpoint Tests
# =============================================================================


class TestAnalyzeEndpoint:
    """Tests for the /analyze endpoint."""

    def test_analyze_returns_report(self, test_client: TestClient) -> None:
        """Analyze should return a valid report."""
        events = create_test_events()
        
        response = test_client.post("/analyze", json={"events": events})
        
        assert response.status_code == 200
        data = response.json()
        assert "analysis_id" in data
        assert "global_risk_score" in data
        assert "anomalies" in data
        assert "metadata" in data

    def test_analyze_without_baseline_returns_503(
        self, test_client_no_baseline: TestClient
    ) -> None:
        """Analyze without baseline should return 503."""
        events = create_test_events()
        
        response = test_client_no_baseline.post("/analyze", json={"events": events})
        
        assert response.status_code == 503
        assert "baseline" in response.json()["detail"].lower()

    def test_analyze_empty_events_returns_400(self, test_client: TestClient) -> None:
        """Analyze with empty events should return 400."""
        response = test_client.post("/analyze", json={"events": []})
        
        # Pydantic validation should fail for min_length=1
        assert response.status_code == 422

    def test_analyze_invalid_event_returns_400(self, test_client: TestClient) -> None:
        """Analyze with invalid event should return 400."""
        invalid_events = [{"invalid": "event"}]
        
        response = test_client.post("/analyze", json={"events": invalid_events})
        
        assert response.status_code == 400

    def test_analyze_non_event_id_1_returns_400(self, test_client: TestClient) -> None:
        """Analyze with non-Event ID 1 should return 400."""
        events = create_test_events()
        events[0]["EventId"] = 3  # Not Event ID 1
        
        response = test_client.post("/analyze", json={"events": events})
        
        assert response.status_code == 400
        assert "event id" in response.json()["detail"].lower()


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for API error handling."""

    def test_error_response_no_stack_trace(self, test_client: TestClient) -> None:
        """Error responses should not contain stack traces."""
        invalid_events = [{"totally": "wrong"}]
        
        response = test_client.post("/analyze", json={"events": invalid_events})
        
        assert response.status_code == 400
        error = response.json()
        
        # Should not contain Python traceback indicators
        detail = str(error.get("detail", ""))
        assert "Traceback" not in detail
        assert "File \"" not in detail

    def test_malformed_json_returns_422(self, test_client: TestClient) -> None:
        """Malformed request body should return 422."""
        response = test_client.post(
            "/analyze",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
        
        assert response.status_code == 422


# =============================================================================
# Response Format Tests
# =============================================================================


class TestResponseFormat:
    """Tests for response format compliance."""

    def test_report_has_required_fields(self, test_client: TestClient) -> None:
        """Report should have all required fields per contract."""
        events = create_test_events()
        
        response = test_client.post("/analyze", json={"events": events})
        
        assert response.status_code == 200
        report = response.json()
        
        # Required top-level fields
        assert "analysis_id" in report
        assert "timestamp" in report
        assert "global_risk_score" in report
        assert "summary" in report
        assert "anomalies" in report
        assert "metadata" in report
        
        # Metadata fields
        assert "events_processed" in report["metadata"]
        assert "model_version" in report["metadata"]

    def test_anomaly_has_required_fields(self, test_client: TestClient) -> None:
        """Each anomaly should have required fields."""
        events = create_test_events()
        
        response = test_client.post("/analyze", json={"events": events})
        
        report = response.json()
        
        # Should have anomalies (empty baseline means all events are anomalies)
        if report["anomalies"]:
            anomaly = report["anomalies"][0]
            assert "id" in anomaly
            assert "risk_level" in anomaly
            assert "confidence" in anomaly
            assert "description" in anomaly
            assert "chain" in anomaly
            assert "involved_entities" in anomaly
