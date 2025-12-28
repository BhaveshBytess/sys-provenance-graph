"""
test_events.py - Unit tests for canonical event and report schemas.

Verifies that the Pydantic models in src/core/events.py correctly
implement the contracts defined in CONTRACTS.md.
"""

from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from src.core.events import (
    AnalysisReport,
    Anomaly,
    CanonicalEvent,
    EntityRole,
    EventMetadata,
    EventType,
    HostInfo,
    InvolvedEntity,
    Object,
    ObjectType,
    Parent,
    ReportMetadata,
    RiskLevel,
    Subject,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def valid_host_info() -> dict:
    """Valid HostInfo data."""
    return {
        "hostname": "test-server-01",
        "boot_id": str(uuid4()),
    }


@pytest.fixture
def valid_subject() -> dict:
    """Valid Subject data."""
    return {
        "type": "process",
        "guid": "ABC123-GUID",
        "pid": 1234,
        "image": "/usr/bin/python3",
    }


@pytest.fixture
def valid_parent() -> dict:
    """Valid Parent data."""
    return {
        "guid": "PARENT-GUID-456",
        "image": "/bin/bash",
    }


@pytest.fixture
def valid_object() -> dict:
    """Valid Object data."""
    return {
        "type": "file",
        "guid": None,
        "path_or_address": "/etc/passwd",
    }


@pytest.fixture
def valid_metadata() -> dict:
    """Valid EventMetadata data."""
    return {
        "command_line": "python3 script.py --verbose",
        "user": "root",
        "cwd": "/home/user",
    }


@pytest.fixture
def valid_canonical_event(
    valid_host_info, valid_subject, valid_parent, valid_object, valid_metadata
) -> dict:
    """Valid CanonicalEvent data."""
    return {
        "event_id": str(uuid4()),
        "timestamp": datetime.now().isoformat(),
        "host": valid_host_info,
        "event_type": "PROCESS_CREATE",
        "subject": valid_subject,
        "parent": valid_parent,
        "object": valid_object,
        "metadata": valid_metadata,
    }


# =============================================================================
# CanonicalEvent Tests
# =============================================================================


class TestCanonicalEvent:
    """Tests for the CanonicalEvent input schema."""

    def test_valid_event_creation(self, valid_canonical_event: dict) -> None:
        """Test that a valid event can be created successfully."""
        event = CanonicalEvent(**valid_canonical_event)
        
        assert event.event_type == EventType.PROCESS_CREATE
        assert event.subject.guid == valid_canonical_event["subject"]["guid"]
        assert event.parent.guid == valid_canonical_event["parent"]["guid"]

    def test_event_is_immutable(self, valid_canonical_event: dict) -> None:
        """Test that CanonicalEvent is frozen (immutable)."""
        event = CanonicalEvent(**valid_canonical_event)
        
        with pytest.raises(ValidationError):
            event.event_type = EventType.PROCESS_CREATE  # type: ignore

    def test_missing_required_field_raises_error(self, valid_canonical_event: dict) -> None:
        """Test that missing required fields raise ValidationError."""
        del valid_canonical_event["subject"]
        
        with pytest.raises(ValidationError) as exc_info:
            CanonicalEvent(**valid_canonical_event)
        
        assert "subject" in str(exc_info.value)

    def test_invalid_event_type_raises_error(self, valid_canonical_event: dict) -> None:
        """Test that invalid event_type raises ValidationError."""
        valid_canonical_event["event_type"] = "INVALID_TYPE"
        
        with pytest.raises(ValidationError) as exc_info:
            CanonicalEvent(**valid_canonical_event)
        
        assert "event_type" in str(exc_info.value)

    def test_guid_is_primary_identifier(self, valid_canonical_event: dict) -> None:
        """Test that GUID is used as primary identifier, not PID."""
        event = CanonicalEvent(**valid_canonical_event)
        
        # GUID should be accessible and non-empty
        assert event.subject.guid is not None
        assert len(event.subject.guid) > 0
        
        # PID is informational only
        assert isinstance(event.subject.pid, int)

    def test_event_with_null_object(self, valid_canonical_event: dict) -> None:
        """Test that object can have null type."""
        valid_canonical_event["object"] = {
            "type": "null",
            "guid": None,
            "path_or_address": None,
        }
        
        event = CanonicalEvent(**valid_canonical_event)
        assert event.object.type == ObjectType.NULL


class TestSubject:
    """Tests for the Subject model."""

    def test_valid_subject_creation(self, valid_subject: dict) -> None:
        """Test that a valid subject can be created."""
        subject = Subject(**valid_subject)
        
        assert subject.guid == valid_subject["guid"]
        assert subject.pid == valid_subject["pid"]
        assert subject.image == valid_subject["image"]

    def test_subject_default_type_is_process(self) -> None:
        """Test that subject type defaults to 'process'."""
        subject = Subject(guid="test-guid", pid=123, image="/bin/test")
        assert subject.type == "process"

    def test_subject_is_immutable(self, valid_subject: dict) -> None:
        """Test that Subject is frozen (immutable)."""
        subject = Subject(**valid_subject)
        
        with pytest.raises(ValidationError):
            subject.pid = 9999  # type: ignore


# =============================================================================
# AnalysisReport Tests
# =============================================================================


class TestAnalysisReport:
    """Tests for the AnalysisReport output schema."""

    def test_valid_report_creation_no_anomalies(self) -> None:
        """Test that a valid report with no anomalies can be created."""
        report = AnalysisReport(
            analysis_id=uuid4(),
            timestamp=datetime.now(),
            global_risk_score=0,
            summary="No anomalies detected.",
            anomalies=[],
            metadata=ReportMetadata(events_processed=100, model_version="1.0.0"),
        )
        
        assert report.global_risk_score == 0
        assert len(report.anomalies) == 0

    def test_valid_report_with_anomaly(self) -> None:
        """Test that a valid report with anomalies can be created."""
        anomaly = Anomaly(
            id="anomaly-001",
            risk_level=RiskLevel.HIGH,
            confidence=0.95,
            description="Unusual parent-child relationship detected.",
            chain=["parent-guid", "child-guid"],
            involved_entities=[
                InvolvedEntity(guid="parent-guid", image="/bin/bash", role=EntityRole.PARENT),
                InvolvedEntity(guid="child-guid", image="/usr/bin/curl", role=EntityRole.CHILD),
            ],
        )
        
        report = AnalysisReport(
            analysis_id=uuid4(),
            timestamp=datetime.now(),
            global_risk_score=75,
            summary="1 high-risk anomaly detected.",
            anomalies=[anomaly],
            metadata=ReportMetadata(events_processed=50, model_version="1.0.0"),
        )
        
        assert report.global_risk_score == 75
        assert len(report.anomalies) == 1
        assert report.anomalies[0].risk_level == RiskLevel.HIGH

    def test_report_is_immutable(self) -> None:
        """Test that AnalysisReport is frozen (immutable)."""
        report = AnalysisReport(
            analysis_id=uuid4(),
            timestamp=datetime.now(),
            global_risk_score=0,
            summary="Test",
            anomalies=[],
            metadata=ReportMetadata(events_processed=0, model_version="1.0.0"),
        )
        
        with pytest.raises(ValidationError):
            report.global_risk_score = 100  # type: ignore

    def test_risk_score_must_be_in_range(self) -> None:
        """Test that global_risk_score must be between 0 and 100."""
        with pytest.raises(ValidationError) as exc_info:
            AnalysisReport(
                analysis_id=uuid4(),
                timestamp=datetime.now(),
                global_risk_score=150,  # Invalid: > 100
                summary="Test",
                anomalies=[],
                metadata=ReportMetadata(events_processed=0, model_version="1.0.0"),
            )
        
        assert "global_risk_score" in str(exc_info.value)


class TestAnomaly:
    """Tests for the Anomaly model."""

    def test_anomaly_requires_chain(self) -> None:
        """Test that anomaly must have at least one chain element."""
        with pytest.raises(ValidationError) as exc_info:
            Anomaly(
                id="test-anomaly",
                risk_level=RiskLevel.LOW,
                confidence=0.5,
                description="Test anomaly",
                chain=[],  # Invalid: empty chain
                involved_entities=[],
            )
        
        assert "chain" in str(exc_info.value)

    def test_confidence_must_be_in_range(self) -> None:
        """Test that confidence must be between 0.0 and 1.0."""
        with pytest.raises(ValidationError):
            Anomaly(
                id="test-anomaly",
                risk_level=RiskLevel.LOW,
                confidence=1.5,  # Invalid: > 1.0
                description="Test anomaly",
                chain=["guid-1"],
                involved_entities=[],
            )

    def test_all_risk_levels_valid(self) -> None:
        """Test that all risk levels can be used."""
        for risk_level in RiskLevel:
            anomaly = Anomaly(
                id=f"anomaly-{risk_level.value}",
                risk_level=risk_level,
                confidence=0.5,
                description=f"Test {risk_level.value} anomaly",
                chain=["guid-1"],
                involved_entities=[],
            )
            assert anomaly.risk_level == risk_level


# =============================================================================
# Integration Tests
# =============================================================================


class TestContractCompliance:
    """Tests verifying compliance with CONTRACTS.md."""

    def test_event_identity_uses_guid_not_pid(self, valid_canonical_event: dict) -> None:
        """
        CONTRACTS.md §3.2: subject.guid is the PRIMARY identifier.
        PIDs are informational only.
        """
        event = CanonicalEvent(**valid_canonical_event)
        
        # Two events with same PID but different GUIDs are different
        valid_canonical_event["subject"]["pid"] = event.subject.pid
        valid_canonical_event["subject"]["guid"] = "DIFFERENT-GUID"
        event2 = CanonicalEvent(**valid_canonical_event)
        
        assert event.subject.guid != event2.subject.guid
        assert event.subject.pid == event2.subject.pid

    def test_only_process_create_event_type_supported(
        self, valid_canonical_event: dict
    ) -> None:
        """
        CONTRACTS.md §3.3: Only PROCESS_CREATE is supported in V1.
        """
        # PROCESS_CREATE should work
        valid_canonical_event["event_type"] = "PROCESS_CREATE"
        event = CanonicalEvent(**valid_canonical_event)
        assert event.event_type == EventType.PROCESS_CREATE
        
        # Other types should fail
        valid_canonical_event["event_type"] = "FILE_CREATE"
        with pytest.raises(ValidationError):
            CanonicalEvent(**valid_canonical_event)

    def test_anomaly_must_have_description(self) -> None:
        """
        CONTRACTS.md §4.2: Every anomaly MUST include an explanation.
        """
        with pytest.raises(ValidationError):
            Anomaly(
                id="test",
                risk_level=RiskLevel.LOW,
                confidence=0.5,
                # Missing description
                chain=["guid-1"],
                involved_entities=[],
            )

    def test_anomaly_must_reference_chain(self) -> None:
        """
        CONTRACTS.md §4.2: Every anomaly MUST reference at least one process chain.
        """
        with pytest.raises(ValidationError):
            Anomaly(
                id="test",
                risk_level=RiskLevel.LOW,
                confidence=0.5,
                description="Test",
                chain=[],  # Empty chain violates contract
                involved_entities=[],
            )
