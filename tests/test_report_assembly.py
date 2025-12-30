"""
test_report_assembly.py - Unit tests for report assembly.

Verifies report generation, risk scoring, entity resolution,
and contract fidelity.
"""

from datetime import datetime
from uuid import uuid4

import pytest

from src.core.analyzer import (
    RISK_LEVEL_SCORES,
    AnomalyReason,
    AnomalyResult,
    BaselineProfile,
    assemble_report,
    build_baseline,
    build_event_index,
    detect_anomalies,
    enrich_anomalies_with_chains,
)
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
    RiskLevel,
    Subject,
)


# =============================================================================
# Test Fixtures
# =============================================================================


def create_event_with_guids(
    subject_guid: str,
    parent_guid: str,
    image: str = "/usr/bin/process",
    user: str = "root",
) -> CanonicalEvent:
    """Create a CanonicalEvent with specific GUIDs."""
    return CanonicalEvent(
        event_id=uuid4(),
        timestamp=datetime.now(),
        host=HostInfo(hostname="test-host", boot_id=uuid4()),
        event_type=EventType.PROCESS_CREATE,
        subject=Subject(
            type="process",
            guid=subject_guid,
            pid=1234,
            image=image,
        ),
        parent=Parent(
            guid=parent_guid,
            image="/bin/parent",
        ),
        object=Object(
            type=ObjectType.NULL,
            guid=None,
            path_or_address=None,
        ),
        metadata=EventMetadata(
            command_line=f"{image} --run",
            user=user,
            cwd="/home/user",
        ),
    )


def create_anomaly_result(
    event: CanonicalEvent,
    risk_level: RiskLevel = RiskLevel.CRITICAL,
    reason: AnomalyReason = AnomalyReason.UNKNOWN,
) -> AnomalyResult:
    """Create an AnomalyResult for testing."""
    return AnomalyResult(
        event=event,
        reason=reason,
        relationship_key=(
            event.parent.image,
            event.subject.image,
            event.metadata.user,
        ),
        observed_count=0,
        baseline_total=100,
        risk_level=risk_level,
        confidence=0.95,
        description=f"Test anomaly for {event.subject.image}",
    )


@pytest.fixture
def sample_events() -> list[CanonicalEvent]:
    """Create a sample chain of events."""
    return [
        create_event_with_guids("root-guid", "missing", "/sbin/init"),
        create_event_with_guids("parent-guid", "root-guid", "/bin/bash"),
        create_event_with_guids("child-guid", "parent-guid", "/usr/bin/python"),
    ]


@pytest.fixture
def sample_anomalies(sample_events: list[CanonicalEvent]) -> list[AnomalyResult]:
    """Create sample anomalies from sample events."""
    return [
        create_anomaly_result(sample_events[-1], RiskLevel.CRITICAL),
    ]


@pytest.fixture
def sample_baseline() -> BaselineProfile:
    """Create an empty baseline for testing."""
    return BaselineProfile()


# =============================================================================
# Report Generation Tests
# =============================================================================


class TestReportGeneration:
    """Tests for basic report generation."""

    def test_generates_valid_report(
        self,
        sample_events: list[CanonicalEvent],
        sample_anomalies: list[AnomalyResult],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Should generate a valid AnalysisReport."""
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains(sample_anomalies, index)
        
        report = assemble_report(
            sample_anomalies, chains, index, sample_baseline, len(sample_events)
        )
        
        assert isinstance(report, AnalysisReport)
        assert report.analysis_id is not None
        assert report.timestamp is not None

    def test_empty_anomalies_empty_report(
        self,
        sample_events: list[CanonicalEvent],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Empty anomalies should produce report with no anomalies."""
        index = build_event_index(sample_events)
        
        report = assemble_report(
            [], {}, index, sample_baseline, len(sample_events)
        )
        
        assert len(report.anomalies) == 0
        assert report.global_risk_score == 0
        assert "No anomalies detected" in report.summary

    def test_report_contains_all_anomalies(
        self,
        sample_events: list[CanonicalEvent],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Report should contain all detected anomalies."""
        # Create multiple anomalies
        anomalies = [
            create_anomaly_result(sample_events[1], RiskLevel.HIGH),
            create_anomaly_result(sample_events[2], RiskLevel.CRITICAL),
        ]
        
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains(anomalies, index)
        
        report = assemble_report(
            anomalies, chains, index, sample_baseline, len(sample_events)
        )
        
        assert len(report.anomalies) == 2


# =============================================================================
# Risk Scoring Tests (Constraint #2 - MAX Method)
# =============================================================================


class TestRiskScoring:
    """Tests for deterministic MAX risk scoring."""

    def test_max_method_single_critical(
        self,
        sample_events: list[CanonicalEvent],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Single CRITICAL anomaly should give score of 100."""
        anomalies = [
            create_anomaly_result(sample_events[-1], RiskLevel.CRITICAL),
        ]
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains(anomalies, index)
        
        report = assemble_report(
            anomalies, chains, index, sample_baseline, len(sample_events)
        )
        
        assert report.global_risk_score == 100

    def test_max_method_highest_wins(
        self,
        sample_events: list[CanonicalEvent],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Multiple anomalies should use highest score (MAX method)."""
        anomalies = [
            create_anomaly_result(sample_events[0], RiskLevel.LOW),
            create_anomaly_result(sample_events[1], RiskLevel.HIGH),
            create_anomaly_result(sample_events[2], RiskLevel.MEDIUM),
        ]
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains(anomalies, index)
        
        report = assemble_report(
            anomalies, chains, index, sample_baseline, len(sample_events)
        )
        
        # HIGH = 70 is the max
        assert report.global_risk_score == 70

    def test_risk_score_mapping(self) -> None:
        """Risk level scores should follow defined mapping."""
        assert RISK_LEVEL_SCORES["LOW"] == 10
        assert RISK_LEVEL_SCORES["MEDIUM"] == 40
        assert RISK_LEVEL_SCORES["HIGH"] == 70
        assert RISK_LEVEL_SCORES["CRITICAL"] == 100

    def test_deterministic_across_runs(
        self,
        sample_events: list[CanonicalEvent],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Same inputs should always produce same risk score."""
        anomalies = [
            create_anomaly_result(sample_events[-1], RiskLevel.HIGH),
        ]
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains(anomalies, index)
        
        scores = [
            assemble_report(
                anomalies, chains, index, sample_baseline, len(sample_events)
            ).global_risk_score
            for _ in range(5)
        ]
        
        # All scores should be identical
        assert all(s == 70 for s in scores)


# =============================================================================
# Entity Resolution Tests (Constraint #3)
# =============================================================================


class TestEntityResolution:
    """Tests for entity resolution from chains."""

    def test_entities_resolved_from_event_index(
        self,
        sample_events: list[CanonicalEvent],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Entity attributes should be resolved from event_index."""
        anomalies = [
            create_anomaly_result(sample_events[-1], RiskLevel.CRITICAL),
        ]
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains(anomalies, index)
        
        report = assemble_report(
            anomalies, chains, index, sample_baseline, len(sample_events)
        )
        
        # Find the child entity (anomalous event)
        child_entity = next(
            e for e in report.anomalies[0].involved_entities
            if e.role == EntityRole.CHILD
        )
        
        # Image should be resolved from event
        assert child_entity.image == "/usr/bin/python"

    def test_entities_deduplicated_by_guid(
        self,
        sample_baseline: BaselineProfile,
    ) -> None:
        """Entities should be deduplicated by GUID."""
        # Create events with repeated GUID in chain (hypothetical)
        events = [
            create_event_with_guids("guid-a", "guid-b", "/bin/a"),
            create_event_with_guids("guid-b", "guid-a", "/bin/b"),  # Cycle
        ]
        
        anomalies = [
            create_anomaly_result(events[0], RiskLevel.HIGH),
        ]
        index = build_event_index(events)
        chains = {"guid-a": ["guid-b", "guid-a"]}  # Chain with potential duplicate context
        
        report = assemble_report(
            anomalies, chains, index, sample_baseline, len(events)
        )
        
        # Each GUID should appear only once in entities
        guids = [e.guid for e in report.anomalies[0].involved_entities]
        assert len(guids) == len(set(guids))

    def test_missing_guid_gets_unknown_image(
        self,
        sample_baseline: BaselineProfile,
    ) -> None:
        """GUIDs not in index should get '<unknown>' image."""
        events = [
            create_event_with_guids("known-guid", "missing-guid", "/bin/known"),
        ]
        
        anomalies = [
            create_anomaly_result(events[0], RiskLevel.HIGH),
        ]
        index = build_event_index(events)
        # Chain includes missing-guid which is not in index
        chains = {"known-guid": ["missing-guid", "known-guid"]}
        
        report = assemble_report(
            anomalies, chains, index, sample_baseline, len(events)
        )
        
        # Find the entity for missing GUID
        missing_entity = next(
            e for e in report.anomalies[0].involved_entities
            if e.guid == "missing-guid"
        )
        assert missing_entity.image == "<unknown>"

    def test_entity_roles_assigned_correctly(
        self,
        sample_events: list[CanonicalEvent],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Last entity in chain should be CHILD, others PARENT."""
        anomalies = [
            create_anomaly_result(sample_events[-1], RiskLevel.CRITICAL),
        ]
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains(anomalies, index)
        
        report = assemble_report(
            anomalies, chains, index, sample_baseline, len(sample_events)
        )
        
        entities = report.anomalies[0].involved_entities
        
        # Last entity should be CHILD
        assert entities[-1].role == EntityRole.CHILD
        
        # All others should be PARENT
        for entity in entities[:-1]:
            assert entity.role == EntityRole.PARENT


# =============================================================================
# No Semantic Inference Tests (Constraint #4)
# =============================================================================


class TestNoSemanticInference:
    """Tests verifying no interpretive labels are added."""

    def test_summary_is_factual(
        self,
        sample_events: list[CanonicalEvent],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Summary should be factual, not interpretive."""
        anomalies = [
            create_anomaly_result(sample_events[-1], RiskLevel.CRITICAL),
        ]
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains(anomalies, index)
        
        report = assemble_report(
            anomalies, chains, index, sample_baseline, len(sample_events)
        )
        
        # Summary should mention count and score, not interpretations
        assert "1" in report.summary or "anomal" in report.summary.lower()
        assert "100" in report.summary
        
        # Should NOT contain semantic labels
        forbidden_terms = ["attack", "exploit", "malware", "intrusion", "breach"]
        for term in forbidden_terms:
            assert term not in report.summary.lower()

    def test_anomaly_description_preserved(
        self,
        sample_events: list[CanonicalEvent],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Anomaly descriptions should be preserved as-is."""
        test_description = "Test anomaly description without interpretation"
        event = sample_events[-1]
        
        anomaly = AnomalyResult(
            event=event,
            reason=AnomalyReason.UNKNOWN,
            relationship_key=(event.parent.image, event.subject.image, "root"),
            observed_count=0,
            baseline_total=100,
            risk_level=RiskLevel.HIGH,
            confidence=0.9,
            description=test_description,
        )
        
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains([anomaly], index)
        
        report = assemble_report(
            [anomaly], chains, index, sample_baseline, len(sample_events)
        )
        
        assert report.anomalies[0].description == test_description


# =============================================================================
# Contract Fidelity Tests (Constraint #5)
# =============================================================================


class TestContractFidelity:
    """Tests for output contract compliance."""

    def test_report_is_immutable(
        self,
        sample_events: list[CanonicalEvent],
        sample_anomalies: list[AnomalyResult],
        sample_baseline: BaselineProfile,
    ) -> None:
        """AnalysisReport should be immutable (frozen)."""
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains(sample_anomalies, index)
        
        report = assemble_report(
            sample_anomalies, chains, index, sample_baseline, len(sample_events)
        )
        
        # Report should be frozen (immutable)
        with pytest.raises(Exception):  # ValidationError or similar
            report.global_risk_score = 50  # type: ignore

    def test_report_metadata_populated(
        self,
        sample_events: list[CanonicalEvent],
        sample_anomalies: list[AnomalyResult],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Report metadata should be populated correctly."""
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains(sample_anomalies, index)
        
        report = assemble_report(
            sample_anomalies, chains, index, sample_baseline, len(sample_events)
        )
        
        assert report.metadata.events_processed == len(sample_events)
        assert report.metadata.model_version == sample_baseline.version

    def test_anomaly_chain_populated(
        self,
        sample_events: list[CanonicalEvent],
        sample_anomalies: list[AnomalyResult],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Each anomaly should have a populated chain."""
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains(sample_anomalies, index)
        
        report = assemble_report(
            sample_anomalies, chains, index, sample_baseline, len(sample_events)
        )
        
        for anomaly in report.anomalies:
            assert len(anomaly.chain) >= 1
            assert len(anomaly.involved_entities) >= 1

    def test_anomaly_has_required_fields(
        self,
        sample_events: list[CanonicalEvent],
        sample_anomalies: list[AnomalyResult],
        sample_baseline: BaselineProfile,
    ) -> None:
        """Each Anomaly should have all required fields."""
        index = build_event_index(sample_events)
        chains = enrich_anomalies_with_chains(sample_anomalies, index)
        
        report = assemble_report(
            sample_anomalies, chains, index, sample_baseline, len(sample_events)
        )
        
        for anomaly in report.anomalies:
            assert anomaly.id is not None
            assert anomaly.risk_level is not None
            assert 0.0 <= anomaly.confidence <= 1.0
            assert len(anomaly.description) > 0
            assert len(anomaly.chain) >= 1
