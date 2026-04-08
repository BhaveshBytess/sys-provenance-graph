"""Unit tests for graph-based process analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from src.core.analyzer import AnomalyReason, AnomalyResult, build_baseline, detect_anomalies
from src.core.events import (
    CanonicalEvent,
    EventMetadata,
    EventType,
    HostInfo,
    Object,
    ObjectType,
    Parent,
    RiskLevel,
    Subject,
)
from src.core.graph_analyzer import ProcessGraph, enrich_anomalies


def _make_event(parent_image: str, child_image: str, user: str, pid: int) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=uuid4(),
        timestamp=datetime.now(timezone.utc),
        host=HostInfo(hostname="test-host", boot_id=uuid4()),
        event_type=EventType.PROCESS_CREATE,
        subject=Subject(type="process", guid=f"child-{pid}", pid=pid, image=child_image),
        parent=Parent(guid=f"parent-{pid}", image=parent_image),
        object=Object(type=ObjectType.NULL, guid=None, path_or_address=None),
        metadata=EventMetadata(command_line=f"{child_image} --run", user=user, cwd="/tmp"),
    )


def test_graph_builds_from_events() -> None:
    events = [
        _make_event("/bin/bash", "/usr/bin/python", "alice", 1),
        _make_event("/bin/bash", "/usr/bin/python", "alice", 2),
        _make_event("/bin/bash", "/usr/bin/nc", "alice", 3),
        _make_event("/usr/bin/ssh", "/usr/bin/bash", "alice", 4),
        _make_event("/usr/bin/ssh", "/usr/bin/curl", "bob", 5),
    ]

    graph = ProcessGraph(events)

    assert graph.graph.number_of_nodes() == 6
    assert graph.graph.number_of_edges() == 4
    assert graph.graph["/bin/bash"]["/usr/bin/python"]["weight"] == 2
    assert graph.graph["/bin/bash"]["/usr/bin/nc"]["weight"] == 1


def test_node_features_correct() -> None:
    events = [
        _make_event("/bin/bash", "/usr/bin/python", "alice", 10),
        _make_event("/bin/bash", "/usr/bin/nc", "alice", 11),
        _make_event("/bin/bash", "/usr/bin/curl", "bob", 12),
    ]

    graph = ProcessGraph(events)
    features = graph.get_node_features("/bin/bash")

    assert features["in_degree"] == 0
    assert features["out_degree"] == 3
    assert features["total_spawned"] == 3


def test_edge_features_correct() -> None:
    events = [
        _make_event("/bin/bash", "/usr/bin/python", "alice", 20),
        _make_event("/bin/bash", "/usr/bin/python", "alice", 21),
        _make_event("/bin/bash", "/usr/bin/python", "alice", 22),
        _make_event("/bin/bash", "/usr/bin/nc", "alice", 23),
    ]

    graph = ProcessGraph(events)

    python_edge = graph.get_edge_features("/bin/bash", "/usr/bin/python")
    nc_edge = graph.get_edge_features("/bin/bash", "/usr/bin/nc")

    assert python_edge["weight"] == 3
    assert nc_edge["weight"] == 1
    assert python_edge["fraction_of_parent"] == 0.75
    assert nc_edge["fraction_of_parent"] == 0.25


def test_enrich_anomalies_adds_context() -> None:
    baseline_events = [
        _make_event("/bin/bash", "/usr/bin/python", "alice", 30),
        _make_event("/bin/bash", "/usr/bin/curl", "alice", 31),
        _make_event("/usr/bin/ssh", "/bin/bash", "alice", 32),
    ]
    test_events = [_make_event("/usr/bin/ssh", "/usr/bin/nc", "alice", 33)]

    baseline = build_baseline(baseline_events)
    anomalies = detect_anomalies(test_events, baseline)

    baseline_graph = ProcessGraph(baseline_events)
    test_graph = ProcessGraph(test_events)

    enriched = enrich_anomalies(anomalies, baseline_graph, test_graph)

    assert len(enriched) == 1
    assert "graph_risk_factors" in enriched[0]
    assert enriched[0]["graph_risk_factors"]
    assert all(isinstance(item, str) and item.strip() for item in enriched[0]["graph_risk_factors"])


def test_enrich_anomalies_unknown_node() -> None:
    baseline_events = [
        _make_event("/bin/bash", "/usr/bin/python", "alice", 40),
        _make_event("/usr/bin/ssh", "/bin/bash", "alice", 41),
    ]

    unknown_event = _make_event("/usr/bin/ssh", "/usr/bin/evil", "alice", 42)
    anomaly = AnomalyResult(
        event=unknown_event,
        reason=AnomalyReason.UNKNOWN,
        relationship_key=("/usr/bin/ssh", "/usr/bin/evil", "alice"),
        observed_count=0,
        baseline_total=len(baseline_events),
        risk_level=RiskLevel.CRITICAL,
        confidence=1.0,
        description="Unknown relationship test",
    )

    baseline_graph = ProcessGraph(baseline_events)
    test_graph = ProcessGraph([unknown_event])

    enriched = enrich_anomalies([anomaly], baseline_graph, test_graph)
    joined = " ".join(enriched[0]["graph_risk_factors"]).lower()

    assert "never seen in baseline" in joined


def test_graph_stats() -> None:
    events = [
        _make_event("A", "B", "alice", 50),
        _make_event("A", "C", "alice", 51),
        _make_event("D", "E", "bob", 52),
    ]

    graph = ProcessGraph(events)
    stats = graph.get_graph_stats()

    assert stats["total_nodes"] == 5
    assert stats["total_edges"] == 3
    assert abs(stats["density"] - 0.15) < 1e-9
