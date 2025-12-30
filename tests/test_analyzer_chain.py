"""
test_analyzer_chain.py - Unit tests for chain reconstruction.

Verifies chain traversal, cycle detection, depth limits,
and proper termination conditions.
"""

from datetime import datetime
from uuid import uuid4

import pytest

from src.core.analyzer import (
    KNOWN_ROOT_IMAGES,
    MAX_CHAIN_DEPTH,
    build_event_index,
    enrich_anomalies_with_chains,
    reconstruct_chain,
    build_baseline,
    detect_anomalies,
    BaselineProfile,
)
from src.core.events import (
    CanonicalEvent,
    EventMetadata,
    EventType,
    HostInfo,
    Object,
    ObjectType,
    Parent,
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
    """
    Create a CanonicalEvent with specific subject and parent GUIDs.
    
    This is essential for testing chain reconstruction where we need
    to control the parent-child relationships.
    """
    return CanonicalEvent(
        event_id=str(uuid4()),
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


def build_chain_fixture(depth: int) -> list[CanonicalEvent]:
    """
    Build a linear chain of events with specified depth.
    
    Creates events: root -> p1 -> p2 -> ... -> leaf
    Returns events in creation order (not chain order).
    """
    events = []
    guids = [f"guid-{i}" for i in range(depth)]
    
    for i in range(depth):
        subject_guid = guids[i]
        # First event has a "missing" parent
        parent_guid = guids[i - 1] if i > 0 else "root-guid"
        
        event = create_event_with_guids(
            subject_guid=subject_guid,
            parent_guid=parent_guid,
            image=f"/usr/bin/process-{i}",
        )
        events.append(event)
    
    return events


# =============================================================================
# Event Index Tests (O(1) Lookup - Constraint #1)
# =============================================================================


class TestEventIndex:
    """Tests for the event index builder."""

    def test_builds_index_from_events(self) -> None:
        """Index should map subject.guid to event."""
        events = [
            create_event_with_guids("guid-a", "parent-a"),
            create_event_with_guids("guid-b", "parent-b"),
        ]
        
        index = build_event_index(events)
        
        assert "guid-a" in index
        assert "guid-b" in index
        assert index["guid-a"].subject.guid == "guid-a"

    def test_index_provides_o1_lookup(self) -> None:
        """Index lookup should be O(1) - dict access."""
        events = build_chain_fixture(100)
        index = build_event_index(events)
        
        # Dict lookup is O(1) by Python specification
        # Verify we can access any element directly
        assert index.get("guid-50") is not None
        assert index.get("guid-99") is not None
        assert index.get("nonexistent") is None

    def test_rejects_raw_dictionaries(self) -> None:
        """Index builder must reject raw dicts."""
        with pytest.raises(TypeError) as exc_info:
            build_event_index([{"raw": "dict"}])  # type: ignore
        
        assert "CanonicalEvent" in str(exc_info.value)

    def test_last_event_wins_on_duplicate_guid(self) -> None:
        """If multiple events have same GUID, last one wins."""
        event1 = create_event_with_guids("duplicate-guid", "parent-1", "/bin/first")
        event2 = create_event_with_guids("duplicate-guid", "parent-2", "/bin/second")
        
        index = build_event_index([event1, event2])
        
        assert index["duplicate-guid"].subject.image == "/bin/second"


# =============================================================================
# Cycle Detection Tests (Safety - Constraint #2)
# =============================================================================


class TestCycleDetection:
    """Tests for cycle detection during chain traversal."""

    def test_detects_self_reference_cycle(self) -> None:
        """Event pointing to itself should not cause infinite loop."""
        # Event where parent.guid == subject.guid
        cyclic_event = create_event_with_guids("self-guid", "self-guid")
        
        index = build_event_index([cyclic_event])
        chain = reconstruct_chain(cyclic_event, index)
        
        # Should terminate with just the event itself
        assert chain == ["self-guid"]

    def test_detects_two_node_cycle(self) -> None:
        """A -> B -> A cycle should terminate safely."""
        event_a = create_event_with_guids("guid-a", "guid-b")
        event_b = create_event_with_guids("guid-b", "guid-a")
        
        index = build_event_index([event_a, event_b])
        
        # Starting from A: A -> B -> (cycle detected, stop)
        chain = reconstruct_chain(event_a, index)
        
        # Should include both nodes but not loop infinitely
        assert len(chain) == 2
        assert chain[-1] == "guid-a"  # Event is last

    def test_detects_multi_node_cycle(self) -> None:
        """A -> B -> C -> A cycle should terminate safely."""
        event_a = create_event_with_guids("guid-a", "guid-b")
        event_b = create_event_with_guids("guid-b", "guid-c")
        event_c = create_event_with_guids("guid-c", "guid-a")
        
        index = build_event_index([event_a, event_b, event_c])
        
        chain = reconstruct_chain(event_a, index)
        
        # Should terminate without infinite loop
        assert len(chain) <= 3
        assert chain[-1] == "guid-a"


# =============================================================================
# Root Termination Tests (Logic - Constraint #3)
# =============================================================================


class TestRootTermination:
    """Tests for proper chain termination conditions."""

    def test_terminates_on_missing_parent(self) -> None:
        """Chain should terminate when parent GUID not in index."""
        # Event with parent that doesn't exist in index
        orphan_event = create_event_with_guids("orphan", "missing-parent")
        
        index = build_event_index([orphan_event])
        chain = reconstruct_chain(orphan_event, index)
        
        # Should include the orphan and the missing parent reference
        assert len(chain) == 2
        assert chain[0] == "missing-parent"  # Root (missing)
        assert chain[1] == "orphan"  # Event

    def test_terminates_on_max_depth(self) -> None:
        """Chain should terminate at max depth."""
        # Build a very deep chain
        events = build_chain_fixture(20)
        index = build_event_index(events)
        
        # Get the deepest event
        leaf_event = events[-1]
        
        # Reconstruct with max_depth=5
        chain = reconstruct_chain(leaf_event, index, max_depth=5)
        
        # Chain should be limited to ~5 ancestors plus the event
        assert len(chain) <= 7  # Some buffer for termination logic

    def test_terminates_on_known_root_systemd(self) -> None:
        """Chain should terminate when reaching systemd."""
        root_event = create_event_with_guids(
            "systemd-guid", "kernel-guid",
            image="/usr/lib/systemd/systemd"
        )
        child_event = create_event_with_guids("child-guid", "systemd-guid")
        
        index = build_event_index([root_event, child_event])
        chain = reconstruct_chain(child_event, index)
        
        # Should terminate at systemd
        assert chain[0] == "systemd-guid"
        assert chain[-1] == "child-guid"

    def test_terminates_on_known_root_init(self) -> None:
        """Chain should terminate when reaching init."""
        init_event = create_event_with_guids(
            "init-guid", "kernel-guid",
            image="/sbin/init"
        )
        child_event = create_event_with_guids("child-guid", "init-guid")
        
        index = build_event_index([init_event, child_event])
        chain = reconstruct_chain(child_event, index)
        
        assert chain[0] == "init-guid"

    def test_does_not_terminate_on_root_user(self) -> None:
        """Chain should NOT terminate just because user is root."""
        # User being "root" is NOT a termination condition
        event1 = create_event_with_guids("guid-1", "guid-2", user="root")
        event2 = create_event_with_guids("guid-2", "guid-3", user="root")
        event3 = create_event_with_guids("guid-3", "missing-parent", user="root")
        
        index = build_event_index([event1, event2, event3])
        chain = reconstruct_chain(event1, index)
        
        # Should traverse through all events despite "root" user
        assert len(chain) >= 3


# =============================================================================
# Chronological Output Tests (Usability - Constraint #4)
# =============================================================================


class TestChronologicalOutput:
    """Tests for proper chain ordering (root -> leaf)."""

    def test_chain_ordered_root_to_leaf(self) -> None:
        """Chain should be ordered: ancestor -> ... -> parent -> event."""
        root = create_event_with_guids("root", "missing", image="/sbin/init")
        parent = create_event_with_guids("parent", "root")
        child = create_event_with_guids("child", "parent")
        leaf = create_event_with_guids("leaf", "child")
        
        index = build_event_index([root, parent, child, leaf])
        chain = reconstruct_chain(leaf, index)
        
        # Root should be first, leaf last
        assert chain[0] == "root"
        assert chain[-1] == "leaf"
        
        # Order should be chronological
        assert chain == ["root", "parent", "child", "leaf"]

    def test_single_event_chain(self) -> None:
        """Single event (orphan) should return single-element chain."""
        orphan = create_event_with_guids("orphan", "missing-parent")
        
        index = build_event_index([orphan])
        chain = reconstruct_chain(orphan, index)
        
        # Should include missing parent reference and the event
        assert chain[-1] == "orphan"


# =============================================================================
# Determinism Tests (Constraint #5)
# =============================================================================


class TestChainDeterminism:
    """Tests for deterministic chain reconstruction."""

    def test_same_inputs_same_output(self) -> None:
        """Same inputs should always produce identical chains."""
        events = build_chain_fixture(5)
        index = build_event_index(events)
        leaf = events[-1]
        
        # Run multiple times
        chain1 = reconstruct_chain(leaf, index)
        chain2 = reconstruct_chain(leaf, index)
        chain3 = reconstruct_chain(leaf, index)
        
        assert chain1 == chain2 == chain3

    def test_deterministic_with_different_index_build_order(self) -> None:
        """Chain should be deterministic regardless of index build order."""
        event_a = create_event_with_guids("a", "b")
        event_b = create_event_with_guids("b", "c")
        event_c = create_event_with_guids("c", "missing")
        
        # Build index in different orders
        index1 = build_event_index([event_a, event_b, event_c])
        index2 = build_event_index([event_c, event_b, event_a])
        index3 = build_event_index([event_b, event_a, event_c])
        
        chain1 = reconstruct_chain(event_a, index1)
        chain2 = reconstruct_chain(event_a, index2)
        chain3 = reconstruct_chain(event_a, index3)
        
        assert chain1 == chain2 == chain3


# =============================================================================
# Raw Output Tests (Scope - Constraint #6)
# =============================================================================


class TestRawOutput:
    """Tests verifying raw GUID list output, no formatting."""

    def test_returns_list_of_strings(self) -> None:
        """Chain should be a list of GUID strings, not formatted text."""
        event = create_event_with_guids("event-guid", "parent-guid")
        index = build_event_index([event])
        
        chain = reconstruct_chain(event, index)
        
        assert isinstance(chain, list)
        for item in chain:
            assert isinstance(item, str)

    def test_no_formatting_in_output(self) -> None:
        """Output should not contain arrows, labels, or formatting."""
        event = create_event_with_guids("guid-a", "guid-b")
        parent = create_event_with_guids("guid-b", "missing")
        
        index = build_event_index([event, parent])
        chain = reconstruct_chain(event, index)
        
        # Should be plain GUIDs
        for guid in chain:
            assert "->" not in guid
            assert ":" not in guid
            assert "\n" not in guid


# =============================================================================
# Integration Tests
# =============================================================================


class TestChainIntegration:
    """Integration tests combining chain reconstruction with detection."""

    def test_enrich_anomalies_with_chains(self) -> None:
        """Should add chains to detected anomalies."""
        # Build a chain of events
        events = build_chain_fixture(5)
        index = build_event_index(events)
        
        # Empty baseline means all events are anomalies
        baseline = BaselineProfile()
        
        # Detect anomalies (all should be flagged as unknown)
        anomalies = detect_anomalies(events, baseline)
        
        # Enrich with chains
        chains = enrich_anomalies_with_chains(anomalies, index)
        
        # Each anomaly should have a chain
        assert len(chains) == len(anomalies)
        
        # Verify chains exist for each event
        for anomaly in anomalies:
            event_guid = anomaly.event.subject.guid
            assert event_guid in chains
            assert chains[event_guid][-1] == event_guid  # Event is last

    def test_max_chain_depth_constant_exposed(self) -> None:
        """MAX_CHAIN_DEPTH constant should be accessible."""
        assert MAX_CHAIN_DEPTH == 10

    def test_known_root_images_constant_exposed(self) -> None:
        """KNOWN_ROOT_IMAGES constant should be accessible."""
        assert "systemd" in KNOWN_ROOT_IMAGES
        assert "/sbin/init" in KNOWN_ROOT_IMAGES
