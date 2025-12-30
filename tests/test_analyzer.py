"""
test_analyzer.py - Unit tests for the baseline profiler.

Verifies baseline construction, serialization, and deterministic output.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest

from src.core.analyzer import (
    BASELINE_VERSION,
    BaselineProfile,
    build_baseline,
    load_baseline,
    save_baseline,
    update_baseline,
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


def create_canonical_event(
    parent_image: str = "/bin/bash",
    child_image: str = "/usr/bin/python3",
    user: str = "root",
    event_id: str | None = None,
) -> CanonicalEvent:
    """Helper to create a CanonicalEvent for testing."""
    return CanonicalEvent(
        event_id=uuid4() if event_id is None else event_id,
        timestamp=datetime.now(),
        host=HostInfo(hostname="test-host", boot_id=uuid4()),
        event_type=EventType.PROCESS_CREATE,
        subject=Subject(
            type="process",
            guid=str(uuid4()),
            pid=1234,
            image=child_image,
        ),
        parent=Parent(
            guid=str(uuid4()),
            image=parent_image,
        ),
        object=Object(
            type=ObjectType.NULL,
            guid=None,
            path_or_address=None,
        ),
        metadata=EventMetadata(
            command_line=f"{child_image} --verbose",
            user=user,
            cwd="/home/user",
        ),
    )


@pytest.fixture
def sample_events() -> list[CanonicalEvent]:
    """Create a sample set of events for testing."""
    return [
        create_canonical_event("/bin/bash", "/usr/bin/python3", "root"),
        create_canonical_event("/bin/bash", "/usr/bin/python3", "root"),
        create_canonical_event("/bin/bash", "/usr/bin/curl", "root"),
        create_canonical_event("/bin/bash", "/usr/bin/python3", "testuser"),
        create_canonical_event("/usr/bin/systemd", "/bin/bash", "root"),
    ]


@pytest.fixture
def temp_baseline_path(tmp_path: Path) -> Path:
    """Provide a temporary path for baseline files."""
    return tmp_path / "baseline.json"


# =============================================================================
# Key Structure Tests (Critical Constraint #1)
# =============================================================================


class TestKeyStructure:
    """Tests verifying the (parent_image, child_image, user) tuple key structure."""

    def test_key_includes_parent_image(self, sample_events: list[CanonicalEvent]) -> None:
        """Key must include parent_image."""
        profile = build_baseline(sample_events)
        
        # Check that parent_image is part of the key
        keys = list(profile.relationships.keys())
        for key in keys:
            assert len(key) == 3
            parent_image, child_image, user = key
            assert isinstance(parent_image, str)

    def test_key_includes_child_image(self, sample_events: list[CanonicalEvent]) -> None:
        """Key must include child_image."""
        profile = build_baseline(sample_events)
        
        keys = list(profile.relationships.keys())
        for key in keys:
            parent_image, child_image, user = key
            assert isinstance(child_image, str)

    def test_key_includes_user(self, sample_events: list[CanonicalEvent]) -> None:
        """Key must include user."""
        profile = build_baseline(sample_events)
        
        keys = list(profile.relationships.keys())
        for key in keys:
            parent_image, child_image, user = key
            assert isinstance(user, str)

    def test_same_images_different_users_are_distinct(self) -> None:
        """Same parent/child with different users should be separate keys."""
        events = [
            create_canonical_event("/bin/bash", "/usr/bin/python3", "root"),
            create_canonical_event("/bin/bash", "/usr/bin/python3", "testuser"),
        ]
        
        profile = build_baseline(events)
        
        # Should have 2 distinct relationships
        assert profile.get_unique_relationship_count() == 2
        assert profile.get_relationship_count("/bin/bash", "/usr/bin/python3", "root") == 1
        assert profile.get_relationship_count("/bin/bash", "/usr/bin/python3", "testuser") == 1

    def test_same_user_different_images_are_distinct(self) -> None:
        """Same user with different images should be separate keys."""
        events = [
            create_canonical_event("/bin/bash", "/usr/bin/python3", "root"),
            create_canonical_event("/bin/bash", "/usr/bin/curl", "root"),
        ]
        
        profile = build_baseline(events)
        
        assert profile.get_unique_relationship_count() == 2


# =============================================================================
# Order Independence Tests (Critical Constraint #2)
# =============================================================================


class TestOrderIndependence:
    """Tests verifying deterministic output regardless of input order."""

    def test_same_events_different_order_same_json(
        self, temp_baseline_path: Path
    ) -> None:
        """Same events in different order must produce identical JSON."""
        events_order_1 = [
            create_canonical_event("/bin/bash", "/usr/bin/python3", "root"),
            create_canonical_event("/bin/bash", "/usr/bin/curl", "testuser"),
            create_canonical_event("/usr/bin/systemd", "/bin/bash", "root"),
        ]
        
        events_order_2 = [
            create_canonical_event("/usr/bin/systemd", "/bin/bash", "root"),
            create_canonical_event("/bin/bash", "/usr/bin/python3", "root"),
            create_canonical_event("/bin/bash", "/usr/bin/curl", "testuser"),
        ]
        
        # Build profiles from different orderings
        profile1 = build_baseline(events_order_1)
        profile2 = build_baseline(events_order_2)
        
        # Save to files
        path1 = temp_baseline_path.parent / "baseline1.json"
        path2 = temp_baseline_path.parent / "baseline2.json"
        
        save_baseline(profile1, path1)
        save_baseline(profile2, path2)
        
        # Read and compare JSON content
        with open(path1) as f1, open(path2) as f2:
            json1 = f1.read()
            json2 = f2.read()
        
        assert json1 == json2, "JSON output must be identical regardless of input order"

    def test_relationships_sorted_in_json(self, temp_baseline_path: Path) -> None:
        """Relationships in JSON should be sorted for determinism."""
        events = [
            create_canonical_event("/z/last", "/a/first", "zoo"),
            create_canonical_event("/a/first", "/z/last", "apple"),
            create_canonical_event("/m/middle", "/m/middle", "mango"),
        ]
        
        profile = build_baseline(events)
        save_baseline(profile, temp_baseline_path)
        
        with open(temp_baseline_path) as f:
            data = json.load(f)
        
        # Extract relationship tuples in order
        relationships = data["relationships"]
        keys = [(r["parent_image"], r["child_image"], r["user"]) for r in relationships]
        
        # Verify they are sorted
        assert keys == sorted(keys), "Relationships must be sorted in JSON output"


# =============================================================================
# Strict Typing Tests (Critical Constraint #3)
# =============================================================================


class TestStrictTyping:
    """Tests verifying strict CanonicalEvent typing requirement."""

    def test_accepts_canonical_event_list(self, sample_events: list[CanonicalEvent]) -> None:
        """Must accept list[CanonicalEvent]."""
        profile = build_baseline(sample_events)
        assert isinstance(profile, BaselineProfile)

    def test_rejects_raw_dictionary(self) -> None:
        """Must reject raw dictionaries with TypeError."""
        raw_dicts = [{"parent": "/bin/bash", "child": "/usr/bin/python3"}]
        
        with pytest.raises(TypeError) as exc_info:
            build_baseline(raw_dicts)  # type: ignore
        
        assert "CanonicalEvent" in str(exc_info.value)

    def test_rejects_json_string(self) -> None:
        """Must reject JSON strings with TypeError."""
        json_str = '[{"parent": "/bin/bash"}]'
        
        with pytest.raises(TypeError) as exc_info:
            build_baseline(json_str)  # type: ignore
        
        assert "list" in str(exc_info.value).lower()

    def test_rejects_mixed_list(self) -> None:
        """Must reject list with mixed types."""
        events = [
            create_canonical_event("/bin/bash", "/usr/bin/python3", "root"),
            {"raw": "dict"},  # This should cause failure
        ]
        
        with pytest.raises(TypeError) as exc_info:
            build_baseline(events)  # type: ignore
        
        assert "Event at index 1" in str(exc_info.value)

    def test_error_message_suggests_loader(self) -> None:
        """Error message should suggest using loader.load_events()."""
        with pytest.raises(TypeError) as exc_info:
            build_baseline([{"raw": "dict"}])  # type: ignore
        
        assert "load_events" in str(exc_info.value)


# =============================================================================
# Serialization Tests (Critical Constraint #4)
# =============================================================================


class TestSerialization:
    """Tests for JSON serialization/deserialization."""

    def test_output_is_valid_json(
        self, sample_events: list[CanonicalEvent], temp_baseline_path: Path
    ) -> None:
        """Output must be valid JSON."""
        profile = build_baseline(sample_events)
        save_baseline(profile, temp_baseline_path)
        
        with open(temp_baseline_path) as f:
            data = json.load(f)  # Should not raise
        
        assert isinstance(data, dict)

    def test_output_is_human_readable(
        self, sample_events: list[CanonicalEvent], temp_baseline_path: Path
    ) -> None:
        """Output should be indented for human readability."""
        profile = build_baseline(sample_events)
        save_baseline(profile, temp_baseline_path)
        
        with open(temp_baseline_path) as f:
            content = f.read()
        
        # Indented JSON should contain newlines and spaces
        assert "\n" in content
        assert "  " in content  # 2-space indentation

    def test_save_and_load_roundtrip(
        self, sample_events: list[CanonicalEvent], temp_baseline_path: Path
    ) -> None:
        """Save then load should preserve all data."""
        original = build_baseline(sample_events)
        save_baseline(original, temp_baseline_path)
        loaded = load_baseline(temp_baseline_path)
        
        assert loaded.version == original.version
        assert loaded.total_events == original.total_events
        assert loaded.relationships == original.relationships

    def test_json_contains_required_fields(
        self, sample_events: list[CanonicalEvent], temp_baseline_path: Path
    ) -> None:
        """JSON should contain version, total_events, relationships."""
        profile = build_baseline(sample_events)
        save_baseline(profile, temp_baseline_path)
        
        with open(temp_baseline_path) as f:
            data = json.load(f)
        
        assert "version" in data
        assert "total_events" in data
        assert "relationships" in data
        assert "unique_relationships" in data

    def test_relationship_entry_structure(
        self, sample_events: list[CanonicalEvent], temp_baseline_path: Path
    ) -> None:
        """Each relationship entry should have parent_image, child_image, user, count."""
        profile = build_baseline(sample_events)
        save_baseline(profile, temp_baseline_path)
        
        with open(temp_baseline_path) as f:
            data = json.load(f)
        
        for rel in data["relationships"]:
            assert "parent_image" in rel
            assert "child_image" in rel
            assert "user" in rel
            assert "count" in rel


# =============================================================================
# Baseline Construction Tests
# =============================================================================


class TestBaselineConstruction:
    """Tests for baseline profile construction."""

    def test_empty_events_returns_empty_profile(self) -> None:
        """Empty event list should return empty profile."""
        profile = build_baseline([])
        
        assert profile.total_events == 0
        assert profile.get_unique_relationship_count() == 0

    def test_counts_relationship_frequency(self) -> None:
        """Repeated relationships should increment count."""
        events = [
            create_canonical_event("/bin/bash", "/usr/bin/python3", "root"),
            create_canonical_event("/bin/bash", "/usr/bin/python3", "root"),
            create_canonical_event("/bin/bash", "/usr/bin/python3", "root"),
        ]
        
        profile = build_baseline(events)
        
        assert profile.get_relationship_count("/bin/bash", "/usr/bin/python3", "root") == 3

    def test_total_events_tracked(self, sample_events: list[CanonicalEvent]) -> None:
        """Total events should be tracked correctly."""
        profile = build_baseline(sample_events)
        assert profile.total_events == len(sample_events)

    def test_version_set_correctly(self, sample_events: list[CanonicalEvent]) -> None:
        """Profile version should be set correctly."""
        profile = build_baseline(sample_events)
        assert profile.version == BASELINE_VERSION


# =============================================================================
# Incremental Update Tests
# =============================================================================


class TestIncrementalUpdates:
    """Tests for incremental baseline updates."""

    def test_update_adds_new_relationships(self) -> None:
        """Update should add new relationships."""
        initial_events = [
            create_canonical_event("/bin/bash", "/usr/bin/python3", "root"),
        ]
        new_events = [
            create_canonical_event("/bin/bash", "/usr/bin/curl", "root"),
        ]
        
        profile = build_baseline(initial_events)
        update_baseline(profile, new_events)
        
        assert profile.get_unique_relationship_count() == 2

    def test_update_increments_existing_counts(self) -> None:
        """Update should increment existing relationship counts."""
        events1 = [create_canonical_event("/bin/bash", "/usr/bin/python3", "root")]
        events2 = [create_canonical_event("/bin/bash", "/usr/bin/python3", "root")]
        
        profile = build_baseline(events1)
        update_baseline(profile, events2)
        
        assert profile.get_relationship_count("/bin/bash", "/usr/bin/python3", "root") == 2

    def test_update_accumulates_total_events(self) -> None:
        """Update should accumulate total event count."""
        events1 = [create_canonical_event("/bin/bash", "/usr/bin/python3", "root")] * 5
        events2 = [create_canonical_event("/bin/bash", "/usr/bin/curl", "root")] * 3
        
        profile = build_baseline(events1)
        update_baseline(profile, events2)
        
        assert profile.total_events == 8


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling in baseline operations."""

    def test_load_nonexistent_file_raises_error(self) -> None:
        """Loading nonexistent file should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_baseline(Path("/nonexistent/path/baseline.json"))

    def test_load_invalid_json_raises_error(self, temp_baseline_path: Path) -> None:
        """Loading invalid JSON should raise error."""
        with open(temp_baseline_path, "w") as f:
            f.write("not valid json {{{")
        
        with pytest.raises(json.JSONDecodeError):
            load_baseline(temp_baseline_path)

    def test_load_missing_fields_raises_error(self, temp_baseline_path: Path) -> None:
        """Loading JSON with missing fields should raise ValueError."""
        with open(temp_baseline_path, "w") as f:
            json.dump({"incomplete": "data"}, f)
        
        with pytest.raises(ValueError) as exc_info:
            load_baseline(temp_baseline_path)
        
        assert "missing" in str(exc_info.value).lower()

    def test_save_creates_parent_directories(self, tmp_path: Path) -> None:
        """Save should create parent directories if needed."""
        deep_path = tmp_path / "a" / "b" / "c" / "baseline.json"
        
        profile = BaselineProfile()
        save_baseline(profile, deep_path)
        
        assert deep_path.exists()
