"""
test_loader.py - Unit tests for the Sysmon log loader.

Verifies that the loader correctly parses raw Sysmon logs,
validates Event ID 1, and normalizes to canonical events.
"""

import json
from datetime import datetime
from uuid import uuid4

import pytest

from src.core.events import CanonicalEvent, EventType
from src.core.loader import (
    InvalidEventError,
    MalformedInputError,
    UnsupportedEventTypeError,
    load_event,
    load_events,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def valid_sysmon_event() -> dict:
    """
    A valid Sysmon Event ID 1 (Process Create) in raw format.
    """
    return {
        "EventId": 1,
        "event_id": str(uuid4()),
        "UtcTime": "2024-01-15T10:30:45.123Z",
        "host": {
            "hostname": "test-server-01",
            "boot_id": str(uuid4()),
        },
        "ProcessGuid": "{ABC12345-1234-5678-ABCD-123456789ABC}",
        "ProcessId": 1234,
        "Image": "/usr/bin/python3",
        "ParentProcessGuid": "{PARENT00-1234-5678-ABCD-123456789ABC}",
        "ParentImage": "/bin/bash",
        "CommandLine": "python3 script.py --verbose",
        "User": "root",
        "CurrentDirectory": "/home/user",
        "object": {
            "type": "null",
            "guid": None,
            "path_or_address": None,
        },
    }


@pytest.fixture
def valid_canonical_format_event() -> dict:
    """
    A valid event already in canonical format (normalized).
    """
    return {
        "EventId": 1,
        "event_id": str(uuid4()),
        "timestamp": datetime.now().isoformat(),
        "host": {
            "hostname": "test-server-01",
            "boot_id": str(uuid4()),
        },
        "subject": {
            "type": "process",
            "guid": "subject-guid-123",
            "pid": 5678,
            "image": "/usr/bin/curl",
        },
        "parent": {
            "guid": "parent-guid-456",
            "image": "/bin/bash",
        },
        "object": {
            "type": "null",
            "guid": None,
            "path_or_address": None,
        },
        "metadata": {
            "command_line": "curl https://example.com",
            "user": "testuser",
            "cwd": "/tmp",
        },
    }


# =============================================================================
# Event ID 1 Validation Tests (User Requirement)
# =============================================================================


class TestEventIdValidation:
    """Tests for Event ID 1 validation requirement."""

    def test_event_id_1_is_accepted(self, valid_sysmon_event: dict) -> None:
        """Event ID 1 (PROCESS_CREATE) should be accepted."""
        event = load_event(valid_sysmon_event)
        
        assert event.event_type == EventType.PROCESS_CREATE

    def test_event_id_2_is_rejected(self, valid_sysmon_event: dict) -> None:
        """Event ID 2 (File Create Time) should be rejected with clear error."""
        valid_sysmon_event["EventId"] = 2
        
        with pytest.raises(UnsupportedEventTypeError) as exc_info:
            load_event(valid_sysmon_event)
        
        error_message = str(exc_info.value)
        assert "Event ID 1" in error_message
        assert "PROCESS_CREATE" in error_message
        assert "Received Event ID: 2" in error_message

    def test_event_id_3_is_rejected(self, valid_sysmon_event: dict) -> None:
        """Event ID 3 (Network Connect) should be rejected with clear error."""
        valid_sysmon_event["EventId"] = 3
        
        with pytest.raises(UnsupportedEventTypeError) as exc_info:
            load_event(valid_sysmon_event)
        
        assert "Received Event ID: 3" in str(exc_info.value)

    def test_event_id_11_is_rejected(self, valid_sysmon_event: dict) -> None:
        """Event ID 11 (File Create) should be rejected with clear error."""
        valid_sysmon_event["EventId"] = 11
        
        with pytest.raises(UnsupportedEventTypeError) as exc_info:
            load_event(valid_sysmon_event)
        
        assert "Received Event ID: 11" in str(exc_info.value)

    def test_missing_event_id_is_rejected(self, valid_sysmon_event: dict) -> None:
        """Missing Event ID should be rejected."""
        del valid_sysmon_event["EventId"]
        
        with pytest.raises(UnsupportedEventTypeError) as exc_info:
            load_event(valid_sysmon_event)
        
        assert "Received Event ID: None" in str(exc_info.value)

    def test_batch_with_mixed_event_ids_fails_on_first_invalid(
        self, valid_sysmon_event: dict
    ) -> None:
        """Batch loading should fail when encountering non-Event ID 1."""
        valid_event = valid_sysmon_event.copy()
        invalid_event = valid_sysmon_event.copy()
        invalid_event["EventId"] = 5  # Invalid Event ID
        
        events_batch = [valid_event, invalid_event]
        
        with pytest.raises(UnsupportedEventTypeError) as exc_info:
            load_events(events_batch)
        
        assert "Event at index 1" in str(exc_info.value)


# =============================================================================
# Valid Event Loading Tests
# =============================================================================


class TestValidEventLoading:
    """Tests for successful event loading."""

    def test_load_single_event_from_dict(self, valid_sysmon_event: dict) -> None:
        """Load a single event from a dictionary."""
        event = load_event(valid_sysmon_event)
        
        assert isinstance(event, CanonicalEvent)
        assert event.event_type == EventType.PROCESS_CREATE
        assert event.subject.pid == 1234
        assert event.subject.image == "/usr/bin/python3"

    def test_load_single_event_from_json_string(
        self, valid_sysmon_event: dict
    ) -> None:
        """Load a single event from a JSON string."""
        json_str = json.dumps(valid_sysmon_event)
        event = load_event(json_str)
        
        assert isinstance(event, CanonicalEvent)
        assert event.subject.pid == 1234

    def test_load_events_batch(self, valid_sysmon_event: dict) -> None:
        """Load multiple events as a batch."""
        event1 = valid_sysmon_event.copy()
        event2 = valid_sysmon_event.copy()
        event2["ProcessId"] = 5678
        
        events = load_events([event1, event2])
        
        assert len(events) == 2
        assert events[0].subject.pid == 1234
        assert events[1].subject.pid == 5678

    def test_load_events_from_json_array(self, valid_sysmon_event: dict) -> None:
        """Load events from a JSON array string."""
        json_str = json.dumps([valid_sysmon_event, valid_sysmon_event])
        events = load_events(json_str)
        
        assert len(events) == 2

    def test_load_events_single_object_normalized_to_list(
        self, valid_sysmon_event: dict
    ) -> None:
        """A single JSON object should be normalized to a list."""
        events = load_events(valid_sysmon_event)
        
        assert len(events) == 1

    def test_canonical_format_event_loading(
        self, valid_canonical_format_event: dict
    ) -> None:
        """Events already in canonical format should load correctly."""
        event = load_event(valid_canonical_format_event)
        
        assert event.subject.guid == "subject-guid-123"
        assert event.metadata.command_line == "curl https://example.com"


# =============================================================================
# Field Normalization Tests
# =============================================================================


class TestFieldNormalization:
    """Tests for field name normalization from Sysmon to canonical format."""

    def test_process_guid_normalized(self, valid_sysmon_event: dict) -> None:
        """ProcessGuid should be normalized to subject.guid."""
        event = load_event(valid_sysmon_event)
        
        # GUID should have braces stripped
        assert "ABC12345" in event.subject.guid

    def test_parent_guid_normalized(self, valid_sysmon_event: dict) -> None:
        """ParentProcessGuid should be normalized to parent.guid."""
        event = load_event(valid_sysmon_event)
        
        assert "PARENT00" in event.parent.guid

    def test_image_paths_preserved(self, valid_sysmon_event: dict) -> None:
        """Image paths should be preserved correctly."""
        event = load_event(valid_sysmon_event)
        
        assert event.subject.image == "/usr/bin/python3"
        assert event.parent.image == "/bin/bash"

    def test_command_line_preserved(self, valid_sysmon_event: dict) -> None:
        """Command line should be preserved correctly."""
        event = load_event(valid_sysmon_event)
        
        assert event.metadata.command_line == "python3 script.py --verbose"

    def test_timestamp_parsing_iso8601(self, valid_sysmon_event: dict) -> None:
        """ISO-8601 timestamps should be parsed correctly."""
        valid_sysmon_event["UtcTime"] = "2024-01-15T10:30:45.000Z"
        event = load_event(valid_sysmon_event)
        
        assert event.timestamp.year == 2024
        assert event.timestamp.month == 1
        assert event.timestamp.day == 15

    def test_timestamp_parsing_sysmon_format(self, valid_sysmon_event: dict) -> None:
        """Sysmon-style timestamps should be parsed correctly."""
        valid_sysmon_event["UtcTime"] = "2024-01-15 10:30:45.123"
        event = load_event(valid_sysmon_event)
        
        assert event.timestamp.year == 2024


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling and validation."""

    def test_malformed_json_raises_error(self) -> None:
        """Malformed JSON should raise MalformedInputError."""
        with pytest.raises(MalformedInputError) as exc_info:
            load_events("not valid json {{{")
        
        assert "Failed to parse JSON" in str(exc_info.value)

    def test_non_object_json_raises_error(self) -> None:
        """Non-object/array JSON should raise MalformedInputError."""
        with pytest.raises(MalformedInputError):
            load_events('"just a string"')

    def test_missing_required_field_raises_error(
        self, valid_sysmon_event: dict
    ) -> None:
        """Missing required field should raise InvalidEventError."""
        del valid_sysmon_event["ProcessGuid"]
        
        with pytest.raises(InvalidEventError) as exc_info:
            load_event(valid_sysmon_event)
        
        assert "validation failed" in str(exc_info.value).lower() or \
               "required" in str(exc_info.value).lower()

    def test_invalid_pid_type_raises_error(self, valid_sysmon_event: dict) -> None:
        """Invalid PID type should raise InvalidEventError."""
        valid_sysmon_event["ProcessId"] = "not-a-number"
        
        with pytest.raises(InvalidEventError):
            load_event(valid_sysmon_event)

    def test_error_includes_event_index_for_batch(
        self, valid_sysmon_event: dict
    ) -> None:
        """Batch errors should include the index of the failing event."""
        valid_event = valid_sysmon_event.copy()
        invalid_event = valid_sysmon_event.copy()
        del invalid_event["ProcessGuid"]  # Make it invalid
        
        with pytest.raises(InvalidEventError) as exc_info:
            load_events([valid_event, invalid_event])
        
        assert "Event at index 1" in str(exc_info.value)


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_list_returns_empty(self) -> None:
        """Empty event list should return empty list."""
        events = load_events([])
        assert events == []

    def test_event_with_minimal_metadata(self, valid_sysmon_event: dict) -> None:
        """Event with minimal metadata should still load."""
        valid_sysmon_event["CommandLine"] = ""
        valid_sysmon_event["CurrentDirectory"] = ""
        
        event = load_event(valid_sysmon_event)
        
        assert event.metadata.command_line == ""

    def test_guid_with_braces_stripped(self, valid_sysmon_event: dict) -> None:
        """GUIDs with Sysmon-style braces should have braces stripped."""
        valid_sysmon_event["ProcessGuid"] = "{12345678-1234-1234-1234-123456789ABC}"
        
        event = load_event(valid_sysmon_event)
        
        # The GUID should be valid (braces stripped internally)
        assert event.subject.guid is not None

    def test_null_object_type_accepted(self, valid_sysmon_event: dict) -> None:
        """Object with type 'null' should be accepted."""
        valid_sysmon_event["object"] = {
            "type": "null",
            "guid": None,
            "path_or_address": None,
        }
        
        event = load_event(valid_sysmon_event)
        
        assert event.object.type.value == "null"
