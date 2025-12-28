"""
loader.py - Sysmon Log Parser and Normalizer

This module handles:
- Parsing raw Sysmon logs (JSON format)
- Validating required fields
- Normalizing data into canonical events per CONTRACTS.md
- Rejecting malformed input early (fail fast)

This module must NOT:
- Perform detection logic
- Assign risk
- Build chains

See SPEC.md Section 4.1 for responsibilities.
"""

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import ValidationError

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
# Custom Exceptions
# =============================================================================


class LoaderError(Exception):
    """Base exception for loader errors."""
    pass


class InvalidEventError(LoaderError):
    """Raised when an event fails validation."""
    pass


class UnsupportedEventTypeError(LoaderError):
    """Raised when an event type is not supported (non Event ID 1)."""
    pass


class MalformedInputError(LoaderError):
    """Raised when input cannot be parsed as JSON."""
    pass


# =============================================================================
# Constants
# =============================================================================

# Sysmon Event ID 1 = Process Create (the only supported type in V1)
SUPPORTED_SYSMON_EVENT_ID = 1


# =============================================================================
# Loader Functions
# =============================================================================


def load_events(raw_data: str | list[dict[str, Any]]) -> list[CanonicalEvent]:
    """
    Load and normalize raw Sysmon logs into canonical events.
    
    This function parses raw Sysmon Event ID 1 (Process Create) logs and
    converts them into canonical events conforming to the CanonicalEvent schema.
    
    Args:
        raw_data: Either a JSON string or a list of dictionaries representing
                  Sysmon events. If a string, it will be parsed as JSON.
    
    Returns:
        A list of validated CanonicalEvent objects.
    
    Raises:
        MalformedInputError: If the input cannot be parsed as JSON.
        UnsupportedEventTypeError: If an event is not Sysmon Event ID 1.
        InvalidEventError: If an event fails schema validation.
    
    Example:
        >>> events = load_events('[{"EventId": 1, ...}]')
        >>> for event in events:
        ...     print(event.subject.image)
    """
    # Parse JSON if string input
    if isinstance(raw_data, str):
        try:
            parsed = json.loads(raw_data)
        except json.JSONDecodeError as e:
            raise MalformedInputError(f"Failed to parse JSON: {e}")
    else:
        parsed = raw_data
    
    # Normalize to list
    if isinstance(parsed, dict):
        parsed = [parsed]
    
    if not isinstance(parsed, list):
        raise MalformedInputError(
            f"Expected JSON array or object, got {type(parsed).__name__}"
        )
    
    # Process each event
    events: list[CanonicalEvent] = []
    for idx, raw_event in enumerate(parsed):
        try:
            event = _normalize_event(raw_event)
            events.append(event)
        except (UnsupportedEventTypeError, InvalidEventError) as e:
            # Re-raise with context about which event failed
            raise type(e)(f"Event at index {idx}: {e}") from e
    
    return events


def load_event(raw_event: dict[str, Any] | str) -> CanonicalEvent:
    """
    Load and normalize a single Sysmon event.
    
    Convenience function for loading a single event rather than a batch.
    
    Args:
        raw_event: A dictionary or JSON string representing a single Sysmon event.
    
    Returns:
        A validated CanonicalEvent object.
    
    Raises:
        MalformedInputError: If the input cannot be parsed as JSON.
        UnsupportedEventTypeError: If the event is not Sysmon Event ID 1.
        InvalidEventError: If the event fails schema validation.
    """
    if isinstance(raw_event, str):
        try:
            raw_event = json.loads(raw_event)
        except json.JSONDecodeError as e:
            raise MalformedInputError(f"Failed to parse JSON: {e}")
    
    if not isinstance(raw_event, dict):
        raise MalformedInputError(
            f"Expected JSON object, got {type(raw_event).__name__}"
        )
    
    return _normalize_event(raw_event)


def _normalize_event(raw_event: dict[str, Any]) -> CanonicalEvent:
    """
    Normalize a single raw Sysmon event to canonical format.
    
    This function handles the mapping from Sysmon field names to canonical
    field names as defined in CONTRACTS.md.
    
    Args:
        raw_event: A dictionary representing a raw Sysmon event.
    
    Returns:
        A validated CanonicalEvent object.
    
    Raises:
        UnsupportedEventTypeError: If the event is not Sysmon Event ID 1.
        InvalidEventError: If the event fails schema validation.
    """
    # Validate Event ID 1 (PROCESS_CREATE) - MANDATORY CHECK
    event_id = raw_event.get("EventId") or raw_event.get("event_id_sysmon")
    if event_id != SUPPORTED_SYSMON_EVENT_ID:
        raise UnsupportedEventTypeError(
            f"Only Sysmon Event ID 1 (PROCESS_CREATE) is supported in V1. "
            f"Received Event ID: {event_id}"
        )
    
    try:
        # Extract and normalize fields
        canonical_data = _extract_canonical_fields(raw_event)
        
        # Validate and create canonical event
        return CanonicalEvent(**canonical_data)
    
    except ValidationError as e:
        raise InvalidEventError(f"Schema validation failed: {e}") from e
    except KeyError as e:
        raise InvalidEventError(f"Missing required field: {e}") from e
    except (TypeError, ValueError) as e:
        raise InvalidEventError(f"Invalid field value: {e}") from e


def _extract_canonical_fields(raw_event: dict[str, Any]) -> dict[str, Any]:
    """
    Extract and normalize fields from raw Sysmon event to canonical format.
    
    This function maps Sysmon-specific field names to the canonical schema
    defined in CONTRACTS.md. It supports both the raw Sysmon format and
    pre-normalized canonical format.
    
    Args:
        raw_event: A dictionary representing a raw Sysmon event.
    
    Returns:
        A dictionary with canonical field names ready for CanonicalEvent.
    """
    # Support both raw Sysmon format and pre-normalized format
    # Field mapping: Sysmon name -> Canonical name
    
    # Event identification
    event_id = _get_field(raw_event, ["event_id", "EventID", "eventId"])
    timestamp = _get_field(
        raw_event, 
        ["timestamp", "UtcTime", "utc_time", "@timestamp"],
        transform=_parse_timestamp
    )
    
    # Host information
    host_data = raw_event.get("host", {})
    if not isinstance(host_data, dict):
        host_data = {}
    
    hostname = _get_field(
        host_data, 
        ["hostname", "ComputerName", "computer_name"],
        default=_get_field(raw_event, ["hostname", "ComputerName", "computer_name"], default="unknown")
    )
    boot_id = _get_field(
        host_data,
        ["boot_id", "BootId", "boot_id"],
        default=_get_field(raw_event, ["boot_id", "BootId"], default=None),
        transform=_parse_uuid
    )
    
    # Subject (the process being created)
    subject_data = raw_event.get("subject", {})
    if not isinstance(subject_data, dict):
        subject_data = {}
    
    subject_guid = _get_field(
        subject_data,
        ["guid", "ProcessGuid", "process_guid"],
        default=_get_field(raw_event, ["ProcessGuid", "process_guid"])
    )
    subject_pid = _get_field(
        subject_data,
        ["pid", "ProcessId", "process_id"],
        default=_get_field(raw_event, ["ProcessId", "process_id"]),
        transform=int
    )
    subject_image = _get_field(
        subject_data,
        ["image", "Image", "image_path"],
        default=_get_field(raw_event, ["Image", "image_path"])
    )
    
    # Parent process
    parent_data = raw_event.get("parent", {})
    if not isinstance(parent_data, dict):
        parent_data = {}
    
    parent_guid = _get_field(
        parent_data,
        ["guid", "ParentProcessGuid", "parent_process_guid"],
        default=_get_field(raw_event, ["ParentProcessGuid", "parent_process_guid"])
    )
    parent_image = _get_field(
        parent_data,
        ["image", "ParentImage", "parent_image"],
        default=_get_field(raw_event, ["ParentImage", "parent_image"])
    )
    
    # Object (target of the action - may be null for PROCESS_CREATE)
    object_data = raw_event.get("object", {})
    if not isinstance(object_data, dict):
        object_data = {}
    
    object_type_str = _get_field(
        object_data,
        ["type"],
        default="null"
    )
    object_type = ObjectType(object_type_str) if object_type_str else ObjectType.NULL
    object_guid = object_data.get("guid")
    object_path = object_data.get("path_or_address")
    
    # Metadata
    metadata_data = raw_event.get("metadata", {})
    if not isinstance(metadata_data, dict):
        metadata_data = {}
    
    command_line = _get_field(
        metadata_data,
        ["command_line", "CommandLine"],
        default=_get_field(raw_event, ["CommandLine", "command_line"], default="")
    )
    user = _get_field(
        metadata_data,
        ["user", "User"],
        default=_get_field(raw_event, ["User", "user"], default="unknown")
    )
    cwd = _get_field(
        metadata_data,
        ["cwd", "CurrentDirectory", "current_directory"],
        default=_get_field(raw_event, ["CurrentDirectory", "current_directory"], default="")
    )
    
    # Build canonical structure
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "host": HostInfo(hostname=hostname, boot_id=boot_id),
        "event_type": EventType.PROCESS_CREATE,
        "subject": Subject(
            type="process",
            guid=subject_guid,
            pid=subject_pid,
            image=subject_image,
        ),
        "parent": Parent(
            guid=parent_guid,
            image=parent_image,
        ),
        "object": Object(
            type=object_type,
            guid=object_guid,
            path_or_address=object_path,
        ),
        "metadata": EventMetadata(
            command_line=command_line,
            user=user,
            cwd=cwd,
        ),
    }


# =============================================================================
# Helper Functions
# =============================================================================


def _get_field(
    data: dict[str, Any],
    keys: list[str],
    default: Any = None,
    transform: callable = None,
) -> Any:
    """
    Get a field value trying multiple possible key names.
    
    Args:
        data: Dictionary to search.
        keys: List of possible key names to try, in order of preference.
        default: Default value if no key is found.
        transform: Optional function to transform the value.
    
    Returns:
        The field value (possibly transformed), or the default.
    """
    for key in keys:
        if key in data and data[key] is not None:
            value = data[key]
            if transform is not None:
                return transform(value)
            return value
    
    if default is not None and transform is not None:
        return transform(default) if not isinstance(default, UUID) else default
    return default


def _parse_timestamp(value: Any) -> datetime:
    """
    Parse a timestamp value into a datetime object.
    
    Supports ISO-8601 format and common Sysmon timestamp formats.
    
    Args:
        value: Timestamp value (string or datetime).
    
    Returns:
        A datetime object.
    """
    if isinstance(value, datetime):
        return value
    
    if isinstance(value, str):
        # Try ISO-8601 format first
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
        
        # Try Sysmon format: "2024-01-15 10:30:45.123"
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            pass
        
        # Try without microseconds
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    
    raise ValueError(f"Cannot parse timestamp: {value}")


def _parse_uuid(value: Any) -> UUID:
    """
    Parse a UUID value.
    
    Args:
        value: UUID value (string or UUID).
    
    Returns:
        A UUID object.
    """
    if isinstance(value, UUID):
        return value
    
    if isinstance(value, str):
        # Handle Sysmon GUID format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
        cleaned = value.strip("{}")
        return UUID(cleaned)
    
    raise ValueError(f"Cannot parse UUID: {value}")
