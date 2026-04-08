"""
mordor_adapter.py - Mordor JSONL Adapter

This module handles:
- Reading Mordor JSONL logs (one JSON object per line)
- Filtering Sysmon Process Create events (EventID == 1)
- Mapping Mordor fields to CanonicalEvent
- Skipping malformed or incomplete records with warnings

This adapter is a boundary module and must NOT contain analysis logic.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_DNS, UUID, uuid4, uuid5

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


logger = logging.getLogger(__name__)

SUPPORTED_EVENT_ID = 1
_REQUIRED_FIELDS = (
    "Hostname",
    "ProcessGuid",
    "ProcessId",
    "Image",
    "ParentProcessGuid",
    "ParentImage",
)


def load_mordor_events(file_path: str | Path) -> list[CanonicalEvent]:
    """
    Load and normalize Mordor JSONL data into canonical events.

    The adapter reads one JSON object per line, keeps only EventID 1 records,
    and maps each valid record into a CanonicalEvent.

    Args:
        file_path: Path to a Mordor JSONL file.

    Returns:
        A list of validated CanonicalEvent objects.
    """
    path = Path(file_path)
    events: list[CanonicalEvent] = []

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            try:
                raw_event = json.loads(stripped)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "Skipping line %d in %s: invalid JSON (%s)",
                    line_number,
                    path,
                    exc,
                )
                continue

            if raw_event.get("EventID") != SUPPORTED_EVENT_ID:
                continue

            event = _normalize_mordor_event(raw_event, line_number, path)
            if event is not None:
                events.append(event)

    return events


def _normalize_mordor_event(
    raw_event: dict[str, Any],
    line_number: int,
    source_path: Path,
) -> CanonicalEvent | None:
    """
    Convert a single Mordor EventID 1 record into CanonicalEvent.

    Returns None when required fields are missing or values are invalid.
    """
    missing_fields = _missing_required_fields(raw_event)
    if missing_fields:
        logger.warning(
            "Skipping EventID=1 at line %d in %s: missing required fields: %s",
            line_number,
            source_path,
            ", ".join(missing_fields),
        )
        return None

    try:
        timestamp = _parse_timestamp(
            raw_event.get("UtcTime")
            or raw_event.get("@timestamp")
            or raw_event.get("TimeCreated")
        )

        hostname = str(raw_event["Hostname"])
        canonical_event = CanonicalEvent(
            event_id=uuid4(),
            timestamp=timestamp,
            host=HostInfo(
                hostname=hostname,
                boot_id=_derive_boot_id(hostname),
            ),
            event_type=EventType.PROCESS_CREATE,
            subject=Subject(
                type="process",
                guid=str(raw_event["ProcessGuid"]),
                pid=int(raw_event["ProcessId"]),
                image=str(raw_event["Image"]),
            ),
            parent=Parent(
                guid=str(raw_event["ParentProcessGuid"]),
                image=str(raw_event["ParentImage"]),
            ),
            object=Object(
                type=ObjectType.NULL,
                guid=None,
                path_or_address=None,
            ),
            metadata=EventMetadata(
                command_line=str(raw_event.get("CommandLine", "")),
                user=str(raw_event.get("User", "unknown")),
                cwd=str(raw_event.get("CurrentDirectory", "")),
            ),
        )
        return canonical_event
    except (ValidationError, TypeError, ValueError, KeyError) as exc:
        logger.warning(
            "Skipping EventID=1 at line %d in %s: invalid field value (%s)",
            line_number,
            source_path,
            exc,
        )
        return None


def _missing_required_fields(raw_event: dict[str, Any]) -> list[str]:
    """Return a list of required fields missing from a Mordor event."""
    missing: list[str] = []

    for field in _REQUIRED_FIELDS:
        if raw_event.get(field) in (None, ""):
            missing.append(field)

    has_timestamp = any(
        raw_event.get(key) not in (None, "")
        for key in ("UtcTime", "@timestamp", "TimeCreated")
    )
    if not has_timestamp:
        missing.append("UtcTime|@timestamp|TimeCreated")

    return missing


def _parse_timestamp(value: Any) -> datetime:
    """Parse timestamp values in Mordor Sysmon formats into datetime."""
    if isinstance(value, datetime):
        return value

    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass

        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            pass

        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    raise ValueError(f"Cannot parse timestamp: {value}")


def _derive_boot_id(hostname: str) -> UUID:
    """
    Derive a stable boot_id fallback from hostname.

    Mordor records do not include boot_id. We derive a deterministic UUID
    to satisfy the canonical schema requirement.
    """
    return uuid5(NAMESPACE_DNS, hostname.lower())
