"""Tests for the Mordor JSONL adapter."""

import json
from datetime import datetime
from uuid import UUID

import pytest

from src.adapters.mordor_adapter import load_mordor_events
from src.core.events import CanonicalEvent, EventType

@pytest.fixture
def mordor_event_id_1_sample() -> dict:
    """Real EventID=1 sample sourced from examples/mordor/SCHEMA_NOTES.md."""
    return {
        "SourceName": "Microsoft-Windows-Sysmon",
        "ProviderGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
        "Level": "4",
        "Keywords": "0x8000000000000000",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Hostname": "MKT01.pandalab.com",
        "TimeCreated": "2023-08-15T09:53:48.554Z",
        "@timestamp": "2023-08-15T09:53:48.554Z",
        "EventID": 1,
        "Message": "Process Create",
        "Task": "1",
        "RuleName": "-",
        "UtcTime": "2023-08-16 04:53:48.446",
        "ProcessGuid": "{81056205-565c-64dc-2304-000000000800}",
        "ProcessId": "7448",
        "Image": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "FileVersion": "92.0.902.67",
        "Description": "Microsoft Edge",
        "Product": "Microsoft Edge",
        "Company": "Microsoft Corporation",
        "OriginalFileName": "msedge.exe",
        "CommandLine": "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --profile-directory=Default",
        "CurrentDirectory": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\",
        "User": "PANDALAB\\stevie.marie",
        "LogonGuid": "{81056205-d113-64d4-2d2f-060000000000}",
        "LogonId": "0x62f2d",
        "TerminalSessionId": "1",
        "IntegrityLevel": "Medium",
        "Hashes": "SHA1=FA9E8B7FB10473A01B8925C4C5B0888924A1147C",
        "ParentProcessGuid": "{81056205-d124-64d4-6a00-000000000800}",
        "ParentProcessId": "4544",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentCommandLine": "C:\\Windows\\Explorer.EXE",
        "ParentUser": "PANDALAB\\stevie.marie",
    }


@pytest.fixture
def write_jsonl(tmp_path):
    """Write JSON objects as JSONL and return the created path."""

    def _write_jsonl(records: list[dict]):
        file_path = tmp_path / "mordor_test.jsonl"
        file_path.write_text(
            "\n".join(json.dumps(record) for record in records) + "\n",
            encoding="utf-8",
        )
        return file_path

    return _write_jsonl

def test_valid_event_parses(
    mordor_event_id_1_sample: dict,
    write_jsonl,
) -> None:
    """A valid EventID=1 row maps into a CanonicalEvent."""
    file_path = write_jsonl([mordor_event_id_1_sample])

    events = load_mordor_events(file_path)

    assert len(events) == 1
    event = events[0]

    assert isinstance(event, CanonicalEvent)
    assert event.event_type == EventType.PROCESS_CREATE
    assert event.host.hostname == "MKT01.pandalab.com"
    assert event.subject.guid == "{81056205-565c-64dc-2304-000000000800}"
    assert event.subject.pid == 7448
    assert event.subject.image == "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    assert event.parent.guid == "{81056205-d124-64d4-6a00-000000000800}"
    assert event.parent.image == "C:\\Windows\\explorer.exe"
    assert event.metadata.command_line.startswith("\"C:\\Program Files (x86)\\Microsoft\\Edge")
    assert event.metadata.user == "PANDALAB\\stevie.marie"
    assert event.timestamp == datetime(2023, 8, 16, 4, 53, 48, 446000)


def test_non_process_create_skipped(
    mordor_event_id_1_sample: dict,
    write_jsonl,
) -> None:
    """Records with EventID != 1 should be skipped."""
    non_process_record = dict(mordor_event_id_1_sample)
    non_process_record["EventID"] = 1102

    file_path = write_jsonl([non_process_record])
    events = load_mordor_events(file_path)

    assert events == []


def test_missing_required_fields_skipped(
    mordor_event_id_1_sample: dict,
    write_jsonl,
    caplog,
) -> None:
    """Rows missing required fields are skipped without raising."""
    missing_process_guid = dict(mordor_event_id_1_sample)
    del missing_process_guid["ProcessGuid"]

    missing_image = dict(mordor_event_id_1_sample)
    del missing_image["Image"]

    file_path = write_jsonl([missing_process_guid, missing_image])

    with caplog.at_level("WARNING"):
        events = load_mordor_events(file_path)

    assert events == []
    assert "missing required fields" in caplog.text


def test_batch_conversion(
    mordor_event_id_1_sample: dict,
    write_jsonl,
) -> None:
    """Mixed batches keep only valid EventID=1 rows."""
    records: list[dict] = []

    # Add 5 valid EventID=1 rows.
    for idx in range(5):
        valid = dict(mordor_event_id_1_sample)
        valid["ProcessGuid"] = f"{{81056205-565c-64dc-2304-00000000080{idx}}}"
        valid["ProcessId"] = str(7000 + idx)
        records.append(valid)

    # Add 3 non-process-create rows.
    for _ in range(3):
        non_process = dict(mordor_event_id_1_sample)
        non_process["EventID"] = 4688
        records.append(non_process)

    # Add 2 EventID=1 rows missing required fields.
    invalid_1 = dict(mordor_event_id_1_sample)
    del invalid_1["Image"]
    records.append(invalid_1)

    invalid_2 = dict(mordor_event_id_1_sample)
    del invalid_2["ProcessGuid"]
    records.append(invalid_2)

    # Add 1 EventID=1 row with invalid PID type.
    invalid_3 = dict(mordor_event_id_1_sample)
    invalid_3["ProcessId"] = "not-an-int"
    records.append(invalid_3)

    assert len(records) >= 10

    file_path = write_jsonl(records)
    events = load_mordor_events(file_path)

    assert len(events) == 5
    assert all(event.event_type == EventType.PROCESS_CREATE for event in events)


def test_field_types(
    mordor_event_id_1_sample: dict,
    write_jsonl,
) -> None:
    """Mapped fields preserve expected CanonicalEvent types."""
    file_path = write_jsonl([mordor_event_id_1_sample])

    events = load_mordor_events(file_path)
    assert len(events) == 1

    event = events[0]
    assert isinstance(event.event_id, UUID)
    assert isinstance(event.timestamp, datetime)
    assert isinstance(event.host.hostname, str)
    assert isinstance(event.subject.guid, str)
    assert isinstance(event.subject.pid, int)
    assert isinstance(event.subject.image, str)
    assert isinstance(event.parent.guid, str)
    assert isinstance(event.parent.image, str)
    assert isinstance(event.metadata.command_line, str)
    assert isinstance(event.metadata.user, str)
    assert isinstance(event.metadata.cwd, str)
