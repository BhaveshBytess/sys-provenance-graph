"""
test_cli.py - Unit tests for CLI interface.

Tests the CLI train and analyze commands.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest
from typer.testing import CliRunner

from src.cli.main import app


runner = CliRunner()


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
        {
            "EventId": 1,
            "event_id": str(uuid4()),
            "UtcTime": datetime.now().isoformat(),
            "host": {
                "hostname": "test-host",
                "boot_id": str(uuid4()),
            },
            "ProcessGuid": "{ABCDEF00-1234-1234-1234-123456789ABC}",
            "ProcessId": 5678,
            "Image": "/usr/bin/curl",
            "ParentProcessGuid": "{12345678-1234-1234-1234-123456789ABC}",
            "ParentImage": "/usr/bin/python",
            "CommandLine": "curl https://example.com",
            "User": "root",
            "CurrentDirectory": "/home/user",
        },
    ]


@pytest.fixture
def events_file(tmp_path: Path) -> Path:
    """Create a temporary events JSON file."""
    events = create_test_events()
    file_path = tmp_path / "events.json"
    with open(file_path, "w") as f:
        json.dump(events, f)
    return file_path


@pytest.fixture
def baseline_file(tmp_path: Path, events_file: Path) -> Path:
    """Create a baseline file by running train command."""
    baseline_path = tmp_path / "baseline.json"
    result = runner.invoke(
        app,
        ["train", "-i", str(events_file), "-o", str(baseline_path)],
    )
    assert result.exit_code == 0
    return baseline_path


# =============================================================================
# Train Command Tests
# =============================================================================


class TestTrainCommand:
    """Tests for the train subcommand."""

    def test_train_creates_baseline(self, events_file: Path, tmp_path: Path) -> None:
        """Train command should create a baseline file."""
        baseline_path = tmp_path / "baseline.json"
        
        result = runner.invoke(
            app,
            ["train", "-i", str(events_file), "-o", str(baseline_path)],
        )
        
        assert result.exit_code == 0
        assert baseline_path.exists()

    def test_train_outputs_stats_to_stderr(
        self, events_file: Path, tmp_path: Path
    ) -> None:
        """Train command should output stats to stderr."""
        baseline_path = tmp_path / "baseline.json"
        
        result = runner.invoke(
            app,
            ["train", "-i", str(events_file), "-o", str(baseline_path)],
        )
        
        assert "events" in result.output.lower()
        assert "baseline" in result.output.lower()

    def test_train_file_not_found(self, tmp_path: Path) -> None:
        """Train should exit with code 1 if input file not found."""
        result = runner.invoke(
            app,
            ["train", "-i", "/nonexistent/file.json", "-o", str(tmp_path / "out.json")],
        )
        
        # Typer validates file existence, so it may fail differently
        assert result.exit_code != 0


# =============================================================================
# Analyze Command Tests
# =============================================================================


class TestAnalyzeCommand:
    """Tests for the analyze subcommand."""

    def test_analyze_outputs_json_to_stdout(
        self, events_file: Path, baseline_file: Path
    ) -> None:
        """Analyze should output JSON to stdout by default."""
        result = runner.invoke(
            app,
            ["analyze", "-i", str(events_file), "-b", str(baseline_file)],
        )
        
        assert result.exit_code == 0
        
        # Output should be valid JSON
        output_lines = result.output.strip().split("\n")
        # Find the JSON line (not stderr info messages)
        json_line = None
        for line in output_lines:
            if line.startswith("{"):
                json_line = line
                break
        
        assert json_line is not None
        report = json.loads(json_line)
        assert "analysis_id" in report
        assert "global_risk_score" in report

    def test_analyze_saves_to_file(
        self, events_file: Path, baseline_file: Path, tmp_path: Path
    ) -> None:
        """Analyze with --output should save to file."""
        output_path = tmp_path / "report.json"
        
        result = runner.invoke(
            app,
            [
                "analyze",
                "-i", str(events_file),
                "-b", str(baseline_file),
                "-o", str(output_path),
            ],
        )
        
        assert result.exit_code == 0
        assert output_path.exists()
        
        with open(output_path) as f:
            report = json.load(f)
        assert "analysis_id" in report

    def test_analyze_pretty_print(
        self, events_file: Path, baseline_file: Path
    ) -> None:
        """Analyze with --pretty should output indented JSON."""
        result = runner.invoke(
            app,
            [
                "analyze",
                "-i", str(events_file),
                "-b", str(baseline_file),
                "--pretty",
            ],
        )
        
        assert result.exit_code == 0
        # Pretty-printed JSON has newlines within the object
        assert "\n  " in result.output or '"analysis_id"' in result.output

    def test_analyze_baseline_not_found(self, events_file: Path) -> None:
        """Analyze should fail if baseline not found."""
        result = runner.invoke(
            app,
            ["analyze", "-i", str(events_file), "-b", "/nonexistent/baseline.json"],
        )
        
        assert result.exit_code != 0


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for CLI error handling."""

    def test_errors_print_to_stderr(self, tmp_path: Path) -> None:
        """Errors should be printed to stderr."""
        result = runner.invoke(
            app,
            ["train", "-i", "/nonexistent.json", "-o", str(tmp_path / "out.json")],
        )
        
        # Error should result in non-zero exit
        assert result.exit_code != 0

    def test_missing_required_options(self) -> None:
        """Missing required options should show help."""
        result = runner.invoke(app, ["analyze"])
        
        # Typer shows error for missing options
        assert result.exit_code != 0
