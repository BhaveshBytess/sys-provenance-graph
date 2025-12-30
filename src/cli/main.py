"""
CLI Interface for System Behavior Analyzer

This module provides the command-line interface using Typer.
It exposes two subcommands:
- train: Build a baseline from event logs
- analyze: Detect anomalies using a baseline

Output is JSON to STDOUT by default for piping.
Errors are printed to STDERR with non-zero exit codes.
"""

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from src.core.pipeline import (
    load_baseline_from_file,
    load_events_from_file,
    run_pipeline,
    train_baseline,
)

# Create Typer app
app = typer.Typer(
    name="sba",
    help="System Behavior Analyzer - Detect anomalous process behavior",
    add_completion=False,
)


def _error(message: str) -> None:
    """Print error message to STDERR."""
    typer.echo(f"Error: {message}", err=True)


def _info(message: str) -> None:
    """Print info message to STDERR (not mixed with JSON output)."""
    typer.echo(message, err=True)


@app.command()
def train(
    input_file: Path = typer.Option(
        ...,
        "--input", "-i",
        help="Path to events JSON file for training",
        exists=True,
        readable=True,
    ),
    output_file: Path = typer.Option(
        ...,
        "--output", "-o",
        help="Path to save baseline JSON file",
    ),
) -> None:
    """
    Build a baseline profile from event logs.
    
    This command reads events from the input file and learns
    normal execution patterns, saving the baseline to disk.
    
    Example:
        sba train -i events.json -o baseline.json
    """
    try:
        _info(f"Loading events from {input_file}...")
        events = load_events_from_file(input_file)
        _info(f"Loaded {len(events)} events")
        
        _info(f"Building baseline...")
        baseline = train_baseline(events, output_file)
        
        _info(f"Baseline saved to {output_file}")
        _info(f"  - Total events: {baseline.total_events}")
        _info(f"  - Unique relationships: {baseline.get_unique_relationship_count()}")
        
    except FileNotFoundError as e:
        _error(f"File not found: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        _error(f"Failed to build baseline: {e}")
        raise typer.Exit(code=1)


@app.command()
def analyze(
    input_file: Path = typer.Option(
        ...,
        "--input", "-i",
        help="Path to events JSON file to analyze",
        exists=True,
        readable=True,
    ),
    baseline_file: Path = typer.Option(
        ...,
        "--baseline", "-b",
        help="Path to baseline JSON file",
        exists=True,
        readable=True,
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Path to save report JSON (default: print to STDOUT)",
    ),
    pretty: bool = typer.Option(
        False,
        "--pretty", "-p",
        help="Pretty-print JSON output with indentation",
    ),
) -> None:
    """
    Analyze events and detect anomalies.
    
    This command compares events against a baseline and detects
    deviations that may indicate anomalous behavior.
    
    Output is JSON to STDOUT by default for piping.
    
    Example:
        sba analyze -i events.json -b baseline.json
        sba analyze -i events.json -b baseline.json -o report.json
        sba analyze -i events.json -b baseline.json | jq '.anomalies'
    """
    try:
        _info(f"Loading events from {input_file}...")
        events = load_events_from_file(input_file)
        _info(f"Loaded {len(events)} events")
        
        _info(f"Loading baseline from {baseline_file}...")
        baseline = load_baseline_from_file(baseline_file)
        _info(f"Baseline loaded ({baseline.get_unique_relationship_count()} relationships)")
        
        _info("Running analysis pipeline...")
        report = run_pipeline(events, baseline)
        
        # Serialize report to JSON
        # Use model_dump() for Pydantic v2
        report_dict = report.model_dump(mode="json")
        
        if pretty:
            json_output = json.dumps(report_dict, indent=2, default=str)
        else:
            json_output = json.dumps(report_dict, default=str)
        
        # Output to file or STDOUT
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(json_output)
            _info(f"Report saved to {output_file}")
        else:
            # Print to STDOUT (for piping)
            typer.echo(json_output)
        
        # Log summary to STDERR
        _info(f"Analysis complete:")
        _info(f"  - Events processed: {report.metadata.events_processed}")
        _info(f"  - Anomalies detected: {len(report.anomalies)}")
        _info(f"  - Global risk score: {report.global_risk_score}/100")
        
    except FileNotFoundError as e:
        _error(f"File not found: {e}")
        raise typer.Exit(code=1)
    except ValueError as e:
        _error(f"Invalid data: {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        _error(f"Analysis failed: {e}")
        raise typer.Exit(code=1)


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
