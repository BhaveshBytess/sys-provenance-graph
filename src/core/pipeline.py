"""
pipeline.py - Shared Analysis Pipeline

This module provides the high-level pipeline function that orchestrates
the complete analysis workflow. Both CLI and API use this single function
to ensure consistent behavior.

Pipeline Steps:
1. Load events from raw data
2. Build event index for O(1) lookups
3. Detect anomalies against baseline
4. Reconstruct chains for anomalies
5. Assemble final report
"""

from pathlib import Path
from typing import Any

from src.core.analyzer import (
    BaselineProfile,
    assemble_report,
    build_baseline,
    build_event_index,
    detect_anomalies,
    enrich_anomalies_with_chains,
    load_baseline,
    save_baseline,
)
from src.core.events import AnalysisReport, CanonicalEvent
from src.core.loader import load_events


def run_pipeline(
    events: list[CanonicalEvent],
    baseline: BaselineProfile,
) -> AnalysisReport:
    """
    Run the complete analysis pipeline on a set of events.
    
    This is the shared entry point for both CLI and API. It orchestrates:
    1. Build event index (O(1) lookup)
    2. Detect anomalies against baseline
    3. Reconstruct chains for anomalies
    4. Assemble final report
    
    Args:
        events: List of CanonicalEvent objects to analyze.
        baseline: The BaselineProfile to compare against.
    
    Returns:
        A complete AnalysisReport with all findings.
    
    Example:
        >>> events = load_events(raw_json)
        >>> baseline = load_baseline(Path("baseline.json"))
        >>> report = run_pipeline(events, baseline)
    """
    # Step 1: Build event index for O(1) lookups
    event_index = build_event_index(events)
    
    # Step 2: Detect anomalies against baseline
    anomalies = detect_anomalies(events, baseline)
    
    # Step 3: Reconstruct chains for anomalies
    chains = enrich_anomalies_with_chains(anomalies, event_index)
    
    # Step 4: Assemble final report
    report = assemble_report(
        anomalies=anomalies,
        chains=chains,
        event_index=event_index,
        baseline=baseline,
        events_processed=len(events),
    )
    
    return report


def train_baseline(
    events: list[CanonicalEvent],
    output_path: Path,
) -> BaselineProfile:
    """
    Build a baseline profile from events and save to disk.
    
    This is the training mode entry point for CLI.
    
    Args:
        events: List of CanonicalEvent objects for training.
        output_path: Path to save the baseline JSON file.
    
    Returns:
        The built BaselineProfile.
    """
    # Build baseline from events
    baseline = build_baseline(events)
    
    # Save to disk
    save_baseline(baseline, output_path)
    
    return baseline


def load_events_from_file(file_path: Path) -> list[CanonicalEvent]:
    """
    Load and parse events from a JSON file.
    
    Args:
        file_path: Path to the events JSON file.
    
    Returns:
        List of validated CanonicalEvent objects.
    
    Raises:
        FileNotFoundError: If the file does not exist.
        MalformedInputError: If the JSON is invalid.
        InvalidEventError: If events fail validation.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        raw_data = f.read()
    
    return load_events(raw_data)


def load_baseline_from_file(file_path: Path) -> BaselineProfile:
    """
    Load a baseline profile from a JSON file.
    
    Args:
        file_path: Path to the baseline JSON file.
    
    Returns:
        The loaded BaselineProfile.
    
    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the format is invalid.
    """
    return load_baseline(file_path)
