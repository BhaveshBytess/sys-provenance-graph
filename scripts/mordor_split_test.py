"""
mordor_split_test.py - Split-baseline smoke test for a Mordor dataset.

This script runs the adapter + baseline + detection + report flow:
1. Load the larger Mordor file.
2. Split loaded events 70/30 (train/test).
3. Build baseline profile from the 70% train split.
4. Run analysis pipeline on the 30% test split.
5. Save analysis report to JSON.
6. Print concise smoke test summary.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.adapters.mordor_adapter import load_mordor_events
from src.core.analyzer import AnomalyReason, build_baseline, detect_anomalies
from src.core.pipeline import run_pipeline


def _default_larger_mordor_path(repo_root: Path) -> Path:
    """Return the largest file from examples/mordor/*.json."""
    mordor_dir = repo_root / "examples" / "mordor"
    files = sorted(mordor_dir.glob("*.json"), key=lambda p: p.stat().st_size)

    if not files:
        raise FileNotFoundError(f"No Mordor JSON files found in {mordor_dir}")

    return files[-1]


def _count_eventid_1_records(file_path: Path) -> int:
    """Count parseable JSONL records where EventID == 1."""
    count = 0
    with file_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if obj.get("EventID") == 1:
                count += 1
    return count


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the split smoke test."""
    repo_root = Path(__file__).resolve().parents[1]
    default_input = _default_larger_mordor_path(repo_root)
    default_report = repo_root / "examples" / "mordor" / "split_test_report.json"

    parser = argparse.ArgumentParser(
        description="Run a 70/30 split-baseline Mordor smoke test through adapter and core pipeline.",
    )
    parser.add_argument(
        "--input-file",
        type=Path,
        default=default_input,
        help="Path to Mordor JSONL file (default: larger file).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=default_report,
        help="Path to save report JSON.",
    )

    return parser.parse_args()


def _serialize_report(report: Any, output_path: Path) -> None:
    """Write AnalysisReport to JSON file using Pydantic JSON mode."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report.model_dump(mode="json"), handle, indent=2)


def _split_events(events: list[Any], train_ratio: float = 0.7) -> tuple[list[Any], list[Any]]:
    """Split events into first train_ratio (train) and remaining (test)."""
    split_index = int(len(events) * train_ratio)

    # Ensure both sides are non-empty when possible.
    if len(events) >= 2:
        split_index = min(max(split_index, 1), len(events) - 1)

    return events[:split_index], events[split_index:]


def main() -> None:
    """Execute the full split-baseline Mordor smoke test flow."""
    args = _parse_args()

    input_file = args.input_file
    output_file = args.output

    candidate_events = _count_eventid_1_records(input_file)
    loaded_events = load_mordor_events(input_file)

    baseline_events, test_events = _split_events(loaded_events, train_ratio=0.7)

    baseline_profile = build_baseline(baseline_events)

    # Shared CLI/API path for full analysis orchestration.
    report = run_pipeline(test_events, baseline_profile)
    _serialize_report(report, output_file)

    # Reuse core anomaly logic for smoke summary breakdown.
    anomaly_results = detect_anomalies(test_events, baseline_profile)
    unknown_count = sum(1 for a in anomaly_results if a.reason == AnomalyReason.UNKNOWN)
    rare_count = sum(1 for a in anomaly_results if a.reason == AnomalyReason.RARE)

    pair_counter: Counter[str] = Counter()
    for anomaly in anomaly_results:
        parent_image, child_image, _user = anomaly.relationship_key
        pair_counter[f"{parent_image} -> {child_image}"] += 1

    total_loaded = len(baseline_events) + len(test_events)
    total_failed = max(candidate_events - total_loaded, 0)

    print("Mordor Smoke Test Summary")
    print(f"Baseline file: {input_file} [first 70% split]")
    print(f"Test file: {input_file} [last 30% split]")
    print(f"Report path: {output_file}")
    print(f"Total events loaded (baseline + test): {total_loaded}")
    print(f"Events passed validation: {total_loaded}")
    print(f"Events failed validation: {total_failed}")
    print(f"Anomalies detected (count): {len(report.anomalies)}")
    print(f"Unknown relationships (count): {unknown_count}")
    print(f"Rare relationships (count): {rare_count}")
    print("Top 5 flagged parent->child pairs:")

    top_pairs = pair_counter.most_common(5)
    if not top_pairs:
        print("  - None")
    else:
        for idx, (pair, count) in enumerate(top_pairs, start=1):
            print(f"  {idx}. {pair} ({count})")


if __name__ == "__main__":
    main()
