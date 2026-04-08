"""Quick end-to-end smoke run for Mordor datasets."""

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


def _default_mordor_paths(repo_root: Path) -> tuple[Path, Path]:
    """Return (smaller_file, larger_file) from examples/mordor/*.json."""
    mordor_dir = repo_root / "examples" / "mordor"
    files = sorted(
        [path for path in mordor_dir.glob("*.json") if not path.name.endswith("_report.json")],
        key=lambda p: p.stat().st_size,
    )

    if len(files) < 2:
        raise FileNotFoundError(
            f"Expected at least 2 Mordor JSON files in {mordor_dir}, found {len(files)}"
        )

    return files[0], files[-1]


def _count_eventid_1_records(file_path: Path) -> int:
    """Count parseable rows where EventID == 1."""
    count = 0
    with file_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if record.get("EventID") == 1:
                count += 1
    return count


def _parse_args() -> argparse.Namespace:
    """Parse CLI options."""
    repo_root = Path(__file__).resolve().parents[1]
    default_baseline, default_test = _default_mordor_paths(repo_root)
    default_report = repo_root / "examples" / "mordor" / "smoke_test_report.json"

    parser = argparse.ArgumentParser(
        description="Run Mordor end-to-end smoke test through adapter and core pipeline.",
    )
    parser.add_argument(
        "--baseline-file",
        type=Path,
        default=default_baseline,
        help="Path to Mordor baseline JSONL file (default: smaller file).",
    )
    parser.add_argument(
        "--test-file",
        type=Path,
        default=default_test,
        help="Path to Mordor attack/test JSONL file (default: larger file).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=default_report,
        help="Path to save report JSON.",
    )

    return parser.parse_args()


def _serialize_report(report: Any, output_path: Path) -> None:
    """Write report JSON to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report.model_dump(mode="json"), handle, indent=2)


def main() -> None:
    """Run smoke test and print a compact summary."""
    args = _parse_args()

    baseline_file = args.baseline_file
    test_file = args.test_file
    output_file = args.output

    baseline_candidates = _count_eventid_1_records(baseline_file)
    test_candidates = _count_eventid_1_records(test_file)

    baseline_events = load_mordor_events(baseline_file)
    test_events = load_mordor_events(test_file)

    baseline_profile = build_baseline(baseline_events)

    report = run_pipeline(test_events, baseline_profile)
    _serialize_report(report, output_file)

    anomaly_results = detect_anomalies(test_events, baseline_profile)
    unknown_count = sum(1 for a in anomaly_results if a.reason == AnomalyReason.UNKNOWN)
    rare_count = sum(1 for a in anomaly_results if a.reason == AnomalyReason.RARE)

    pair_counter: Counter[str] = Counter()
    for anomaly in anomaly_results:
        parent_image, child_image, _user = anomaly.relationship_key
        pair_counter[f"{parent_image} -> {child_image}"] += 1

    total_loaded = len(baseline_events) + len(test_events)
    total_candidates = baseline_candidates + test_candidates
    total_failed = max(total_candidates - total_loaded, 0)

    print("Mordor Smoke Test Summary")
    print(f"Baseline file: {baseline_file}")
    print(f"Test file: {test_file}")
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
