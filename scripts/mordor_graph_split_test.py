"""Run 70/30 split graph-based anomaly enrichment on a Mordor dataset."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.adapters.mordor_adapter import load_mordor_events
from src.core.analyzer import build_baseline, detect_anomalies
from src.core.graph_analyzer import ProcessGraph, enrich_anomalies


def _default_larger_mordor_path(repo_root: Path) -> Path:
    """Pick the largest JSON file in examples/mordor."""
    mordor_dir = repo_root / "examples" / "mordor"
    files = sorted(
        [path for path in mordor_dir.glob("*.json") if not path.name.endswith("_report.json")],
        key=lambda p: p.stat().st_size,
    )

    if not files:
        raise FileNotFoundError(f"No Mordor JSON files found in {mordor_dir}")

    return files[-1]


def _parse_args() -> argparse.Namespace:
    """Parse CLI options for split graph analysis run."""
    repo_root = Path(__file__).resolve().parents[1]
    default_input = _default_larger_mordor_path(repo_root)
    default_output = repo_root / "examples" / "mordor" / "graph_split_report.json"

    parser = argparse.ArgumentParser(
        description="Run 70/30 split graph-based enrichment on Mordor anomalies.",
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
        default=default_output,
        help="Path to save enriched split graph analysis JSON.",
    )
    return parser.parse_args()


def _split_events(events: list[Any], train_ratio: float = 0.7) -> tuple[list[Any], list[Any]]:
    """Split events by order into baseline and test partitions."""
    split_index = int(len(events) * train_ratio)

    if len(events) >= 2:
        split_index = min(max(split_index, 1), len(events) - 1)

    return events[:split_index], events[split_index:]


def _save_report(output_path: Path, payload: dict[str, Any]) -> None:
    """Write JSON report payload to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def main() -> None:
    """Execute split graph analysis and print a concise summary."""
    args = _parse_args()

    loaded_events = load_mordor_events(args.input_file)
    baseline_events, test_events = _split_events(loaded_events, train_ratio=0.7)

    baseline_graph = ProcessGraph(baseline_events)
    test_graph = ProcessGraph(test_events)

    baseline_profile = build_baseline(baseline_events)
    anomalies = detect_anomalies(test_events, baseline_profile)
    enriched = enrich_anomalies(anomalies, baseline_graph, test_graph)

    baseline_stats = baseline_graph.get_graph_stats()
    test_stats = test_graph.get_graph_stats()
    with_factors = sum(1 for item in enriched if item["graph_risk_factors"])

    report_payload = {
        "input_file": str(args.input_file),
        "baseline_window": "first_70_percent",
        "test_window": "last_30_percent",
        "baseline_graph": baseline_stats,
        "test_graph": test_stats,
        "anomaly_count": len(enriched),
        "anomalies_with_graph_risk_factors": with_factors,
        "anomalies": enriched,
    }
    _save_report(args.output, report_payload)

    print("Mordor Graph Analysis Summary")
    print(
        "Baseline graph: "
        f"{baseline_stats['total_nodes']} nodes, {baseline_stats['total_edges']} edges"
    )
    print(
        "Test graph: "
        f"{test_stats['total_nodes']} nodes, {test_stats['total_edges']} edges"
    )
    print(f"Anomalies found: {len(enriched)}")
    print(f"Anomalies with graph risk factors: {with_factors}")
    print("Top 5 most suspicious:")

    top_items = sorted(enriched, key=lambda item: len(item["graph_risk_factors"]), reverse=True)[:5]
    if not top_items:
        print("  - None")
    else:
        for idx, item in enumerate(top_items, start=1):
            parent_image, child_image, _user = item["relationship_key"]
            print(f"  {idx}. {parent_image} -> {child_image}")
            print(f"     risk_level: {item['risk_level']}")
            factors: list[str] = item["graph_risk_factors"]
            if not factors:
                print("     graph_risk_factors: None")
            else:
                print("     graph_risk_factors:")
                for factor in factors:
                    print(f"       - {factor}")

    print(f"Report path: {args.output}")


if __name__ == "__main__":
    main()
