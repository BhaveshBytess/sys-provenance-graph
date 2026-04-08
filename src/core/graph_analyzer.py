"""
graph_analyzer.py - Graph-Based Process Relationship Analysis

This module provides graph-oriented analysis utilities for process
relationships represented in CanonicalEvent telemetry.

It complements frequency-based anomaly detection with structural context:
- Process graph construction
- Node and edge feature extraction
- Explainable graph risk factor enrichment for detected anomalies
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

import networkx as nx

if TYPE_CHECKING:
    from src.core.analyzer import AnomalyResult
    from src.core.events import CanonicalEvent


class ProcessGraph:
    """
    Directed graph of process relationships from events.

    Nodes are process images and directed edges are parent -> child
    process-spawn relationships.
    """

    def __init__(self, events: list["CanonicalEvent"]):
        """
        Build a directed process relationship graph from canonical events.

        Args:
            events: CanonicalEvent telemetry used to construct the graph.
        """
        self.graph: nx.DiGraph = nx.DiGraph()

        for event in events:
            parent_image = event.parent.image
            child_image = event.subject.image
            user = event.metadata.user

            self._ensure_node(parent_image)
            self._ensure_node(child_image)

            self.graph.nodes[parent_image]["total_as_parent"] += 1
            self.graph.nodes[parent_image]["users"].add(user)

            self.graph.nodes[child_image]["total_as_child"] += 1
            self.graph.nodes[child_image]["users"].add(user)

            if self.graph.has_edge(parent_image, child_image):
                self.graph[parent_image][child_image]["weight"] += 1
            else:
                self.graph.add_edge(parent_image, child_image, weight=1)

    def _ensure_node(self, image: str) -> None:
        """Create a graph node with default attributes if it does not exist."""
        if image not in self.graph:
            self.graph.add_node(
                image,
                total_as_parent=0,
                total_as_child=0,
                users=set(),
            )

    def has_node(self, image: str) -> bool:
        """Return True if the image exists as a node in the graph."""
        return image in self.graph

    def has_edge(self, parent_image: str, child_image: str) -> bool:
        """Return True if the directed edge exists in the graph."""
        return self.graph.has_edge(parent_image, child_image)

    def get_node_features(self, image: str) -> dict[str, Any]:
        """
        Return graph features for a process image node.

        Args:
            image: Process image path.

        Returns:
            Dictionary of node-level graph features.

        Raises:
            KeyError: If the image does not exist in the graph.
        """
        if image not in self.graph:
            raise KeyError(f"Node '{image}' not found in graph")

        node_data = self.graph.nodes[image]
        in_degree = self.graph.in_degree(image)
        out_degree = self.graph.out_degree(image)

        return {
            "in_degree": int(in_degree),
            "out_degree": int(out_degree),
            "total_spawned": int(node_data["total_as_parent"]),
            "total_spawned_as_child": int(node_data["total_as_child"]),
            "user_count": len(node_data["users"]),
            "is_leaf": out_degree == 0,
            "is_root": in_degree == 0,
        }

    def get_edge_features(self, parent_image: str, child_image: str) -> dict[str, Any]:
        """
        Return graph features for a directed parent->child edge.

        Args:
            parent_image: Parent process image path.
            child_image: Child process image path.

        Returns:
            Dictionary of edge-level graph features.
        """
        if not self.graph.has_edge(parent_image, child_image):
            return {
                "weight": 0,
                "fraction_of_parent": 0.0,
                "fraction_of_child": 0.0,
                "is_unique_parent": False,
                "is_unique_child": False,
            }

        weight = int(self.graph[parent_image][child_image]["weight"])
        parent_total = int(self.graph.nodes[parent_image]["total_as_parent"])
        child_total = int(self.graph.nodes[child_image]["total_as_child"])

        fraction_of_parent = (weight / parent_total) if parent_total > 0 else 0.0
        fraction_of_child = (weight / child_total) if child_total > 0 else 0.0

        return {
            "weight": weight,
            "fraction_of_parent": fraction_of_parent,
            "fraction_of_child": fraction_of_child,
            "is_unique_parent": self.graph.in_degree(child_image) == 1,
            "is_unique_child": self.graph.out_degree(parent_image) == 1,
        }

    def get_graph_stats(self) -> dict[str, Any]:
        """
        Return high-level graph statistics.

        Returns:
            Dictionary with node/edge totals, density, connectivity summary,
            and nodes whose total degree equals 1.
        """
        total_nodes = self.graph.number_of_nodes()
        total_edges = self.graph.number_of_edges()
        density = float(nx.density(self.graph)) if total_nodes > 0 else 0.0

        degree_counter: Counter[str] = Counter()
        for node in self.graph.nodes:
            degree_counter[node] = int(self.graph.in_degree(node) + self.graph.out_degree(node))

        most_connected_nodes = [
            {"image": image, "degree": degree}
            for image, degree in degree_counter.most_common(5)
        ]

        isolated_nodes = [image for image, degree in degree_counter.items() if degree == 1]

        return {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "density": density,
            "most_connected_nodes": most_connected_nodes,
            "isolated_nodes": isolated_nodes,
        }


def enrich_anomalies(
    anomalies: list["AnomalyResult"],
    baseline_graph: ProcessGraph,
    test_graph: ProcessGraph,
) -> list[dict[str, Any]]:
    """
    Enrich anomaly results with explainable graph-derived context.

    Args:
        anomalies: Frequency-based anomaly outputs from detect_anomalies().
        baseline_graph: Process graph built from baseline events.
        test_graph: Process graph built from test events.

    Returns:
        A list of dictionaries containing original anomaly information plus
        graph-derived node/edge context and explainable risk factors.
        Results are sorted by descending count of graph_risk_factors.
    """
    enriched: list[dict[str, Any]] = []
    baseline_components = _weak_component_map(baseline_graph.graph)

    for anomaly in anomalies:
        parent_image, child_image, user = anomaly.relationship_key

        parent_features = (
            baseline_graph.get_node_features(parent_image)
            if baseline_graph.has_node(parent_image)
            else None
        )
        child_features = (
            baseline_graph.get_node_features(child_image)
            if baseline_graph.has_node(child_image)
            else None
        )
        edge_features = (
            baseline_graph.get_edge_features(parent_image, child_image)
            if baseline_graph.has_edge(parent_image, child_image)
            else None
        )

        graph_risk_factors: list[str] = []

        if parent_features is None:
            graph_risk_factors.append(
                f"Parent process {parent_image} was never seen in baseline."
            )
        else:
            if parent_features["total_spawned"] == 0:
                graph_risk_factors.append(
                    f"Parent process {parent_image} has never spawned children in baseline."
                )
            if parent_features["out_degree"] <= 1:
                graph_risk_factors.append(
                    f"Parent process {parent_image} has low out-degree ({parent_features['out_degree']}), so a new child is highly unusual."
                )

        if child_features is None:
            graph_risk_factors.append(
                f"Child process {child_image} was never seen in baseline."
            )
        else:
            if child_features["is_leaf"]:
                graph_risk_factors.append(
                    f"Child process {child_image} is a leaf node in baseline and rarely appears in execution chains."
                )

        if edge_features is None:
            graph_risk_factors.append(
                f"Relationship {parent_image} -> {child_image} does not exist in the baseline process graph."
            )

            if parent_features is not None and child_features is not None:
                parent_component = baseline_components.get(parent_image)
                child_component = baseline_components.get(child_image)
                if parent_component is not None and child_component is not None:
                    if parent_component != child_component:
                        graph_risk_factors.append(
                            "This edge introduces a new path between previously unconnected baseline clusters."
                        )
        else:
            if edge_features["fraction_of_parent"] < 0.05:
                graph_risk_factors.append(
                    f"This edge accounts for only {edge_features['fraction_of_parent']:.2%} of parent process {parent_image} activity in baseline."
                )
            if edge_features["fraction_of_child"] < 0.05:
                graph_risk_factors.append(
                    f"This edge accounts for only {edge_features['fraction_of_child']:.2%} of child process {child_image} observations in baseline."
                )

        if test_graph.has_node(child_image) and not baseline_graph.has_node(child_image):
            child_test_features = test_graph.get_node_features(child_image)
            if child_test_features["is_leaf"]:
                graph_risk_factors.append(
                    f"Child process {child_image} is a new leaf node in test activity and was never seen in baseline."
                )

        if baseline_graph.has_node(parent_image):
            parent_users = baseline_graph.graph.nodes[parent_image]["users"]
            if user not in parent_users:
                graph_risk_factors.append(
                    f"User {user} has not previously executed parent process {parent_image} in baseline."
                )

        enriched_item = {
            "reason": anomaly.reason.value,
            "relationship_key": list(anomaly.relationship_key),
            "observed_count": anomaly.observed_count,
            "baseline_total": anomaly.baseline_total,
            "risk_level": anomaly.risk_level.value,
            "confidence": anomaly.confidence,
            "description": anomaly.description,
            "event": anomaly.event.model_dump(mode="json"),
            "parent_node_features": parent_features,
            "child_node_features": child_features,
            "edge_features": edge_features,
            "graph_risk_factors": graph_risk_factors,
        }
        enriched.append(enriched_item)

    enriched.sort(key=lambda item: len(item["graph_risk_factors"]), reverse=True)
    return enriched


def _weak_component_map(graph: nx.DiGraph) -> dict[str, int]:
    """Build a map of node -> weakly connected component index."""
    component_map: dict[str, int] = {}
    for idx, component in enumerate(nx.weakly_connected_components(graph)):
        for node in component:
            component_map[node] = idx
    return component_map
