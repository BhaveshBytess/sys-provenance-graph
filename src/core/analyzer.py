"""
analyzer.py - Core Analysis Engine

This module contains all system intelligence:
- Baseline construction (Phase 3)
- Anomaly detection (Phase 4)
- Chain reconstruction (Phase 5) - NOT YET IMPLEMENTED
- Report assembly (Phase 6) - NOT YET IMPLEMENTED

See SPEC.md Section 4.2 for responsibilities.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.events import CanonicalEvent


# =============================================================================
# Constants
# =============================================================================

# Version string for baseline compatibility tracking
BASELINE_VERSION = "1.0.0"

# -----------------------------------------------------------------------------
# DETECTION THRESHOLDS (Configurable - Phase 4)
# -----------------------------------------------------------------------------
# These thresholds control anomaly detection sensitivity.
# Adjust based on environment and false positive tolerance.

# Minimum observation count for a relationship to be considered "normal"
# Relationships observed fewer times than this are flagged as RARE
RARITY_COUNT_THRESHOLD: int = 3

# Minimum percentage of total events for a relationship to be considered "normal"
# Relationships below this percentage are flagged as RARE (if above count threshold)
RARITY_PERCENTAGE_THRESHOLD: float = 0.001  # 0.1% of total events

# -----------------------------------------------------------------------------
# CHAIN RECONSTRUCTION (Configurable - Phase 5)
# -----------------------------------------------------------------------------
# These settings control execution chain reconstruction behavior.

# Maximum depth for parent chain traversal (safety limit)
# Prevents infinite loops and excessive memory usage
MAX_CHAIN_DEPTH: int = 10

# Known root process images that terminate chain traversal
# When these are encountered, the chain is considered complete
KNOWN_ROOT_IMAGES: frozenset[str] = frozenset({
    "/sbin/init",
    "/usr/lib/systemd/systemd",
    "/lib/systemd/systemd",
    "systemd",
    "init",
    "[kernel]",
})


# =============================================================================
# Baseline Profile
# =============================================================================


@dataclass
class BaselineProfile:
    """
    A learned profile of normal execution behavior.
    
    The baseline captures normal parent → child process relationships
    observed during training. Each relationship is keyed by a tuple of
    (parent_image, child_image, user) to capture user-specific behavior.
    
    Attributes:
        relationships: Counter mapping (parent_image, child_image, user) 
                      tuples to observation counts.
        total_events: Total number of events used to build this baseline.
        version: Version string for compatibility tracking.
    
    Example:
        >>> profile = BaselineProfile()
        >>> profile.relationships[("/bin/bash", "/usr/bin/python3", "root")] = 42
        >>> profile.total_events = 1000
    """
    relationships: Counter[tuple[str, str, str]] = field(default_factory=Counter)
    total_events: int = 0
    version: str = BASELINE_VERSION
    
    def get_relationship_count(
        self, 
        parent_image: str, 
        child_image: str, 
        user: str
    ) -> int:
        """
        Get the observation count for a specific relationship.
        
        Args:
            parent_image: Path to parent executable.
            child_image: Path to child executable.
            user: User account under which the relationship was observed.
        
        Returns:
            Number of times this relationship was observed, or 0 if never seen.
        """
        return self.relationships.get((parent_image, child_image, user), 0)
    
    def has_relationship(
        self, 
        parent_image: str, 
        child_image: str, 
        user: str
    ) -> bool:
        """
        Check if a relationship exists in the baseline.
        
        Args:
            parent_image: Path to parent executable.
            child_image: Path to child executable.
            user: User account.
        
        Returns:
            True if the relationship has been observed at least once.
        """
        return (parent_image, child_image, user) in self.relationships
    
    def get_unique_relationship_count(self) -> int:
        """
        Get the number of unique relationships in the baseline.
        
        Returns:
            Count of distinct (parent_image, child_image, user) tuples.
        """
        return len(self.relationships)
    
    def merge(self, other: BaselineProfile) -> None:
        """
        Merge another baseline profile into this one.
        
        This allows incremental updates to the baseline by combining
        observations from multiple training sessions.
        
        Args:
            other: Another BaselineProfile to merge into this one.
        """
        self.relationships.update(other.relationships)
        self.total_events += other.total_events


# =============================================================================
# Baseline Construction Functions
# =============================================================================


def build_baseline(events: list["CanonicalEvent"]) -> BaselineProfile:
    """
    Build a baseline profile from a list of canonical events.
    
    This function learns normal execution behavior by extracting
    parent → child process relationships from the provided events.
    Each relationship is keyed by (parent_image, child_image, user).
    
    Args:
        events: A list of CanonicalEvent objects. Raw dictionaries or
               JSON strings are NOT accepted - events must be validated
               CanonicalEvent instances.
    
    Returns:
        A BaselineProfile containing the learned relationships.
    
    Raises:
        TypeError: If events is not a list or contains non-CanonicalEvent items.
    
    Example:
        >>> from src.core.loader import load_events
        >>> events = load_events(raw_data)
        >>> profile = build_baseline(events)
        >>> save_baseline(profile, Path("baseline.json"))
    """
    # Import here to avoid circular imports
    from src.core.events import CanonicalEvent
    
    # Strict type validation - MUST be list[CanonicalEvent]
    if not isinstance(events, list):
        raise TypeError(
            f"events must be a list of CanonicalEvent objects, "
            f"got {type(events).__name__}"
        )
    
    for idx, event in enumerate(events):
        if not isinstance(event, CanonicalEvent):
            raise TypeError(
                f"Event at index {idx} must be a CanonicalEvent, "
                f"got {type(event).__name__}. "
                f"Use loader.load_events() to convert raw data first."
            )
    
    # Build the profile
    profile = BaselineProfile()
    profile.total_events = len(events)
    
    for event in events:
        # Extract the relationship key: (parent_image, child_image, user)
        relationship_key = (
            event.parent.image,
            event.subject.image,
            event.metadata.user,
        )
        profile.relationships[relationship_key] += 1
    
    return profile


def update_baseline(
    profile: BaselineProfile, 
    events: list["CanonicalEvent"]
) -> BaselineProfile:
    """
    Update an existing baseline profile with new events.
    
    This allows incremental training by adding new observations
    to an existing baseline without rebuilding from scratch.
    
    Args:
        profile: The existing BaselineProfile to update.
        events: New CanonicalEvent objects to incorporate.
    
    Returns:
        The updated BaselineProfile (same instance, modified in place).
    
    Raises:
        TypeError: If events contains non-CanonicalEvent items.
    """
    new_profile = build_baseline(events)
    profile.merge(new_profile)
    return profile


# =============================================================================
# Baseline Persistence Functions
# =============================================================================


def save_baseline(profile: BaselineProfile, path: Path) -> None:
    """
    Save a baseline profile to a JSON file.
    
    The output is human-readable JSON with sorted keys to ensure
    deterministic output regardless of input event order.
    
    Args:
        profile: The BaselineProfile to save.
        path: Path to the output JSON file.
    
    Raises:
        IOError: If the file cannot be written.
    
    Example:
        >>> save_baseline(profile, Path("baseline.json"))
    """
    # Convert relationships to a serializable format
    # Keys are sorted to ensure deterministic output (order independence)
    relationships_list = [
        {
            "parent_image": parent_image,
            "child_image": child_image,
            "user": user,
            "count": count,
        }
        for (parent_image, child_image, user), count 
        in sorted(profile.relationships.items())
    ]
    
    data = {
        "version": profile.version,
        "total_events": profile.total_events,
        "unique_relationships": len(profile.relationships),
        "relationships": relationships_list,
    }
    
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write with sorted keys and indentation for human readability
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def load_baseline(path: Path) -> BaselineProfile:
    """
    Load a baseline profile from a JSON file.
    
    Args:
        path: Path to the baseline JSON file.
    
    Returns:
        The loaded BaselineProfile.
    
    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file format is invalid.
        IOError: If the file cannot be read.
    
    Example:
        >>> profile = load_baseline(Path("baseline.json"))
        >>> print(f"Loaded {profile.get_unique_relationship_count()} relationships")
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    # Validate structure
    if not isinstance(data, dict):
        raise ValueError(f"Invalid baseline format: expected object, got {type(data).__name__}")
    
    required_fields = ["version", "total_events", "relationships"]
    for field_name in required_fields:
        if field_name not in data:
            raise ValueError(f"Invalid baseline format: missing '{field_name}' field")
    
    # Reconstruct the profile
    profile = BaselineProfile()
    profile.version = data["version"]
    profile.total_events = data["total_events"]
    
    # Reconstruct relationships Counter
    for rel in data["relationships"]:
        key = (rel["parent_image"], rel["child_image"], rel["user"])
        profile.relationships[key] = rel["count"]
    
    return profile


# =============================================================================
# Anomaly Detection (Phase 4)
# =============================================================================


class AnomalyReason(Enum):
    """
    Reason why an event was flagged as anomalous.
    
    Used to distinguish between completely unknown relationships
    and relationships that are simply rare.
    """
    UNKNOWN = "unknown"      # Relationship never seen in baseline
    RARE = "rare"            # Relationship seen but below threshold


@dataclass(frozen=True)
class AnomalyResult:
    """
    Intermediate result from anomaly detection.
    
    This is a purely internal data structure used between detection
    and report assembly. It contains the raw detection findings without
    chain reconstruction or full report formatting.
    
    Attributes:
        event: The CanonicalEvent that triggered the anomaly.
        reason: Why this event was flagged (UNKNOWN or RARE).
        relationship_key: The (parent_image, child_image, user) tuple.
        observed_count: How many times this relationship was seen in baseline.
        baseline_total: Total events in the baseline for context.
        risk_level: Assigned risk level based on statistical analysis.
        confidence: Confidence score for the detection (0.0 to 1.0).
        description: Human-readable explanation of the anomaly.
    """
    event: "CanonicalEvent"
    reason: AnomalyReason
    relationship_key: tuple[str, str, str]
    observed_count: int
    baseline_total: int
    risk_level: "RiskLevel"
    confidence: float
    description: str


def detect_anomalies(
    events: list["CanonicalEvent"],
    baseline: BaselineProfile,
    *,
    rarity_count_threshold: int = RARITY_COUNT_THRESHOLD,
    rarity_percentage_threshold: float = RARITY_PERCENTAGE_THRESHOLD,
) -> list[AnomalyResult]:
    """
    Detect anomalies by comparing events against a learned baseline.
    
    This function is PURELY FUNCTIONAL and does NOT mutate the baseline.
    Learning happens in Phase 3 (build_baseline); Detection happens here.
    
    An event is considered anomalous if its (parent_image, child_image, user)
    relationship is either:
    1. UNKNOWN: Never observed in the baseline
    2. RARE: Observed fewer times than the configured thresholds
    
    Risk levels are assigned based on STATISTICAL ANALYSIS ONLY:
    - CRITICAL: Unknown relationship (never seen)
    - HIGH: Rare relationship (seen < threshold times)
    - MEDIUM: Rare by percentage (seen but below % threshold)
    
    Args:
        events: List of CanonicalEvent objects to analyze.
        baseline: The learned BaselineProfile to compare against (READ-ONLY).
        rarity_count_threshold: Minimum count for "normal" (default: RARITY_COUNT_THRESHOLD).
        rarity_percentage_threshold: Minimum % for "normal" (default: RARITY_PERCENTAGE_THRESHOLD).
    
    Returns:
        A list of AnomalyResult objects for events that deviate from baseline.
        Events that match baseline behavior are NOT included in the result.
    
    Raises:
        TypeError: If events is not a list or contains non-CanonicalEvent items.
    
    Example:
        >>> baseline = load_baseline(Path("baseline.json"))
        >>> events = load_events(new_telemetry)
        >>> anomalies = detect_anomalies(events, baseline)
        >>> for anomaly in anomalies:
        ...     print(f"{anomaly.risk_level}: {anomaly.description}")
    """
    # Import here to avoid circular imports
    from src.core.events import CanonicalEvent, RiskLevel
    
    # Strict type validation - MUST be list[CanonicalEvent]
    if not isinstance(events, list):
        raise TypeError(
            f"events must be a list of CanonicalEvent objects, "
            f"got {type(events).__name__}"
        )
    
    for idx, event in enumerate(events):
        if not isinstance(event, CanonicalEvent):
            raise TypeError(
                f"Event at index {idx} must be a CanonicalEvent, "
                f"got {type(event).__name__}. "
                f"Use loader.load_events() to convert raw data first."
            )
    
    anomalies: list[AnomalyResult] = []
    
    for event in events:
        # Extract relationship key
        relationship_key = (
            event.parent.image,
            event.subject.image,
            event.metadata.user,
        )
        
        # Check against baseline (READ-ONLY access)
        observed_count = baseline.get_relationship_count(*relationship_key)
        
        # Determine if anomalous
        anomaly_result = _evaluate_relationship(
            event=event,
            relationship_key=relationship_key,
            observed_count=observed_count,
            baseline_total=baseline.total_events,
            rarity_count_threshold=rarity_count_threshold,
            rarity_percentage_threshold=rarity_percentage_threshold,
        )
        
        if anomaly_result is not None:
            anomalies.append(anomaly_result)
    
    return anomalies


def _evaluate_relationship(
    event: "CanonicalEvent",
    relationship_key: tuple[str, str, str],
    observed_count: int,
    baseline_total: int,
    rarity_count_threshold: int,
    rarity_percentage_threshold: float,
) -> AnomalyResult | None:
    """
    Evaluate a single relationship and return an AnomalyResult if anomalous.
    
    This is a pure function that performs statistical analysis only.
    No domain semantics or hardcoded rules are applied.
    
    Args:
        event: The event being evaluated.
        relationship_key: The (parent_image, child_image, user) tuple.
        observed_count: How many times seen in baseline.
        baseline_total: Total events in baseline.
        rarity_count_threshold: Minimum count threshold.
        rarity_percentage_threshold: Minimum percentage threshold.
    
    Returns:
        AnomalyResult if anomalous, None if normal.
    """
    from src.core.events import RiskLevel
    
    parent_image, child_image, user = relationship_key
    
    # Case 1: UNKNOWN - Never seen in baseline
    if observed_count == 0:
        return AnomalyResult(
            event=event,
            reason=AnomalyReason.UNKNOWN,
            relationship_key=relationship_key,
            observed_count=0,
            baseline_total=baseline_total,
            risk_level=RiskLevel.CRITICAL,
            confidence=1.0,  # 100% confident it's unknown
            description=(
                f"Unknown relationship: '{parent_image}' spawned '{child_image}' "
                f"as user '{user}'. This combination was never observed in baseline."
            ),
        )
    
    # Case 2: RARE by count - Seen but below count threshold
    if observed_count < rarity_count_threshold:
        confidence = 1.0 - (observed_count / rarity_count_threshold)
        return AnomalyResult(
            event=event,
            reason=AnomalyReason.RARE,
            relationship_key=relationship_key,
            observed_count=observed_count,
            baseline_total=baseline_total,
            risk_level=RiskLevel.HIGH,
            confidence=confidence,
            description=(
                f"Rare relationship: '{parent_image}' spawned '{child_image}' "
                f"as user '{user}'. Observed only {observed_count} time(s) in baseline "
                f"(threshold: {rarity_count_threshold})."
            ),
        )
    
    # Case 3: RARE by percentage - Above count but below percentage threshold
    if baseline_total > 0:
        observed_percentage = observed_count / baseline_total
        if observed_percentage < rarity_percentage_threshold:
            confidence = 1.0 - (observed_percentage / rarity_percentage_threshold)
            return AnomalyResult(
                event=event,
                reason=AnomalyReason.RARE,
                relationship_key=relationship_key,
                observed_count=observed_count,
                baseline_total=baseline_total,
                risk_level=RiskLevel.MEDIUM,
                confidence=confidence,
                description=(
                    f"Statistically rare relationship: '{parent_image}' spawned '{child_image}' "
                    f"as user '{user}'. Observed {observed_count} time(s) ({observed_percentage:.4%}) "
                    f"which is below threshold ({rarity_percentage_threshold:.4%})."
                ),
            )
    
    # Not anomalous - relationship is within normal parameters
    return None


# =============================================================================
# Chain Reconstruction (Phase 5)
# =============================================================================


def build_event_index(events: list["CanonicalEvent"]) -> dict[str, "CanonicalEvent"]:
    """
    Build an O(1) lookup index from process GUID to CanonicalEvent.
    
    This index enables efficient parent traversal during chain reconstruction
    without iterating through the event list for each lookup.
    
    Args:
        events: List of CanonicalEvent objects to index.
    
    Returns:
        A dictionary mapping subject.guid to CanonicalEvent.
        If multiple events share the same GUID, the last one wins.
    
    Raises:
        TypeError: If events is not a list or contains non-CanonicalEvent items.
    
    Example:
        >>> events = load_events(raw_data)
        >>> index = build_event_index(events)
        >>> event = index.get("some-guid")
    """
    from src.core.events import CanonicalEvent
    
    # Strict type validation
    if not isinstance(events, list):
        raise TypeError(
            f"events must be a list of CanonicalEvent objects, "
            f"got {type(events).__name__}"
        )
    
    index: dict[str, CanonicalEvent] = {}
    
    for idx, event in enumerate(events):
        if not isinstance(event, CanonicalEvent):
            raise TypeError(
                f"Event at index {idx} must be a CanonicalEvent, "
                f"got {type(event).__name__}."
            )
        # Index by subject GUID (the process created by this event)
        index[event.subject.guid] = event
    
    return index


def reconstruct_chain(
    event: "CanonicalEvent",
    event_index: dict[str, "CanonicalEvent"],
    *,
    max_depth: int = MAX_CHAIN_DEPTH,
    known_roots: frozenset[str] = KNOWN_ROOT_IMAGES,
) -> list[str]:
    """
    Reconstruct the execution chain for a given event.
    
    This function traverses parent relationships to build a causal chain
    from the root ancestor down to the given event. The chain provides
    context for understanding how a process execution occurred.
    
    Traversal terminates when:
    1. Parent GUID is not found in the index (missing data)
    2. Maximum depth is reached (safety limit)
    3. A known root process is reached (e.g., systemd, init)
    4. A cycle is detected (GUID already visited)
    
    The output is ordered chronologically: root/ancestor first, event last.
    
    Args:
        event: The CanonicalEvent to reconstruct the chain for.
        event_index: Pre-built GUID → CanonicalEvent lookup index.
                    MUST be built using build_event_index() for O(1) lookups.
        max_depth: Maximum traversal depth (default: MAX_CHAIN_DEPTH).
        known_roots: Set of image paths considered root processes.
    
    Returns:
        Ordered list of process GUIDs from root ancestor to the event.
        The last element is always the event's subject.guid.
    
    Example:
        >>> index = build_event_index(all_events)
        >>> chain = reconstruct_chain(anomalous_event, index)
        >>> print(f"Chain: {' -> '.join(chain)}")
    """
    # Start with the current event's GUID
    current_guid = event.subject.guid
    
    # Build chain in reverse order (child → parent → grandparent → ...)
    # We'll reverse it at the end for chronological order
    chain_reversed: list[str] = [current_guid]
    
    # Track visited GUIDs to detect cycles
    visited: set[str] = {current_guid}
    
    # Current position for traversal
    current_event = event
    depth = 0
    
    while depth < max_depth:
        # Get parent GUID from current event
        parent_guid = current_event.parent.guid
        
        # Termination: Cycle detected
        if parent_guid in visited:
            break
        
        # Mark as visited
        visited.add(parent_guid)
        
        # Termination: Parent not in index (missing data / orphan)
        parent_event = event_index.get(parent_guid)
        if parent_event is None:
            # Add parent GUID even if we don't have its event data
            # This preserves the link information
            chain_reversed.append(parent_guid)
            break
        
        # Add parent to chain
        chain_reversed.append(parent_guid)
        
        # Termination: Known root process reached
        parent_image = parent_event.subject.image
        if _is_root_process(parent_image, known_roots):
            break
        
        # Move to parent for next iteration
        current_event = parent_event
        depth += 1
    
    # Reverse to get chronological order: root → ... → parent → event
    chain_reversed.reverse()
    
    return chain_reversed


def _is_root_process(image_path: str, known_roots: frozenset[str]) -> bool:
    """
    Check if an image path represents a known root process.
    
    Compares the image path against known root process names/paths.
    Both exact matches and basename matches are considered.
    
    Args:
        image_path: Path to the process executable.
        known_roots: Set of known root process identifiers.
    
    Returns:
        True if the image represents a root process.
    """
    # Exact match
    if image_path in known_roots:
        return True
    
    # Basename match (e.g., "/usr/lib/systemd/systemd" matches "systemd")
    basename = image_path.rsplit("/", 1)[-1] if "/" in image_path else image_path
    if basename in known_roots:
        return True
    
    return False


def enrich_anomalies_with_chains(
    anomalies: list[AnomalyResult],
    event_index: dict[str, "CanonicalEvent"],
    *,
    max_depth: int = MAX_CHAIN_DEPTH,
) -> dict[str, list[str]]:
    """
    Reconstruct chains for all detected anomalies.
    
    This is a convenience function that processes multiple anomalies
    and returns their chains in a lookup dictionary.
    
    Args:
        anomalies: List of AnomalyResult objects from detect_anomalies().
        event_index: Pre-built GUID → CanonicalEvent lookup index.
        max_depth: Maximum traversal depth for each chain.
    
    Returns:
        Dictionary mapping event subject.guid to its reconstructed chain.
        Each chain is ordered root → ... → event.
    
    Example:
        >>> anomalies = detect_anomalies(events, baseline)
        >>> index = build_event_index(all_events)
        >>> chains = enrich_anomalies_with_chains(anomalies, index)
        >>> for anomaly in anomalies:
        ...     chain = chains[anomaly.event.subject.guid]
        ...     print(f"Chain length: {len(chain)}")
    """
    chains: dict[str, list[str]] = {}
    
    for anomaly in anomalies:
        event_guid = anomaly.event.subject.guid
        chain = reconstruct_chain(
            anomaly.event,
            event_index,
            max_depth=max_depth,
        )
        chains[event_guid] = chain
    
    return chains


