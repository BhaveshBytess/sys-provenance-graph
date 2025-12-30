"""
analyzer.py - Core Analysis Engine

This module contains all system intelligence:
- Baseline construction (Phase 3)
- Anomaly detection (Phase 4) - NOT YET IMPLEMENTED
- Chain reconstruction (Phase 5) - NOT YET IMPLEMENTED
- Report assembly (Phase 6) - NOT YET IMPLEMENTED

See SPEC.md Section 4.2 for responsibilities.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.events import CanonicalEvent


# =============================================================================
# Constants
# =============================================================================

# Version string for baseline compatibility tracking
BASELINE_VERSION = "1.0.0"


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
