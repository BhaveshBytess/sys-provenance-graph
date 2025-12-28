"""
events.py - Canonical Event and Report Schemas

This module defines the Pydantic models for:
- Canonical Event Schema (input contract)
- Analysis Report Schema (output contract)

These schemas are the authoritative data contracts as defined in CONTRACTS.md.
All input telemetry MUST be normalized into CanonicalEvent before analysis.
All analysis results MUST conform to AnalysisReport before output.

See CONTRACTS.md for full schema specifications and invariants.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


# =============================================================================
# Enumerations
# =============================================================================


class EventType(str, Enum):
    """
    Supported event types for V1.
    
    Currently only PROCESS_CREATE (Sysmon Event ID 1) is supported.
    Other event types are explicitly out of scope for V1.
    """
    PROCESS_CREATE = "PROCESS_CREATE"


class ObjectType(str, Enum):
    """
    Types of objects that can be acted upon by a subject.
    
    In V1, the object may be another process, a file, a network endpoint,
    or null if not applicable.
    """
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    NULL = "null"


class RiskLevel(str, Enum):
    """
    Risk classification levels for anomalies.
    
    Used to categorize the severity of detected anomalies.
    """
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EntityRole(str, Enum):
    """
    Role of an entity in an anomaly chain.
    
    Indicates whether the entity is the parent (ancestor) or child (descendant)
    in the execution relationship.
    """
    PARENT = "parent"
    CHILD = "child"


# =============================================================================
# Input Contract Models (Canonical Event Schema)
# =============================================================================


class HostInfo(BaseModel, frozen=True):
    """
    Host identification information.
    
    Provides context about the system where the event originated.
    The boot_id scopes process identity to a system lifecycle.
    
    Attributes:
        hostname: The name of the host system.
        boot_id: Unique identifier for the current boot session (UUID).
    """
    hostname: str = Field(..., description="The name of the host system")
    boot_id: UUID = Field(..., description="Unique identifier for the current boot session")


class Subject(BaseModel, frozen=True):
    """
    The active entity performing an action.
    
    In V1, the subject is always a process. The GUID is the primary identifier
    for process identity - PIDs must never be used for identity as they can
    be reused across different processes.
    
    Attributes:
        type: Entity type, always "process" in V1.
        guid: Primary identifier for the process (unique within boot session).
        pid: Process ID (informational only, NOT for identity).
        image: Path to the executable image.
    """
    type: str = Field(default="process", description="Entity type, always 'process' in V1")
    guid: str = Field(..., description="Primary identifier for the process")
    pid: int = Field(..., description="Process ID (informational only)")
    image: str = Field(..., description="Path to the executable image")


class Parent(BaseModel, frozen=True):
    """
    The immediate causal predecessor of the subject.
    
    Parent relationships define execution lineage and are used to
    reconstruct causal execution chains.
    
    Attributes:
        guid: Primary identifier for the parent process.
        image: Path to the parent's executable image.
    """
    guid: str = Field(..., description="Primary identifier for the parent process")
    image: str = Field(..., description="Path to the parent's executable image")


class Object(BaseModel, frozen=True):
    """
    The target entity acted upon by the subject.
    
    In V1, this may be another process, a file, a network endpoint,
    or null if not applicable to the event type.
    
    Attributes:
        type: Type of the object (process, file, network, or null).
        guid: Identifier for the object (null if not applicable).
        path_or_address: File path or network address (null if not applicable).
    """
    type: ObjectType = Field(..., description="Type of the object")
    guid: Optional[str] = Field(default=None, description="Identifier for the object")
    path_or_address: Optional[str] = Field(
        default=None, 
        description="File path or network address"
    )


class EventMetadata(BaseModel, frozen=True):
    """
    Additional context about the event.
    
    Contains execution context that may be useful for analysis
    but is not part of the core identity or relationship data.
    
    Attributes:
        command_line: Full command line used to start the process.
        user: User account under which the process is running.
        cwd: Current working directory of the process.
    """
    command_line: str = Field(..., description="Full command line")
    user: str = Field(..., description="User account")
    cwd: str = Field(..., description="Current working directory")


class CanonicalEvent(BaseModel, frozen=True):
    """
    Normalized representation of a single system action.
    
    This is the canonical input schema as defined in CONTRACTS.md §3.1.
    All input telemetry MUST be normalized into this format before analysis.
    
    An event is semantic (e.g., "process created"), not raw (e.g., "syscall 59").
    
    Identity Rules (Non-Negotiable):
    - subject.guid is the PRIMARY identifier for a process
    - PIDs are informational only and must NEVER be used for identity
    - boot_id scopes process identity to a system lifecycle
    - Two events with same PID but different GUIDs are DIFFERENT processes
    
    Attributes:
        event_id: Unique identifier for this event (UUID v4).
        timestamp: When the event occurred (ISO-8601 format).
        host: Host identification information.
        event_type: Type of event (only PROCESS_CREATE in V1).
        subject: The process performing the action.
        parent: The parent process.
        object: The target entity (may be null).
        metadata: Additional execution context.
    """
    event_id: UUID = Field(..., description="Unique identifier for this event")
    timestamp: datetime = Field(..., description="When the event occurred")
    host: HostInfo = Field(..., description="Host identification")
    event_type: EventType = Field(..., description="Type of event")
    subject: Subject = Field(..., description="The process performing the action")
    parent: Parent = Field(..., description="The parent process")
    object: Object = Field(..., description="The target entity")
    metadata: EventMetadata = Field(..., description="Additional execution context")


# =============================================================================
# Output Contract Models (Analysis Report Schema)
# =============================================================================


class InvolvedEntity(BaseModel, frozen=True):
    """
    An entity involved in an anomaly.
    
    Provides identification and role information for processes
    that are part of an anomalous execution chain.
    
    Attributes:
        guid: Primary identifier for the process.
        image: Path to the executable image.
        role: Whether this entity is a parent or child in the relationship.
    """
    guid: str = Field(..., description="Primary identifier for the process")
    image: str = Field(..., description="Path to the executable image")
    role: EntityRole = Field(..., description="Role in the relationship")


class Anomaly(BaseModel, frozen=True):
    """
    A detected deviation from baseline behavior.
    
    An anomaly represents a process relationship or chain that violates
    the learned baseline of normal behavior. Every anomaly MUST include
    an explanation and reference at least one process chain.
    
    Attributes:
        id: Unique identifier for this anomaly.
        risk_level: Severity classification (LOW, MEDIUM, HIGH, CRITICAL).
        confidence: Confidence score for the detection (0.0 to 1.0).
        description: Human-readable explanation of why this is anomalous.
        chain: Ordered sequence of process GUIDs representing the execution path.
        involved_entities: Detailed information about processes in the chain.
    """
    id: str = Field(..., description="Unique identifier for this anomaly")
    risk_level: RiskLevel = Field(..., description="Severity classification")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    description: str = Field(..., description="Explanation of the anomaly")
    chain: list[str] = Field(
        ..., 
        min_length=1,
        description="Ordered sequence of process GUIDs"
    )
    involved_entities: list[InvolvedEntity] = Field(
        ..., 
        description="Processes involved in the anomaly"
    )


class ReportMetadata(BaseModel, frozen=True):
    """
    Metadata about the analysis run.
    
    Provides context about how the analysis was performed.
    
    Attributes:
        events_processed: Total number of events analyzed.
        model_version: Version of the analysis model/baseline used.
    """
    events_processed: int = Field(..., ge=0, description="Number of events analyzed")
    model_version: str = Field(..., description="Version of the analysis model")


class AnalysisReport(BaseModel, frozen=True):
    """
    Structured analysis report.
    
    This is the canonical output schema as defined in CONTRACTS.md §4.1.
    All analysis results MUST conform to this format.
    
    Output Guarantees:
    - Every anomaly MUST include an explanation
    - Every anomaly MUST reference at least one process chain
    - global_risk_score MUST be consistent with individual anomalies
    
    Attributes:
        analysis_id: Unique identifier for this analysis run (UUID v4).
        timestamp: When the analysis was performed (ISO-8601 format).
        global_risk_score: Overall risk score for the analyzed events (0-100).
        summary: Human-readable summary of findings.
        anomalies: List of detected anomalies.
        metadata: Information about the analysis run.
    """
    analysis_id: UUID = Field(..., description="Unique identifier for this analysis")
    timestamp: datetime = Field(..., description="When analysis was performed")
    global_risk_score: int = Field(
        ..., 
        ge=0, 
        le=100, 
        description="Overall risk score (0-100)"
    )
    summary: str = Field(..., description="Human-readable summary")
    anomalies: list[Anomaly] = Field(default_factory=list, description="Detected anomalies")
    metadata: ReportMetadata = Field(..., description="Analysis run metadata")
