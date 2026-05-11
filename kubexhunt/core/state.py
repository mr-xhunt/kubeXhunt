"""Mutable scan state."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanState:
    """Mutable shared state produced during a scan."""

    findings: list[Any] = field(default_factory=list)
    attack_graph: list[Any] = field(default_factory=list)
    token_scores: list[Any] = field(default_factory=list)
    current_phase: str = "0"
    optimal_paths: list[Any] = field(default_factory=list)
    identity_nodes: list[Any] = field(default_factory=list)
    identity_edges: list[Any] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
