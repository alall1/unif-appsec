from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


InsertionLocation = Literal["query", "path", "header", "form"]


@dataclass(frozen=True)
class InsertionPoint:
    name: str
    location: InsertionLocation


@dataclass
class DiscoveredEndpoint:
    method: str
    url: str
    insertion_points: list[InsertionPoint] = field(default_factory=list)
    source: str = "unknown"
