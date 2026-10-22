"""Shared types for the scoring module."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScoringResult:
    """Result of scoring a single finding."""

    risk_score: float
    risk_rating: str
    risk_model: str
