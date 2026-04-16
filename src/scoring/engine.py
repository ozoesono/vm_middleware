"""Scoring engine — dispatches to the active scoring model."""

from __future__ import annotations

from src.common.config import ScoringConfig
from src.scoring.custom_model import score_custom
from src.scoring.lumin_model import score_lumin
from src.scoring.types import ScoringResult


def score_finding(
    config: ScoringConfig,
    vpr_score: float | None,
    asset_criticality_score: float | None,
    acr: int | None = None,
    aes: int | None = None,
    severity: str | None = None,
) -> ScoringResult:
    """Score a single finding using the active model.

    Args:
        config: Scoring configuration
        vpr_score: Tenable VPR score (0.1 - 10.0)
        asset_criticality_score: Normalised asset criticality (0.25 - 1.0)
        acr: Tenable ACR (1-10), used by Lumin model
        aes: Tenable AES (0-1000), used by Lumin model
        severity: Tenable severity string, fallback if VPR unavailable
    """
    if config.active_model == "lumin_ces":
        return score_lumin(
            config=config.lumin,
            acr=acr,
            aes=aes,
            vpr_score=vpr_score,
            severity=severity,
        )
    else:
        return score_custom(
            config=config.custom,
            vpr_score=vpr_score,
            asset_criticality_score=asset_criticality_score,
            severity=severity,
        )
