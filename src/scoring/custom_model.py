"""Custom risk scoring model: risk_score = (VPR * weight) + (ACS * weight)."""

from __future__ import annotations

from src.common.config import CustomScoringConfig
from src.scoring.types import ScoringResult

# Fallback VPR scores when VPR is not available, based on severity string
SEVERITY_TO_VPR_FALLBACK = {
    "Critical": 9.0,
    "High": 7.0,
    "Medium": 5.0,
    "Low": 2.0,
    "Info": 0.5,
}

DEFAULT_ACS = 0.25  # Default asset criticality score if not enriched


def score_custom(
    config: CustomScoringConfig,
    vpr_score: float | None,
    asset_criticality_score: float | None,
    severity: str | None = None,
) -> ScoringResult:
    """Calculate risk score using the custom weighted formula.

    Formula: risk_score = (vpr_normalised * vpr_weight) + (acs * acs_weight)

    VPR is normalised from 0-10 to 0-1.0 scale.
    ACS is already on 0.25-1.0 scale.
    """
    # Resolve VPR: use provided score, or fall back to severity mapping
    if vpr_score is not None and vpr_score > 0:
        vpr = vpr_score
    elif severity:
        vpr = SEVERITY_TO_VPR_FALLBACK.get(severity, SEVERITY_TO_VPR_FALLBACK.get(severity.capitalize(), 2.0))
    else:
        vpr = 2.0  # Default to Low-equivalent

    # Normalise VPR to 0.0 - 1.0
    vpr_normalised = min(max(vpr / 10.0, 0.0), 1.0)

    # Resolve ACS
    acs = asset_criticality_score if asset_criticality_score is not None else DEFAULT_ACS

    # Calculate weighted score
    risk_score = (vpr_normalised * config.vpr_weight) + (acs * config.acs_weight)

    # Clamp to 0.0 - 1.0
    risk_score = min(max(risk_score, 0.0), 1.0)

    # Determine risk rating from thresholds
    risk_rating = _score_to_rating(risk_score, config.thresholds)

    return ScoringResult(
        risk_score=round(risk_score, 4),
        risk_rating=risk_rating,
        risk_model="custom",
    )


def _score_to_rating(score: float, thresholds: dict[str, float]) -> str:
    """Map a numeric score to a risk rating based on configurable thresholds."""
    if score >= thresholds.get("critical", 0.75):
        return "CRITICAL"
    elif score >= thresholds.get("high", 0.50):
        return "HIGH"
    elif score >= thresholds.get("medium", 0.30):
        return "MEDIUM"
    else:
        return "LOW"
