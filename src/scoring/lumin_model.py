"""Lumin CES scoring model — uses Tenable's native ACR/AES/VPR scores."""

from __future__ import annotations

from src.common.config import LuminScoringConfig
from src.scoring.types import ScoringResult


def score_lumin(
    config: LuminScoringConfig,
    acr: int | None = None,
    aes: int | None = None,
    vpr_score: float | None = None,
    severity: str | None = None,
) -> ScoringResult:
    """Calculate risk score using Tenable Lumin's CES approach.

    If AES (Asset Exposure Score, 0-1000) is available, use it directly
    as it represents Tenable's native CES = f(VPR, ACR).

    If AES is not available, approximate CES from VPR and ACR:
        approximate_ces = (vpr_normalised * 50) + (acr_normalised * 50)
        scaled to 0-1000 range.
    """
    if aes is not None and aes > 0:
        ces_score = aes
    else:
        # Approximate CES from VPR and ACR
        vpr_component = ((vpr_score or 2.0) / 10.0) * 500  # 0-500
        acr_component = ((acr or 5) / 10.0) * 500  # 0-500
        ces_score = int(vpr_component + acr_component)

    # Clamp to 0-1000
    ces_score = min(max(ces_score, 0), 1000)

    # Map to risk rating
    risk_rating = _ces_to_rating(ces_score, config.ces_thresholds)

    # Normalise score to 0.0-1.0 for consistency with custom model
    risk_score_normalised = round(ces_score / 1000.0, 4)

    return ScoringResult(
        risk_score=risk_score_normalised,
        risk_rating=risk_rating,
        risk_model="lumin_ces",
    )


def _ces_to_rating(ces_score: int, thresholds: dict[str, int]) -> str:
    """Map a CES score to a risk rating based on configurable thresholds."""
    if ces_score >= thresholds.get("critical", 800):
        return "CRITICAL"
    elif ces_score >= thresholds.get("high", 600):
        return "HIGH"
    elif ces_score >= thresholds.get("medium", 400):
        return "MEDIUM"
    else:
        return "LOW"
