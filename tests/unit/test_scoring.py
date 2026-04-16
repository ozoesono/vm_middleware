"""Tests for the scoring engine — both custom and Lumin models."""

import pytest

from src.common.config import CustomScoringConfig, LuminScoringConfig, ScoringConfig
from src.scoring.custom_model import score_custom
from src.scoring.engine import score_finding
from src.scoring.types import ScoringResult
from src.scoring.lumin_model import score_lumin


class TestCustomModel:
    """Tests for the custom VPR + ACS scoring model."""

    def test_critical_score(self):
        """High VPR + Critical asset = CRITICAL rating."""
        config = CustomScoringConfig()
        result = score_custom(config, vpr_score=9.8, asset_criticality_score=1.0)
        assert result.risk_rating == "CRITICAL"
        assert result.risk_score >= 0.75
        assert result.risk_model == "custom"

    def test_high_score(self):
        """High VPR + Medium asset = HIGH rating."""
        config = CustomScoringConfig()
        result = score_custom(config, vpr_score=7.0, asset_criticality_score=0.5)
        assert result.risk_rating == "HIGH"
        assert 0.50 <= result.risk_score < 0.75

    def test_medium_score(self):
        """Medium VPR + Low asset = MEDIUM rating."""
        config = CustomScoringConfig()
        result = score_custom(config, vpr_score=5.0, asset_criticality_score=0.25)
        assert result.risk_rating == "MEDIUM"
        assert 0.30 <= result.risk_score < 0.50

    def test_low_score(self):
        """Low VPR + Low asset = LOW rating."""
        config = CustomScoringConfig()
        result = score_custom(config, vpr_score=2.0, asset_criticality_score=0.25)
        assert result.risk_rating == "LOW"
        assert result.risk_score < 0.30

    def test_vpr_none_falls_back_to_severity(self):
        """When VPR is None, use severity-based fallback."""
        config = CustomScoringConfig()
        result = score_custom(config, vpr_score=None, asset_criticality_score=1.0, severity="Critical")
        # Fallback VPR for Critical = 9.0, so (0.9*0.5) + (1.0*0.5) = 0.95
        assert result.risk_rating == "CRITICAL"

    def test_vpr_none_severity_none_defaults_low(self):
        """When both VPR and severity are None, default to low VPR."""
        config = CustomScoringConfig()
        result = score_custom(config, vpr_score=None, asset_criticality_score=0.25, severity=None)
        assert result.risk_rating == "LOW"

    def test_custom_weights(self):
        """Custom weights are applied correctly."""
        config = CustomScoringConfig(vpr_weight=0.80, acs_weight=0.20)
        result = score_custom(config, vpr_score=9.0, asset_criticality_score=0.25)
        # (0.9*0.8) + (0.25*0.2) = 0.72 + 0.05 = 0.77
        assert result.risk_score == pytest.approx(0.77, abs=0.01)
        assert result.risk_rating == "CRITICAL"

    def test_score_clamped_to_1(self):
        """Score should never exceed 1.0."""
        config = CustomScoringConfig(vpr_weight=0.70, acs_weight=0.70)
        result = score_custom(config, vpr_score=10.0, asset_criticality_score=1.0)
        assert result.risk_score <= 1.0

    def test_custom_thresholds(self):
        """Custom thresholds change the rating boundaries."""
        config = CustomScoringConfig(
            thresholds={"critical": 0.90, "high": 0.70, "medium": 0.40}
        )
        result = score_custom(config, vpr_score=7.0, asset_criticality_score=0.75)
        # (0.7*0.5) + (0.75*0.5) = 0.35 + 0.375 = 0.725
        assert result.risk_rating == "HIGH"


class TestLuminModel:
    """Tests for the Lumin CES scoring model."""

    def test_aes_based_critical(self):
        """High AES score = CRITICAL."""
        config = LuminScoringConfig()
        result = score_lumin(config, aes=850)
        assert result.risk_rating == "CRITICAL"
        assert result.risk_model == "lumin_ces"

    def test_aes_based_high(self):
        """Mid-high AES = HIGH."""
        config = LuminScoringConfig()
        result = score_lumin(config, aes=650)
        assert result.risk_rating == "HIGH"

    def test_aes_based_medium(self):
        """Mid AES = MEDIUM."""
        config = LuminScoringConfig()
        result = score_lumin(config, aes=450)
        assert result.risk_rating == "MEDIUM"

    def test_aes_based_low(self):
        """Low AES = LOW."""
        config = LuminScoringConfig()
        result = score_lumin(config, aes=200)
        assert result.risk_rating == "LOW"

    def test_no_aes_approximates_from_vpr_acr(self):
        """When AES is None, approximate from VPR and ACR."""
        config = LuminScoringConfig()
        result = score_lumin(config, aes=None, vpr_score=9.0, acr=9)
        # (9/10)*500 + (9/10)*500 = 450 + 450 = 900
        assert result.risk_rating == "CRITICAL"

    def test_custom_thresholds(self):
        """Custom CES thresholds change rating boundaries."""
        config = LuminScoringConfig(ces_thresholds={"critical": 900, "high": 700, "medium": 500})
        result = score_lumin(config, aes=750)
        assert result.risk_rating == "HIGH"


class TestScoringEngine:
    """Tests for the scoring engine dispatcher."""

    def test_dispatches_to_custom(self):
        """Engine uses custom model when configured."""
        config = ScoringConfig(active_model="custom")
        result = score_finding(config, vpr_score=8.0, asset_criticality_score=0.75)
        assert result.risk_model == "custom"

    def test_dispatches_to_lumin(self):
        """Engine uses Lumin model when configured."""
        config = ScoringConfig(active_model="lumin_ces")
        result = score_finding(config, vpr_score=8.0, asset_criticality_score=0.75, aes=700)
        assert result.risk_model == "lumin_ces"
