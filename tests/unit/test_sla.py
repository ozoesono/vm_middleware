"""Tests for SLA calculation and status determination."""

from datetime import date, datetime, timedelta

import pytest

from src.common.config import SLAConfig
from src.scoring.sla import calculate_sla_due_date, determine_sla_status


class TestSLACalculation:
    """Tests for SLA due date calculation."""

    def test_critical_sla(self):
        config = SLAConfig()
        first_seen = datetime(2026, 4, 1, 8, 0, 0)
        days, due = calculate_sla_due_date(first_seen, "CRITICAL", config)
        assert days == 10
        assert due == date(2026, 4, 11)

    def test_high_sla(self):
        config = SLAConfig()
        first_seen = datetime(2026, 4, 1, 8, 0, 0)
        days, due = calculate_sla_due_date(first_seen, "HIGH", config)
        assert days == 30
        assert due == date(2026, 5, 1)

    def test_medium_sla(self):
        config = SLAConfig()
        first_seen = datetime(2026, 4, 1, 8, 0, 0)
        days, due = calculate_sla_due_date(first_seen, "MEDIUM", config)
        assert days == 45

    def test_low_sla(self):
        config = SLAConfig()
        first_seen = datetime(2026, 4, 1, 8, 0, 0)
        days, due = calculate_sla_due_date(first_seen, "LOW", config)
        assert days == 90

    def test_none_first_seen(self):
        config = SLAConfig()
        days, due = calculate_sla_due_date(None, "HIGH", config)
        assert days == 30
        assert due is None

    def test_custom_sla_values(self):
        config = SLAConfig(critical=5, high=15, medium=30, low=60)
        first_seen = datetime(2026, 4, 1)
        days, due = calculate_sla_due_date(first_seen, "CRITICAL", config)
        assert days == 5
        assert due == date(2026, 4, 6)

    def test_unknown_rating_defaults_to_low(self):
        config = SLAConfig()
        first_seen = datetime(2026, 4, 1)
        days, due = calculate_sla_due_date(first_seen, "UNKNOWN", config)
        assert days == 90


class TestSLAStatus:
    """Tests for SLA status determination."""

    def test_within_sla(self):
        config = SLAConfig()
        due = date.today() + timedelta(days=20)
        assert determine_sla_status(due, config) == "WITHIN_SLA"

    def test_approaching_sla(self):
        config = SLAConfig(approaching_warning_days=5)
        due = date.today() + timedelta(days=3)
        assert determine_sla_status(due, config) == "APPROACHING"

    def test_breached_sla(self):
        config = SLAConfig()
        due = date.today() - timedelta(days=1)
        assert determine_sla_status(due, config) == "BREACHED"

    def test_due_today_is_approaching(self):
        config = SLAConfig(approaching_warning_days=5)
        due = date.today()
        assert determine_sla_status(due, config) == "APPROACHING"

    def test_none_due_date(self):
        config = SLAConfig()
        assert determine_sla_status(None, config) == "WITHIN_SLA"

    def test_exactly_at_warning_boundary(self):
        config = SLAConfig(approaching_warning_days=5)
        due = date.today() + timedelta(days=5)
        assert determine_sla_status(due, config) == "APPROACHING"

    def test_one_day_past_warning(self):
        config = SLAConfig(approaching_warning_days=5)
        due = date.today() + timedelta(days=6)
        assert determine_sla_status(due, config) == "WITHIN_SLA"

    def test_custom_reference_date(self):
        config = SLAConfig()
        due = date(2026, 5, 1)
        ref = date(2026, 5, 5)
        assert determine_sla_status(due, config, reference_date=ref) == "BREACHED"
