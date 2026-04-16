"""SLA calculation — due date and status determination."""

from __future__ import annotations

from datetime import date, datetime, timedelta

from src.common.config import SLAConfig


def calculate_sla_due_date(
    first_seen: datetime | None,
    risk_rating: str,
    sla_config: SLAConfig,
) -> tuple[int, date | None]:
    """Calculate SLA days and due date for a finding.

    Returns:
        Tuple of (sla_days, sla_due_date)
    """
    sla_days = sla_config.days_for_rating(risk_rating)

    if first_seen is None:
        return sla_days, None

    if isinstance(first_seen, datetime):
        start_date = first_seen.date()
    else:
        start_date = first_seen

    due_date = start_date + timedelta(days=sla_days)
    return sla_days, due_date


def determine_sla_status(
    sla_due_date: date | None,
    sla_config: SLAConfig,
    reference_date: date | None = None,
) -> str:
    """Determine SLA status based on due date.

    Returns: WITHIN_SLA / APPROACHING / BREACHED
    """
    if sla_due_date is None:
        return "WITHIN_SLA"

    today = reference_date or date.today()
    days_remaining = (sla_due_date - today).days

    if days_remaining < 0:
        return "BREACHED"
    elif days_remaining <= sla_config.approaching_warning_days:
        return "APPROACHING"
    else:
        return "WITHIN_SLA"
