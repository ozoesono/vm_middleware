"""Ordered service membership, shared by routing and reporting."""

from sqlalchemy import and_, func, literal, not_, or_, select


def unique_names(values):
    """Deduplicate case-insensitively, retaining first-seen order and spelling."""
    if isinstance(values, str):
        values = [values]
    result = {}
    for value in values or []:
        if isinstance(value, str) and value.strip():
            name = value.strip()
            result.setdefault(name.casefold(), name)
    return list(result.values())


def services_for(finding):
    return unique_names(getattr(finding, "services", None) or getattr(finding, "service", None))


def membership_sql(model, array_name, scalar_name, predicate, dialect):
    """Match any JSON member, with a fallback for legacy scalar records.

    EXISTS keeps report counts independent of the number of matching services.
    """
    array = getattr(model, array_name)
    if dialect == "postgresql":
        elements = func.json_array_elements_text(array).table_valued("value").render_derived()
    elif dialect == "sqlite":
        elements = func.json_each(array).table_valued("value")
    else:
        raise ValueError("Service membership queries require PostgreSQL or SQLite")
    has_members = func.coalesce(func.json_array_length(array), 0) > 0
    matches = (select(literal(1)).select_from(elements)
               .where(predicate(elements.c.value)).correlate(model).exists())
    return or_(matches, and_(not_(has_members), predicate(getattr(model, scalar_name))))
