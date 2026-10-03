"""Generic validation helpers for future adapters and analyzers."""


def require_non_empty(value: str, field_name: str) -> str:
    """Return a non-blank string or raise a clear argument error."""
    if not value or not value.strip():
        raise ValueError(f"{field_name} cannot be empty")
    return value
