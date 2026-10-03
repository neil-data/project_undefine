"""Process entry point; workflow, parsing, and analysis are intentionally deferred."""

from static_analysis.bootstrap import create_engine


def main() -> None:
    """Assemble the foundation without invoking any analysis behavior."""
    create_engine()
