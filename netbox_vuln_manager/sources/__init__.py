from .crowdstrike import CrowdStrikeSource
from .securityscorecard import SecurityScorecardSource
from .csv_handler import CSVSource

SOURCE_REGISTRY = {
    "crowdstrike": CrowdStrikeSource,
    "securityscorecard": SecurityScorecardSource,
    "csv": CSVSource,
}


def get_source_handler(source_type: str):
    """Return the handler class for the given source type string."""
    handler = SOURCE_REGISTRY.get(source_type)
    if handler is None:
        raise ValueError(f"Unknown source type: {source_type!r}")
    return handler
