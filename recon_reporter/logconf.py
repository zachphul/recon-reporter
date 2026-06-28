"""Central logging setup. The CLI calls `setup()` once; library modules just use
`logging.getLogger(__name__)` so they stay quiet when imported as a library."""
from __future__ import annotations

import logging
import sys

_CONFIGURED = False


def setup(verbose: bool = False) -> None:
    """Configure root logging for CLI use. Idempotent."""
    global _CONFIGURED
    if _CONFIGURED:
        logging.getLogger().setLevel(logging.DEBUG if verbose else logging.INFO)
        return
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
