from __future__ import annotations

import logging
import sys


def setup_logging(verbosity: int = 0) -> None:
    level = logging.WARNING if verbosity <= 0 else logging.INFO if verbosity == 1 else logging.DEBUG
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("certin_bom")
    root.handlers[:] = [handler]
    root.setLevel(level)
