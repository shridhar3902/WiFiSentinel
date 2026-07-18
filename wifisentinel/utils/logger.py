"""
utils/logger.py

Centralized, colorized logging setup used across all WiFiSentinel modules.
"""

import logging
import os
import sys

LOG_LEVEL = os.environ.get("WIFISENTINEL_LOG_LEVEL", "INFO").upper()

_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"

_configured = False


def _configure_root() -> None:
    global _configured
    if _configured:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
    root = logging.getLogger("wifisentinel")
    root.setLevel(LOG_LEVEL)
    root.addHandler(handler)
    root.propagate = False
    _configured = True


def get_logger(name: str) -> logging.Logger:
    _configure_root()
    return logging.getLogger(name)
