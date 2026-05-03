"""INFRA — Infrastructure Intelligence Through Passive Observation."""

__version__ = "0.2.0"

import logging

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def setup_logging(log_path="infra.log", level=logging.INFO):
    """Configure logging to file + stdout. Call once at startup."""
    import sys
    from pathlib import Path

    root = logging.getLogger()
    if root.handlers:
        # Already configured (e.g. tests)
        return logging.getLogger("infra")

    root.setLevel(level)
    fmt = logging.Formatter(LOG_FORMAT)

    fh = logging.FileHandler(Path(log_path))
    fh.setFormatter(fmt)
    fh.setLevel(logging.DEBUG)  # Always debug to file
    root.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh.setLevel(level)
    root.addHandler(sh)

    # Tame noisy libs
    logging.getLogger("scapy").setLevel(logging.WARNING)

    return logging.getLogger("infra")
