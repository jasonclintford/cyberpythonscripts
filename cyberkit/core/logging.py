from __future__ import annotations

import logging

_FORMAT = "%(asctime)s %(levelname)s %(name)s - %(message)s"


def get_logger(name: str = "cyberkit") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(_FORMAT))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
