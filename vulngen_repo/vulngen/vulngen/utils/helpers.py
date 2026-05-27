"""
vulngen/utils/helpers.py
-------------------------
Shared utility functions used across pipeline stages.

Author: Anuansh Tiwari <anuanshtiwari191@gmail.com>
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any


def timestamp() -> str:
    """Return a sortable timestamp string: YYYYMMDD_HHMMSS."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def save_json(path: Path, data: Any, indent: int = 2) -> None:
    """Serialise *data* to JSON at *path*, creating parent dirs as needed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, ensure_ascii=False, default=str)


def load_json(path: Path) -> Any:
    """Load JSON from *path*."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def chunk(lst: list, size: int) -> list:
    """Split *lst* into sublists of at most *size* elements."""
    return [lst[i : i + size] for i in range(0, len(lst), size)]


def retry(fn, retries: int = 5, backoff: float = 2.0):
    """Call *fn* with exponential back-off on exception."""
    for attempt in range(retries):
        try:
            return fn()
        except Exception as exc:
            if attempt == retries - 1:
                raise
            wait = backoff ** attempt
            time.sleep(wait)
