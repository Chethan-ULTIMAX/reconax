from __future__ import annotations

import json
from typing import Any


def format_json(data: Any) -> str:
    """Return report data as readable JSON."""
    if hasattr(data, "to_dict"):
        data = data.to_dict()
    return json.dumps(data, indent=2, ensure_ascii=False)
