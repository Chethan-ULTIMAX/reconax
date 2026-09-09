"""JSON output formatter for ReconAx."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any


def _serialize(value: Any) -> Any:
    """Recursively convert ReconAx objects into JSON-compatible values."""
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _serialize(value.to_dict())

    if is_dataclass(value):
        return {
            key: _serialize(item)
            for key, item in asdict(value).items()
        }

    if isinstance(value, dict):
        return {str(key): _serialize(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_serialize(item) for item in value]

    if hasattr(value, "value"):
        try:
            return value.value
        except Exception:
            pass

    return value


def result_to_dict(result: Any) -> dict[str, Any]:
    serialized = _serialize(result)
    return serialized if isinstance(serialized, dict) else {"result": serialized}


def result_to_json(result: Any, *, indent: int = 2) -> str:
    return json.dumps(
        result_to_dict(result),
        indent=indent,
        ensure_ascii=False,
        sort_keys=False,
        default=str,
    )


def report_to_dict(report: Any) -> dict[str, Any]:
    return result_to_dict(report)


def report_to_json(report: Any, *, indent: int = 2) -> str:
    return json.dumps(
        report_to_dict(report),
        indent=indent,
        ensure_ascii=False,
        sort_keys=False,
        default=str,
    )


def write_json(data: Any, filename: str, *, indent: int = 2) -> None:
    payload = _serialize(data)
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=indent, ensure_ascii=False, default=str)
        file.write("\n")
