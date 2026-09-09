"""
JSON output formatter for ReconAx.

ReconAx models are dataclasses, so structured results can be converted
to dictionaries and JSON without requiring every module to implement
its own serialization code.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any


def _serialize(value: Any) -> Any:
    """
    Recursively convert ReconAx objects into JSON-compatible values.
    """
    if is_dataclass(value):
        return {
            key: _serialize(item)
            for key, item in asdict(value).items()
        }

    if isinstance(value, dict):
        return {
            str(key): _serialize(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [_serialize(item) for item in value]

    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _serialize(value.to_dict())

    if hasattr(value, "value"):
        try:
            return value.value
        except Exception:
            pass

    return value


def result_to_dict(result: Any) -> dict[str, Any]:
    """
    Convert one analysis result to a dictionary.

    Parameters
    ----------
    result:
        A ReconAx dataclass or another object exposing to_dict().
    """
    serialized = _serialize(result)

    if isinstance(serialized, dict):
        return serialized

    return {"result": serialized}


def result_to_json(
    result: Any,
    *,
    indent: int = 2,
) -> str:
    """
    Convert one analysis result to formatted JSON.
    """
    return json.dumps(
        result_to_dict(result),
        indent=indent,
        ensure_ascii=False,
        sort_keys=False,
        default=str,
    )


def report_to_dict(report: Any) -> dict[str, Any]:
    """
    Convert a complete ReconReport into a dictionary.
    """
    return result_to_dict(report)


def report_to_json(
    report: Any,
    *,
    indent: int = 2,
) -> str:
    """
    Convert a complete ReconReport into formatted JSON.
    """
    return json.dumps(
        report_to_dict(report),
        indent=indent,
        ensure_ascii=False,
        sort_keys=False,
        default=str,
    )


def write_json(
    data: Any,
    filename: str,
    *,
    indent: int = 2,
) -> None:
    """
    Write structured ReconAx data to a JSON file.
    """
    payload = _serialize(data)

    with open(
        filename,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            payload,
            file,
            indent=indent,
            ensure_ascii=False,
            default=str,
        )
        file.write("\n")