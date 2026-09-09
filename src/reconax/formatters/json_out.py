from __future__ import annotations

import json
from typing import Any

from ..models import ReconReport


def report_to_dict(
    report: ReconReport,
) -> dict[str, Any]:
    """
    Convert a ReconReport into a dictionary.

    This is useful for applications that want to
    process ReconAx results programmatically.
    """

    return report.to_dict()


def report_to_json(
    report: ReconReport,
    indent: int = 2,
) -> str:
    """
    Convert a ReconReport into a JSON string.
    """

    return json.dumps(
        report_to_dict(report),
        indent=indent,
        ensure_ascii=False,
    )


def save_json(
    report: ReconReport,
    path: str,
    indent: int = 2,
) -> None:
    """
    Save a ReconReport as a JSON file.
    """

    data = report_to_json(
        report,
        indent=indent,
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(data)


def print_json(
    report: ReconReport,
) -> None:
    """
    Print a ReconReport as JSON to stdout.
    """

    print(
        report_to_json(report)
    )