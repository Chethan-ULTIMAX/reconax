"""
Output formatters for ReconAx.

Formatters convert structured ReconAx results into human-friendly
terminal output or machine-readable JSON.
"""

from .json_out import (
    report_to_dict,
    report_to_json,
    result_to_dict,
    result_to_json,
)

from .rich_out import (
    render_report,
    render_result,
)

__all__ = [
    "report_to_dict",
    "report_to_json",
    "result_to_dict",
    "result_to_json",
    "render_report",
    "render_result",
]