"""
Rich terminal output for ReconAx.

The renderer intentionally works with generic dataclass-based results.
Individual modules can later provide richer specialized renderers
without changing the underlying analysis API.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


console = Console()


def _display_value(value: Any) -> str:
    """
    Convert a Python value into readable terminal text.
    """
    if value is None:
        return "—"

    if isinstance(value, bool):
        return "YES" if value else "NO"

    if isinstance(value, (list, tuple, set)):
        if not value:
            return "—"

        return "\n".join(
            f"• {item}"
            for item in value
        )

    if isinstance(value, dict):
        if not value:
            return "—"

        return "\n".join(
            f"{key}: {item}"
            for key, item in value.items()
        )

    return str(value)


def _result_name(result: Any) -> str:
    """
    Determine a human-readable title for an analysis result.
    """
    class_name = result.__class__.__name__

    if class_name.endswith("Analysis"):
        return class_name[:-8]

    if class_name.endswith("Report"):
        return class_name[:-6]

    return class_name


def _status_style(status: str) -> str:
    """
    Select a Rich style for a PASS/WARN/INFO verdict.
    """
    normalized = status.upper()

    if normalized == "PASS":
        return "green"

    if normalized == "WARN":
        return "yellow"

    if normalized == "FAIL":
        return "red"

    return "cyan"


def _render_dataclass_table(
    result: Any,
    *,
    title: str | None = None,
) -> Table:
    """
    Convert a dataclass result into a two-column Rich table.
    """
    table = Table(
        title=title or _result_name(result),
        show_header=True,
        header_style="bold",
        expand=True,
    )

    table.add_column(
        "Field",
        style="bold",
        no_wrap=True,
    )

    table.add_column(
        "Value",
        overflow="fold",
    )

    data = asdict(result)

    for key, value in data.items():
        if key in {
            "verdict",
            "flags",
            "explanations",
        }:
            continue

        field_name = key.replace("_", " ").title()

        table.add_row(
            field_name,
            _display_value(value),
        )

    return table


def render_result(
    result: Any,
    *,
    title: str | None = None,
    explain: bool = False,
    output: Console | None = None,
) -> None:
    """
    Render one ReconAx module result.

    If the result contains a verdict, it is displayed prominently.
    If explain=True and explanations exist, they are shown below the
    main result table.
    """
    target_console = output or console

    if result is None:
        target_console.print(
            "[yellow]No result available.[/yellow]"
        )
        return

    result_title = title or _result_name(result)

    if is_dataclass(result):
        table = _render_dataclass_table(
            result,
            title=result_title,
        )

        target_console.print(table)

        verdict = getattr(
            result,
            "verdict",
            None,
        )

        if verdict:
            verdict_text = str(verdict).upper()
            style = _status_style(verdict_text)

            target_console.print(
                Panel(
                    Text(
                        verdict_text,
                        style=f"bold {style}",
                    ),
                    title="Verdict",
                    border_style=style,
                )
            )

        flags = getattr(
            result,
            "flags",
            None,
        )

        if flags:
            target_console.print(
                Panel(
                    "\n".join(
                        f"• {flag}"
                        for flag in flags
                    ),
                    title="Findings",
                )
            )

        if explain:
            explanations = getattr(
                result,
                "explanations",
                None,
            )

            if explanations:
                target_console.print(
                    Panel(
                        "\n\n".join(
                            str(item)
                            for item in explanations
                        ),
                        title="Explanation",
                    )
                )

        return

    target_console.print(
        Panel(
            _display_value(result),
            title=result_title,
        )
    )


def render_report(
    report: Any,
    *,
    explain: bool = False,
    output: Console | None = None,
) -> None:
    """
    Render a complete ReconReport.

    The report is rendered section-by-section so the terminal remains
    readable even when many modules are present.
    """
    target_console = output or console

    target = getattr(
        report,
        "final_url",
        None,
    ) or getattr(
        report,
        "normalized_url",
        None,
    ) or getattr(
        report,
        "target",
        "Unknown target",
    )

    target_console.print()
    target_console.print(
        Panel(
            f"[bold]Target[/bold]\n{target}",
            title="⚡ ReconAx",
            border_style="cyan",
        )
    )

    section_order = [
        "http",
        "headers",
        "cookies",
        "html",
        "robots",
        "dns",
        "tls",
        "tech",
        "sitemap",
        "cors",
        "csp",
        "sri",
        "security_txt",
        "metadata",
        "resources",
        "endpoints",
        "attack_surface",
        "score",
    ]

    for section_name in section_order:
        result = getattr(
            report,
            section_name,
            None,
        )

        if result is None:
            continue

        title = section_name.replace(
            "_",
            " ",
        ).title()

        render_result(
            result,
            title=title,
            explain=explain,
            output=target_console,
        )

        target_console.print()

    score = getattr(
        report,
        "score",
        None,
    )

    if score is not None:
        numeric_score = getattr(
            score,
            "score",
            None,
        )

        if numeric_score is not None:
            target_console.print(
                Panel(
                    f"[bold]{numeric_score}/100[/bold]",
                    title="Website Hygiene Score",
                    border_style="cyan",
                )
            )