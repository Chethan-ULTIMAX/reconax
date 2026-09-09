"""
ReconAx command-line interface.

The CLI exposes individual analysis modules as subcommands while
retaining the simple `reconax example.com` behavior as an alias for
`reconax analyze example.com`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from .core import ReconAx
from .formatters.json_out import report_to_json, result_to_json
from .formatters.rich_out import render_report, render_result


app = typer.Typer(
    name="reconax",
    help=(
        "⚡ ReconAx - lightweight, developer-friendly "
        "website analyzer."
    ),
    no_args_is_help=True,
    add_completion=True,
)


def _write_output(
    content: str,
    output_file: str | None,
) -> None:
    """Print content or write it to a file."""
    if output_file:
        Path(output_file).write_text(
            content,
            encoding="utf-8",
        )

        typer.echo(
            f"Report written to {output_file}"
        )
    else:
        typer.echo(content)


def _run_module(
    url: str,
    method: str,
    *,
    as_json: bool = False,
    explain: bool = False,
    output_file: str | None = None,
    timeout: float = 10.0,
    verify_ssl: bool = True,
    **kwargs: Any,
) -> None:
    """Run one module through the public ReconAx class."""
    recon = ReconAx(
        url,
        timeout=timeout,
        verify_ssl=verify_ssl,
    )

    try:
        result = getattr(
            recon,
            method,
        )(**kwargs)

        if as_json:
            content = result_to_json(result)

            _write_output(
                content,
                output_file,
            )

        elif output_file:
            typer.echo(
                "Output files are supported for JSON output. "
                "Use --json with -o."
            )

        else:
            render_result(
                result,
                explain=explain,
            )

    except ValueError as exc:
        typer.echo(
            f"Error: {exc}",
            err=True,
        )
        raise typer.Exit(
            code=1
        )

    except Exception as exc:
        typer.echo(
            f"ReconAx error: {exc}",
            err=True,
        )
        raise typer.Exit(
            code=1
        )

    finally:
        recon.close()


@app.command(
    "analyze",
)
def analyze_command(
    url: str = typer.Argument(
        ...,
        help="Target HTTP/HTTPS URL.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output machine-readable JSON.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Show explanations for findings.",
    ),
    no_dns: bool = typer.Option(
        False,
        "--no-dns",
        help="Skip DNS analysis.",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        min=0.1,
        help="HTTP/DNS timeout in seconds.",
    ),
    output: str | None = typer.Option(
        None,
        "-o",
        "--output",
        help="Write JSON output to a file.",
    ),
) -> None:
    """Run the complete website analysis."""
    recon = ReconAx(
        url,
        timeout=timeout,
    )

    try:
        report = recon.analyze(
            include_dns=not no_dns,
        )

        if json_output:
            content = report_to_json(
                report
            )

            _write_output(
                content,
                output,
            )

        elif output:
            typer.echo(
                "Output files are supported for JSON output. "
                "Use --json with -o."
            )

        else:
            render_report(
                report,
                explain=explain,
            )

    except ValueError as exc:
        typer.echo(
            f"Error: {exc}",
            err=True,
        )
        raise typer.Exit(
            code=1
        )

    except Exception as exc:
        typer.echo(
            f"ReconAx error: {exc}",
            err=True,
        )
        raise typer.Exit(
            code=1
        )

    finally:
        recon.close()


@app.command("headers")
def headers_command(
    url: str = typer.Argument(...),
    explain: bool = typer.Option(
        False,
        "--explain",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        min=0.1,
    ),
) -> None:
    """Analyze security headers."""
    _run_module(
        url,
        "headers",
        explain=explain,
        as_json=json_output,
        timeout=timeout,
    )


@app.command("cookies")
def cookies_command(
    url: str = typer.Argument(...),
    explain: bool = typer.Option(
        False,
        "--explain",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        min=0.1,
    ),
) -> None:
    """Analyze cookies."""
    _run_module(
        url,
        "cookies",
        explain=explain,
        as_json=json_output,
        timeout=timeout,
    )


@app.command("html")
def html_command(
    url: str = typer.Argument(...),
    explain: bool = typer.Option(
        False,
        "--explain",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        min=0.1,
    ),
) -> None:
    """Analyze returned HTML."""
    _run_module(
        url,
        "html",
        explain=explain,
        as_json=json_output,
        timeout=timeout,
    )


@app.command("robots")
def robots_command(
    url: str = typer.Argument(...),
    explain: bool = typer.Option(
        False,
        "--explain",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        min=0.1,
    ),
) -> None:
    """Analyze robots.txt."""
    _run_module(
        url,
        "robots",
        explain=explain,
        as_json=json_output,
        timeout=timeout,
    )


@app.command("dns")
def dns_command(
    url: str = typer.Argument(...),
    explain: bool = typer.Option(
        False,
        "--explain",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        min=0.1,
    ),
) -> None:
    """Analyze DNS records."""
    _run_module(
        url,
        "dns",
        explain=explain,
        as_json=json_output,
        timeout=timeout,
    )


def main() -> None:
    """
    Compatibility entry point.

    Typer normally invokes `app` directly through pyproject.toml.
    """
    app()


if __name__ == "__main__":
    main()