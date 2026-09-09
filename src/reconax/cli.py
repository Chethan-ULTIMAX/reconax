from __future__ import annotations

import typer

from .core import ReconAx
from .formatters.json_out import print_json
from .formatters.rich_out import print_report


app = typer.Typer(
    name="reconax",
    help="A simple, developer-friendly website analyzer.",
    add_completion=False,
)


@app.command()
def main(
    url: str = typer.Argument(
        ...,
        help="Website URL to analyze.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Output the report as JSON.",
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Explain security-related headers.",
    ),
    no_dns: bool = typer.Option(
        False,
        "--no-dns",
        help="Skip DNS lookups.",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        min=1.0,
        help="HTTP timeout in seconds.",
    ),
    output: str | None = typer.Option(
        None,
        "-o",
        "--output",
        help="Write JSON output to a file.",
    ),
):
    """Analyze a website."""

    try:
        analyzer = ReconAx(
            url=url,
            timeout=timeout,
            enable_dns=not no_dns,
        )

        report = analyzer.analyze()

    except ValueError as exc:
        typer.secho(
            f"Error: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    except Exception as exc:
        typer.secho(
            f"Request failed: {exc}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)

    # -------------------------------------------------------------
    # JSON output
    # -------------------------------------------------------------

    if json_output or output:

        data = report.to_json(
            path=output,
        )

        if json_output:
            typer.echo(data)

        elif output:
            typer.secho(
                f"Report written to {output}",
                fg=typer.colors.GREEN,
            )

        return

    # -------------------------------------------------------------
    # Rich terminal output
    # -------------------------------------------------------------

    print_report(
        report,
        explain=explain,
    )


if __name__ == "__main__":
    app()