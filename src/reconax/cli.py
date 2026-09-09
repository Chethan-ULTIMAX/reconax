from __future__ import annotations

import typer

from .core import ReconAx
from .formatters.json_out import format_json
from .formatters.rich_out import print_report

app = typer.Typer(name="reconax", help="A simple, developer-friendly website analyzer.")


@app.command()
def main(
    url: str,
    json_output: bool = typer.Option(False, "--json", help="Output the report as JSON."),
    timeout: float = typer.Option(10.0, "--timeout", min=1.0, help="HTTP/DNS timeout in seconds."),
    output: str | None = typer.Option(None, "-o", "--output", help="Write JSON output to a file."),
):
    """Analyze a website URL."""
    try:
        report = ReconAx(url, timeout=timeout).analyze()
    except Exception as exc:
        raise typer.BadParameter(str(exc)) from exc

    if json_output or output:
        data = format_json(report)
        if output:
            with open(output, "w", encoding="utf-8") as file:
                file.write(data)
        typer.echo(data)
    else:
        print_report(report)


if __name__ == "__main__":
    app()
