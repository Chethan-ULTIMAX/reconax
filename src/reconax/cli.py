"""Command-line interface for ReconAx."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import typer

from .core import ReconAx
from .formatters.json_out import report_to_json, result_to_json
from .formatters.rich_out import render_report, render_result

app = typer.Typer(
    name="reconax",
    help="⚡ ReconAx - lightweight, developer-friendly website analyzer.",
    no_args_is_help=True,
    add_completion=True,
)


def _write_output(content: str, output_file: str | None) -> None:
    if output_file:
        Path(output_file).write_text(content, encoding="utf-8")
        typer.echo(f"Report written to {output_file}")
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
) -> None:
    recon = ReconAx(url, timeout=timeout)
    try:
        result = getattr(recon, method)()
        if as_json:
            _write_output(result_to_json(result), output_file)
        elif output_file:
            raise typer.BadParameter("Use --json with -o/--output.")
        else:
            render_result(result, explain=explain)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"ReconAx error: {exc}", err=True)
        raise typer.Exit(code=1)
    finally:
        recon.close()


def _module_command(
    url: str,
    method: str,
    explain: bool,
    json_output: bool,
    timeout: float,
) -> None:
    _run_module(
        url,
        method,
        explain=explain,
        as_json=json_output,
        timeout=timeout,
    )


@app.command("analyze")
def analyze_command(
    url: str = typer.Argument(..., help="Target HTTP/HTTPS URL."),
    json_output: bool = typer.Option(False, "--json", help="Output JSON."),
    explain: bool = typer.Option(False, "--explain", help="Show explanations."),
    no_dns: bool = typer.Option(False, "--no-dns", help="Skip DNS analysis."),
    timeout: float = typer.Option(10.0, "--timeout", min=0.1),
    output: str | None = typer.Option(None, "-o", "--output", help="Write JSON to a file."),
) -> None:
    recon = ReconAx(url, timeout=timeout)
    try:
        report = recon.analyze(include_dns=not no_dns)
        if json_output:
            _write_output(report_to_json(report), output)
        elif output:
            raise typer.BadParameter("Use --json with -o/--output.")
        else:
            render_report(report, explain=explain)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"ReconAx error: {exc}", err=True)
        raise typer.Exit(code=1)
    finally:
        recon.close()


def _standard_options():
    return


@app.command("headers")
def headers_command(
    url: str = typer.Argument(...),
    explain: bool = typer.Option(False, "--explain"),
    json_output: bool = typer.Option(False, "--json"),
    timeout: float = typer.Option(10.0, "--timeout", min=0.1),
) -> None:
    _module_command(url, "headers", explain, json_output, timeout)


@app.command("cookies")
def cookies_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "cookies", explain, json_output, timeout)


@app.command("html")
def html_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "html", explain, json_output, timeout)


@app.command("robots")
def robots_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "robots", explain, json_output, timeout)


@app.command("dns")
def dns_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "dns", explain, json_output, timeout)


@app.command("tls")
def tls_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "tls", explain, json_output, timeout)


@app.command("sitemap")
def sitemap_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "sitemap", explain, json_output, timeout)


@app.command("tech")
def tech_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "tech", explain, json_output, timeout)


@app.command("cors")
def cors_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "cors", explain, json_output, timeout)


@app.command("csp")
def csp_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "csp", explain, json_output, timeout)


@app.command("sri")
def sri_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "sri", explain, json_output, timeout)


@app.command("security-txt")
def security_txt_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "security_txt", explain, json_output, timeout)


@app.command("metadata")
def metadata_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "metadata", explain, json_output, timeout)


@app.command("resources")
def resources_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "resources", explain, json_output, timeout)


@app.command("endpoints")
def endpoints_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "endpoints", explain, json_output, timeout)


@app.command("attack-surface")
def attack_surface_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "attack_surface", explain, json_output, timeout)


@app.command("score")
def score_command(url: str = typer.Argument(...), explain: bool = typer.Option(False, "--explain"), json_output: bool = typer.Option(False, "--json"), timeout: float = typer.Option(10.0, "--timeout", min=0.1)) -> None:
    _module_command(url, "score", explain, json_output, timeout)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
