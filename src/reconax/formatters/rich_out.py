from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..models import ReconReport


def print_report(report: ReconReport, console: Console | None = None) -> None:
    console = console or Console()
    console.print(Panel.fit(f"[bold]ReconAx Report[/bold] — {report.final_url}"))

    table = Table(show_header=False)
    table.add_row("URL", report.final_url)
    table.add_row("Status", f"{report.status_code} {report.reason_phrase} · {report.elapsed_ms:.0f}ms")
    table.add_row("HTTP", report.http_version)
    table.add_row("Content-Type", report.content_type or "unknown")
    table.add_row("Title", report.html.title or "(none)")
    console.print(table)

    console.print("\n[bold]Security Headers[/bold]")
    for name in report.headers.present:
        console.print(f"  ✓ {name}")
    for name in report.headers.missing:
        console.print(f"  ✗ {name} (missing)")

    console.print(f"\nLinks: {report.html.internal_link_count} internal · {report.html.external_link_count} external")
    console.print(f"Scripts: {len(report.html.scripts)}   Images: {len(report.html.images)}")
    console.print(f"robots.txt: {'found' if report.robots.found else 'not found'}")
    console.print(f"DNS A: {', '.join(report.dns.A) if report.dns.A else 'none'}")
