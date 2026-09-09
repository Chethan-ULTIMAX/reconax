from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..models import ReconReport


console = Console()


SECURITY_HEADER_LABELS = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def _format_size(
    size: int | None,
) -> str:
    """Format a byte count into a readable value."""

    if size is None:
        return "unknown"

    if size < 1024:
        return f"{size} bytes"

    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"

    return f"{size / (1024 * 1024):.2f} MB"


def _format_value(
    values: list[str],
    empty: str = "none",
) -> str:
    """Format a list of values for terminal output."""

    if not values:
        return empty

    return ", ".join(values)


def _print_header_section(
    report: ReconReport,
) -> None:
    """Print security-related response headers."""

    table = Table(
        title="Security Headers",
        show_header=True,
        header_style="bold",
    )

    table.add_column(
        "Status",
        width=8,
    )

    table.add_column(
        "Header",
    )

    table.add_column(
        "Value",
        overflow="fold",
    )

    # Present headers.
    for name, value in report.headers.present.items():

        label = SECURITY_HEADER_LABELS.get(
            name.lower(),
            name,
        )

        table.add_row(
            "✓",
            label,
            value,
        )

    # Missing headers.
    for name in report.headers.missing:

        label = SECURITY_HEADER_LABELS.get(
            name.lower(),
            name,
        )

        table.add_row(
            "✗",
            label,
            "missing",
        )

    console.print(table)


def _print_cookie_section(
    report: ReconReport,
) -> None:
    """Print safe cookie information."""

    table = Table(
        title=f"Cookies ({len(report.cookies)})",
        show_header=True,
        header_style="bold",
    )

    table.add_column(
        "Name",
    )

    table.add_column(
        "Secure",
        width=8,
    )

    table.add_column(
        "HttpOnly",
        width=10,
    )

    table.add_column(
        "SameSite",
        width=12,
    )

    if not report.cookies:

        table.add_row(
            "None",
            "—",
            "—",
            "—",
        )

    else:

        for cookie in report.cookies:

            table.add_row(
                cookie.name,
                "yes" if cookie.secure else "no",
                "yes" if cookie.httponly else "no",
                cookie.samesite or "not set",
            )

    console.print(table)


def _print_html_section(
    report: ReconReport,
) -> None:
    """Print HTML analysis."""

    html = report.html

    table = Table(
        title="HTML",
        show_header=False,
        box=None,
    )

    table.add_column(
        "Property",
        style="bold",
        width=18,
    )

    table.add_column(
        "Value",
        overflow="fold",
    )

    table.add_row(
        "Title",
        html.title or "not found",
    )

    table.add_row(
        "Meta Description",
        html.meta_description or "not found",
    )

    table.add_row(
        "Links",
        (
            f"{len(html.internal_links)} internal · "
            f"{len(html.external_links)} external"
        ),
    )

    table.add_row(
        "Scripts",
        str(len(html.scripts)),
    )

    table.add_row(
        "Images",
        str(len(html.images)),
    )

    console.print(table)


def _print_robots_section(
    report: ReconReport,
) -> None:
    """Print robots.txt analysis."""

    robots = report.robots

    table = Table(
        title="robots.txt",
        show_header=False,
        box=None,
    )

    table.add_column(
        "Property",
        style="bold",
        width=18,
    )

    table.add_column(
        "Value",
    )

    table.add_row(
        "Found",
        "yes" if robots.found else "no",
    )

    table.add_row(
        "Disallow Rules",
        str(len(robots.disallow_rules)),
    )

    table.add_row(
        "Sitemaps",
        str(len(robots.sitemap_urls)),
    )

    console.print(table)

    if robots.disallow_rules:

        console.print(
            "  Disallow: "
            + ", ".join(
                robots.disallow_rules
            )
        )

    if robots.sitemap_urls:

        console.print(
            "  Sitemap: "
            + ", ".join(
                robots.sitemap_urls
            )
        )


def _print_dns_section(
    report: ReconReport,
) -> None:
    """Print DNS information."""

    dns = report.dns

    table = Table(
        title="DNS",
        show_header=False,
        box=None,
    )

    table.add_column(
        "Record",
        style="bold",
        width=10,
    )

    table.add_column(
        "Value",
        overflow="fold",
    )

    table.add_row(
        "A",
        _format_value(dns.a),
    )

    table.add_row(
        "AAAA",
        _format_value(dns.aaaa),
    )

    table.add_row(
        "MX",
        _format_value(dns.mx),
    )

    table.add_row(
        "NS",
        _format_value(dns.ns),
    )

    table.add_row(
        "TXT",
        _format_value(dns.txt),
    )

    console.print(table)


def _print_http_section(
    report: ReconReport,
) -> None:
    """Print HTTP response information."""

    table = Table(
        title="HTTP",
        show_header=False,
        box=None,
    )

    table.add_column(
        "Property",
        style="bold",
        width=18,
    )

    table.add_column(
        "Value",
        overflow="fold",
    )

    status = (
        f"{report.status_code} "
        f"{report.reason_phrase}"
    )

    table.add_row(
        "Status",
        status,
    )

    table.add_row(
        "Response Time",
        f"{report.elapsed_ms:.2f} ms",
    )

    table.add_row(
        "Requested URL",
        report.requested_url,
    )

    if report.final_url != report.requested_url:

        table.add_row(
            "Final URL",
            report.final_url,
        )

    else:

        table.add_row(
            "Final URL",
            report.final_url,
        )

    table.add_row(
        "HTTP Version",
        report.http_version,
    )

    table.add_row(
        "Content-Type",
        report.content_type or "unknown",
    )

    table.add_row(
        "Content Length",
        _format_size(
            report.content_length
        ),
    )

    console.print(table)


def _print_explanations(
    report: ReconReport,
) -> None:
    """
    Print short plain-English explanations of
    security-related headers.

    These explanations are informational and do not
    claim that a missing header represents a vulnerability.
    """

    explanations = {
        "strict-transport-security": (
            "HSTS tells browsers to prefer HTTPS for the site."
        ),
        "content-security-policy": (
            "CSP lets a site restrict which resources browsers may load."
        ),
        "x-content-type-options": (
            "This can prevent browsers from MIME-sniffing certain responses."
        ),
        "x-frame-options": (
            "This can control whether pages may be embedded in frames."
        ),
        "referrer-policy": (
            "This controls how much referrer information browsers send."
        ),
        "permissions-policy": (
            "This can restrict access to selected browser features."
        ),
    }

    table = Table(
        title="Header Explanations",
        show_header=True,
        header_style="bold",
    )

    table.add_column(
        "Header",
    )

    table.add_column(
        "Explanation",
        overflow="fold",
    )

    for name in report.headers.present:

        explanation = explanations.get(
            name.lower(),
            "Security-related HTTP response header.",
        )

        label = SECURITY_HEADER_LABELS.get(
            name.lower(),
            name,
        )

        table.add_row(
            label,
            explanation,
        )

    for name in report.headers.missing:

        explanation = explanations.get(
            name.lower(),
            "Security-related HTTP response header.",
        )

        label = SECURITY_HEADER_LABELS.get(
            name.lower(),
            name,
        )

        table.add_row(
            f"{label} (missing)",
            explanation,
        )

    console.print(table)


def print_report(
    report: ReconReport,
    explain: bool = False,
) -> None:
    """
    Render a complete ReconAx report in the terminal.
    """

    # ---------------------------------------------------------
    # Header
    # ---------------------------------------------------------

    title = Text(
        "ReconAx Report",
        style="bold",
    )

    console.print(
        Panel(
            title,
            subtitle=report.final_url,
            expand=False,
        )
    )

    # ---------------------------------------------------------
    # HTTP
    # ---------------------------------------------------------

    _print_http_section(report)

    console.print()

    # ---------------------------------------------------------
    # Security headers
    # ---------------------------------------------------------

    _print_header_section(report)

    console.print()

    # ---------------------------------------------------------
    # Cookies
    # ---------------------------------------------------------

    _print_cookie_section(report)

    console.print()

    # ---------------------------------------------------------
    # HTML
    # ---------------------------------------------------------

    _print_html_section(report)

    console.print()

    # ---------------------------------------------------------
    # robots.txt
    # ---------------------------------------------------------

    _print_robots_section(report)

    console.print()

    # ---------------------------------------------------------
    # DNS
    # ---------------------------------------------------------

    _print_dns_section(report)

    # ---------------------------------------------------------
    # Optional explanations
    # ---------------------------------------------------------

    if explain:

        console.print()

        _print_explanations(report)

    console.print()

    console.print(
        "[dim]ReconAx collects public website information "
        "with lightweight requests.[/dim]"
    )