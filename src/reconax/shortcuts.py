"""
Convenience functions for ReconAx.

These functions provide a simple functional API around the ReconAx
class. Each function creates one analyzer, executes the requested
module, and closes the underlying HTTP client.
"""

from __future__ import annotations

from typing import Any

from .core import ReconAx


def _run(
    url: str,
    method: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
    **kwargs: Any,
) -> Any:
    """
    Execute one ReconAx method safely and close its resources.
    """
    recon = ReconAx(
        url,
        timeout=timeout,
        verify_ssl=verify_ssl,
    )

    try:
        return getattr(
            recon,
            method,
        )(**kwargs)
    finally:
        recon.close()


def analyze(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
    include_dns: bool = True,
):
    """Run the complete ReconAx analysis."""
    return _run(
        url,
        "analyze",
        timeout=timeout,
        verify_ssl=verify_ssl,
        include_dns=include_dns,
    )


def headers(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze HTTP security headers."""
    return _run(
        url,
        "headers",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def cookies(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze response cookies."""
    return _run(
        url,
        "cookies",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def html(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze returned HTML."""
    return _run(
        url,
        "html",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def robots(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze robots.txt."""
    return _run(
        url,
        "robots",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def dns(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze DNS records."""
    return _run(
        url,
        "dns",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def tls(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze TLS and the public certificate."""
    return _run(
        url,
        "tls",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def tech(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Perform passive technology detection."""
    return _run(
        url,
        "tech",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def sitemap(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze the public sitemap."""
    return _run(
        url,
        "sitemap",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def cors(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze CORS response configuration."""
    return _run(
        url,
        "cors",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def csp(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze Content-Security-Policy."""
    return _run(
        url,
        "csp",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def sri(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze Subresource Integrity usage."""
    return _run(
        url,
        "sri",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def security_txt(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze /.well-known/security.txt."""
    return _run(
        url,
        "security_txt",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def metadata(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze public HTML metadata."""
    return _run(
        url,
        "metadata",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def resources(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Analyze page resources."""
    return _run(
        url,
        "resources",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def endpoints(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Extract publicly observed endpoints."""
    return _run(
        url,
        "endpoints",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def attack_surface(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Build a passive attack-surface summary."""
    return _run(
        url,
        "attack_surface",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )


def score(
    url: str,
    *,
    timeout: float = 10.0,
    verify_ssl: bool = True,
):
    """Calculate the Website Hygiene Score."""
    return _run(
        url,
        "score",
        timeout=timeout,
        verify_ssl=verify_ssl,
    )