from __future__ import annotations

import httpx
import respx

from reconax.http_client import HTTPClient
from reconax.parsers.cookies import parse_cookies
from reconax.parsers.dns_lookup import lookup_dns
from reconax.parsers.headers import analyze_headers
from reconax.parsers.html_parser import parse_html
from reconax.parsers.robots import fetch_robots


# =========================================================
# HTML PARSER
# =========================================================


def test_parse_html_extracts_title():

    html = """
    <html>
        <head>
            <title>ReconAx Test</title>
        </head>
        <body>
        </body>
    </html>
    """

    result = parse_html(
        html,
        "https://example.com",
    )

    assert result.title == "ReconAx Test"


def test_parse_html_extracts_meta_description():

    html = """
    <html>
        <head>
            <meta
                name="description"
                content="Test website"
            >
        </head>
    </html>
    """

    result = parse_html(
        html,
        "https://example.com",
    )

    assert result.meta_description == (
        "Test website"
    )


def test_parse_html_extracts_internal_and_external_links():

    html = """
    <html>
        <body>
            <a href="/about">About</a>
            <a href="https://example.com/contact">
                Contact
            </a>
            <a href="https://google.com">
                Google
            </a>
        </body>
    </html>
    """

    result = parse_html(
        html,
        "https://example.com",
    )

    assert len(result.links) == 3

    assert len(result.internal_links) == 2

    assert len(result.external_links) == 1

    assert (
        "https://example.com/about"
        in result.internal_links
    )

    assert (
        "https://google.com/"
        in result.external_links
    )


def test_parse_html_ignores_non_http_links():

    html = """
    <html>
        <body>
            <a href="#section">Section</a>
            <a href="mailto:test@example.com">
                Email
            </a>
            <a href="javascript:void(0)">
                JavaScript
            </a>
            <a href="/real">Real</a>
        </body>
    </html>
    """

    result = parse_html(
        html,
        "https://example.com",
    )

    assert len(result.links) == 1

    assert (
        result.links[0]
        == "https://example.com/real"
    )


def test_parse_html_extracts_scripts():

    html = """
    <html>
        <body>
            <script src="/static/app.js"></script>
            <script src="https://cdn.example.com/lib.js">
            </script>
        </body>
    </html>
    """

    result = parse_html(
        html,
        "https://example.com",
    )

    assert len(result.scripts) == 2

    assert (
        "https://example.com/static/app.js"
        in result.scripts
    )


def test_parse_html_extracts_images():

    html = """
    <html>
        <body>
            <img src="/images/logo.png">
            <img src="https://cdn.example.com/photo.jpg">
        </body>
    </html>
    """

    result = parse_html(
        html,
        "https://example.com",
    )

    assert len(result.images) == 2

    assert (
        "https://example.com/images/logo.png"
        in result.images
    )


def test_parse_html_removes_duplicate_links():

    html = """
    <html>
        <body>
            <a href="/about">About</a>
            <a href="/about">About again</a>
            <a href="/about">About again</a>
        </body>
    </html>
    """

    result = parse_html(
        html,
        "https://example.com",
    )

    assert len(result.links) == 1


# =========================================================
# HEADER PARSER
# =========================================================


def test_analyze_headers_detects_present_headers():

    headers = {
        "Strict-Transport-Security":
            "max-age=31536000",
        "Content-Security-Policy":
            "default-src 'self'",
        "X-Content-Type-Options":
            "nosniff",
    }

    result = analyze_headers(
        headers
    )

    assert (
        "strict-transport-security"
        in result.present
    )

    assert (
        "content-security-policy"
        in result.present
    )

    assert (
        "x-content-type-options"
        in result.present
    )


def test_analyze_headers_detects_missing_headers():

    headers = {
        "Content-Security-Policy":
            "default-src 'self'",
    }

    result = analyze_headers(
        headers
    )

    assert (
        "content-security-policy"
        in result.present
    )

    assert (
        "strict-transport-security"
        in result.missing
    )

    assert (
        "x-frame-options"
        in result.missing
    )


def test_analyze_headers_is_case_insensitive():

    headers = {
        "CONTENT-SECURITY-POLICY":
            "default-src 'self'",
    }

    result = analyze_headers(
        headers
    )

    assert (
        "content-security-policy"
        in result.present
    )


# =========================================================
# COOKIE PARSER
# =========================================================


def test_parse_cookies_extracts_cookie_name():

    header = (
        "session=secret-value; "
        "Secure; "
        "HttpOnly; "
        "SameSite=Lax"
    )

    result = parse_cookies(
        header
    )

    assert len(result) == 1

    cookie = result[0]

    assert cookie.name == "session"

    assert cookie.secure is True

    assert cookie.httponly is True

    assert cookie.samesite == "Lax"


def test_parse_cookies_does_not_store_cookie_value():

    header = (
        "session=super-secret-value; "
        "Secure; HttpOnly"
    )

    result = parse_cookies(
        header
    )

    assert len(result) == 1

    cookie = result[0]

    assert cookie.name == "session"

    # Cookie values must never appear
    # anywhere in the CookieInfo object.
    assert "super-secret-value" not in str(
        cookie
    )


def test_parse_cookies_handles_multiple_cookies():

    header = (
        "session=abc; Secure; HttpOnly, "
        "theme=dark; SameSite=Lax"
    )

    result = parse_cookies(
        header
    )

    assert len(result) == 2

    names = {
        cookie.name
        for cookie in result
    }

    assert names == {
        "session",
        "theme",
    }


def test_parse_cookies_handles_empty_header():

    result = parse_cookies("")

    assert result == []


# =========================================================
# ROBOTS.TXT
# =========================================================


@respx.mock
def test_fetch_robots_extracts_disallow_rules():

    respx.get(
        "https://example.com/robots.txt"
    ).mock(
        return_value=httpx.Response(
            200,
            text="""
            User-agent: *
            Disallow: /admin
            Disallow: /private

            Sitemap: https://example.com/sitemap.xml
            """,
            headers={
                "content-type": "text/plain"
            },
        )
    )

    client = HTTPClient()

    result = fetch_robots(
        client,
        "https://example.com/",
    )

    assert result.found is True

    assert "/admin" in (
        result.disallow_rules
    )

    assert "/private" in (
        result.disallow_rules
    )

    assert (
        "https://example.com/sitemap.xml"
        in result.sitemap_urls
    )


@respx.mock
def test_fetch_robots_handles_missing_robots():

    respx.get(
        "https://example.com/robots.txt"
    ).mock(
        return_value=httpx.Response(
            404,
            text="Not Found",
        )
    )

    client = HTTPClient()

    result = fetch_robots(
        client,
        "https://example.com/",
    )

    assert result.found is False

    assert result.disallow_rules == []

    assert result.sitemap_urls == []


# =========================================================
# DNS
# =========================================================


def test_lookup_dns_returns_dns_analysis():

    result = lookup_dns(
        "https://example.com/"
    )

    # We don't assert specific real-world DNS values.
    # DNS can change at any time.
    assert isinstance(
        result.a,
        list,
    )

    assert isinstance(
        result.aaaa,
        list,
    )

    assert isinstance(
        result.mx,
        list,
    )

    assert isinstance(
        result.ns,
        list,
    )

    assert isinstance(
        result.txt,
        list,
    )


def test_lookup_dns_invalid_url_returns_empty_result():

    result = lookup_dns(
        "not-a-valid-url"
    )

    assert result.a == []

    assert result.aaaa == []

    assert result.mx == []

    assert result.ns == []

    assert result.txt == []