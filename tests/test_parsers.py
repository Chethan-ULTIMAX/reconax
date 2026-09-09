from __future__ import annotations

import httpx
import respx

from reconax.http_client import HTTPClient
from reconax.models import DNSAnalysis, HTMLAnalysis
from reconax.parsers.cookies import parse_cookies
from reconax.parsers.dns_lookup import lookup_dns
from reconax.parsers.headers import analyze_headers
from reconax.parsers.html_parser import parse_html
from reconax.parsers.robots import fetch_robots


def test_parse_html_extracts_title():
    result = parse_html("<html><head><title>ReconAx Test</title></head></html>", "https://example.com")
    assert isinstance(result, HTMLAnalysis)
    assert result.title == "ReconAx Test"


def test_parse_html_extracts_meta_description():
    result = parse_html('<meta name="description" content="Test website">', "https://example.com")
    assert result.meta_description == "Test website"


def test_parse_html_extracts_internal_and_external_links():
    html = '<a href="/about">About</a><a href="https://example.com/contact">Contact</a><a href="https://google.com">Google</a>'
    result = parse_html(html, "https://example.com")
    assert result.link_count == 3
    assert len(result.internal_links) == 2
    assert len(result.external_links) == 1
    assert "https://example.com/about" in result.internal_links
    assert "https://google.com" in result.external_links


def test_parse_html_ignores_non_http_links():
    html = '<a href="#section">Section</a><a href="mailto:test@example.com">Email</a><a href="javascript:void(0)">JS</a><a href="/real">Real</a>'
    result = parse_html(html, "https://example.com")
    assert result.link_count == 1
    assert result.internal_links == ["https://example.com/real"]


def test_parse_html_extracts_scripts():
    html = '<script src="/static/app.js"></script><script src="https://cdn.example.com/lib.js"></script>'
    result = parse_html(html, "https://example.com")
    assert result.script_count == 2


def test_parse_html_extracts_images():
    html = '<img src="/images/logo.png"><img src="https://cdn.example.com/photo.jpg">'
    result = parse_html(html, "https://example.com")
    assert result.image_count == 2


def test_parse_html_removes_duplicate_links():
    result = parse_html('<a href="/about">1</a><a href="/about">2</a><a href="/about">3</a>', "https://example.com")
    assert result.link_count == 1


def test_analyze_headers_detects_present_headers():
    result = analyze_headers({"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'self'", "X-Content-Type-Options": "nosniff"})
    assert "strict-transport-security" in result.present
    assert "content-security-policy" in result.present
    assert "x-content-type-options" in result.present


def test_analyze_headers_detects_missing_headers():
    result = analyze_headers({"Content-Security-Policy": "default-src 'self'"})
    assert "content-security-policy" in result.present
    assert "strict-transport-security" in result.missing
    assert "x-frame-options" in result.missing


def test_analyze_headers_is_case_insensitive():
    result = analyze_headers({"CONTENT-SECURITY-POLICY": "default-src 'self'"})
    assert "content-security-policy" in result.present


def test_parse_cookies_extracts_cookie_name():
    result = parse_cookies("session=secret-value; Secure; HttpOnly; SameSite=Lax")
    assert len(result) == 1
    cookie = result[0]
    assert cookie.name == "session"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "Lax"


def test_parse_cookies_does_not_store_cookie_value():
    result = parse_cookies("session=super-secret-value; Secure; HttpOnly")
    assert len(result) == 1
    cookie = result[0]
    assert cookie.name == "session"
    assert "super-secret-value" not in str(cookie)


def test_parse_cookies_handles_multiple_cookies():
    result = parse_cookies("session=abc; Secure; HttpOnly, theme=dark; SameSite=Lax")
    assert {cookie.name for cookie in result} == {"session", "theme"}


def test_parse_cookies_handles_empty_header():
    assert parse_cookies("") == []


@respx.mock
def test_fetch_robots_extracts_disallow_rules():
    respx.get("https://example.com/robots.txt").mock(return_value=httpx.Response(200, text="User-agent: *\nDisallow: /admin\nDisallow: /private\nSitemap: https://example.com/sitemap.xml\n", headers={"content-type": "text/plain"}))
    result = fetch_robots(HTTPClient(), "https://example.com/")
    assert result.found is True
    assert result.status_code == 200
    assert "/admin" in result.disallow_rules
    assert "/private" in result.disallow_rules
    assert "https://example.com/sitemap.xml" in result.sitemap_urls


@respx.mock
def test_fetch_robots_handles_missing_robots():
    respx.get("https://example.com/robots.txt").mock(return_value=httpx.Response(404, text="Not Found"))
    result = fetch_robots(HTTPClient(), "https://example.com/")
    assert result.found is False
    assert result.status_code == 404
    assert result.disallow_rules == []
    assert result.sitemap_urls == []


def test_lookup_dns_returns_dns_analysis():
    result = lookup_dns("https://example.com/")
    assert isinstance(result, DNSAnalysis)
    assert result.hostname == "example.com"
    assert isinstance(result.records, dict)
    for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
        assert isinstance(result.records.get(record_type), list)


def test_lookup_dns_invalid_url_returns_empty_result():
    result = lookup_dns("not-a-valid-url")
    assert isinstance(result, DNSAnalysis)
    assert result.hostname == ""
    assert result.records == {}
