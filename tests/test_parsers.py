from reconax.parsers.cookies import parse_cookies
from reconax.parsers.headers import analyze_headers
from reconax.parsers.html_parser import parse_html


def test_html_parser():
    report = parse_html(
        '<title>Example</title><meta name="description" content="Demo">'
        '<a href="/about">About</a><a href="https://other.example/x">Other</a>'
        '<script src="/app.js"></script><img src="/logo.png">',
        "https://example.com/",
    )
    assert report.title == "Example"
    assert report.meta_description == "Demo"
    assert report.internal_link_count == 1
    assert report.external_link_count == 1
    assert len(report.scripts) == 1
    assert len(report.images) == 1


def test_header_parser():
    report = analyze_headers({"Strict-Transport-Security": "max-age=31536000"})
    assert "strict-transport-security" in report.present
    assert "content-security-policy" in report.missing


def test_cookie_parser_does_not_expose_values():
    cookies = parse_cookies("session=secret; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert len(cookies) == 1
    assert cookies[0].name == "session"
    assert cookies[0].secure is True
    assert cookies[0].http_only is True
    assert cookies[0].same_site == "Lax"
