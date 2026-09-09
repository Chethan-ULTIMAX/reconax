from unittest.mock import Mock

from reconax.context import AnalysisContext
from reconax.models import HTTPResponse


def make_response():
    return HTTPResponse(
        requested_url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        response_time_ms=12.5,
        http_version="HTTP/1.1",
        content_type="text/html",
        content_length=20,
        content="<html><title>Test</title></html>",
        headers={"content-type": "text/html"},
    )


def test_context_caches_primary_response():
    ctx = AnalysisContext("example.com")
    ctx._client.fetch = Mock(return_value=make_response())
    assert ctx.status_code == 200
    assert ctx.final_url == "https://example.com/"
    assert ctx.status_code == 200
    ctx._client.fetch.assert_called_once_with("https://example.com")
    ctx.close()


def test_context_normalizes_url():
    ctx = AnalysisContext("example.com/path")
    assert ctx.normalized_url == "https://example.com/path"
    ctx.close()


def test_context_html_is_cached():
    ctx = AnalysisContext("https://example.com")
    ctx._client.fetch = Mock(return_value=make_response())
    first = ctx.html()
    second = ctx.html()
    assert first is second
    assert first.title.string == "Test"
    ctx.close()
