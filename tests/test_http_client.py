from __future__ import annotations

import httpx
import pytest
import respx

from reconax.http_client import HTTPClient


# ---------------------------------------------------------
# URL normalization
# ---------------------------------------------------------


def test_normalize_url_adds_https():
    result = HTTPClient.normalize_url(
        "example.com"
    )

    assert result == "https://example.com"


def test_normalize_url_preserves_https():
    result = HTTPClient.normalize_url(
        "https://example.com"
    )

    assert result == "https://example.com"


def test_normalize_url_preserves_http():
    result = HTTPClient.normalize_url(
        "http://example.com"
    )

    assert result == "http://example.com"


def test_normalize_url_strips_whitespace():
    result = HTTPClient.normalize_url(
        "  https://example.com  "
    )

    assert result == "https://example.com"


def test_normalize_url_rejects_empty_url():
    with pytest.raises(ValueError):
        HTTPClient.normalize_url("")


def test_normalize_url_rejects_invalid_scheme():
    with pytest.raises(ValueError):
        HTTPClient.normalize_url(
            "ftp://example.com"
        )


def test_normalize_url_rejects_missing_hostname():
    with pytest.raises(ValueError):
        HTTPClient.normalize_url(
            "https://"
        )


# ---------------------------------------------------------
# HTTP GET
# ---------------------------------------------------------


@respx.mock
def test_get_returns_response_metadata():

    route = respx.get(
        "https://example.com/"
    ).mock(
        return_value=httpx.Response(
            200,
            text="<html><title>Example</title></html>",
            headers={
                "content-type": "text/html",
                "content-length": "40",
            },
        )
    )

    client = HTTPClient()

    response = client.get(
        "https://example.com"
    )

    assert route.called

    assert response.requested_url == (
        "https://example.com"
    )

    assert response.final_url == (
        "https://example.com"
    )

    assert response.status_code == 200

    assert response.reason_phrase == "OK"

    assert response.content_type == (
        "text/html"
    )

    assert response.content_length == 40

    assert response.body == (
        "<html><title>Example</title></html>"
    )

    assert response.elapsed_ms >= 0


# ---------------------------------------------------------
# Redirects
# ---------------------------------------------------------


@respx.mock
def test_get_follows_redirect():

    first = respx.get(
        "https://example.com/"
    ).mock(
        return_value=httpx.Response(
            301,
            headers={
                "location": "https://example.com/home"
            },
        )
    )

    second = respx.get(
        "https://example.com/home"
    ).mock(
        return_value=httpx.Response(
            200,
            text="Hello",
        )
    )

    client = HTTPClient()

    response = client.get(
        "https://example.com"
    )

    assert first.called
    assert second.called

    assert response.status_code == 200

    assert response.final_url == (
        "https://example.com/home"
    )

    assert response.body == "Hello"


# ---------------------------------------------------------
# User-Agent
# ---------------------------------------------------------


@respx.mock
def test_get_sends_reconax_user_agent():

    route = respx.get(
        "https://example.com/"
    ).mock(
        return_value=httpx.Response(
            200,
            text="OK",
        )
    )

    client = HTTPClient()

    client.get(
        "https://example.com"
    )

    request = route.calls.last.request

    assert request.headers["user-agent"] == (
        "ReconAx/0.1.0"
    )