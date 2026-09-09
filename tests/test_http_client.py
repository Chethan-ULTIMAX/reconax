import httpx

from reconax.http_client import HTTPClient


def test_normalize_url_adds_scheme():
    client = HTTPClient()
    assert client.normalize_url("example.com") == "https://example.com"
    client.close()


def test_normalize_url_preserves_scheme():
    client = HTTPClient()
    assert client.normalize_url("http://example.com/a") == "http://example.com/a"
    client.close()


def test_fetch_builds_structured_response(monkeypatch):
    class FakeResponse:
        status_code = 200
        url = httpx.URL("https://example.com/")
        http_version = "HTTP/2"
        headers = httpx.Headers({"content-type": "text/html; charset=utf-8"})
        content = b"hello"
        text = "hello"
        history = []

    class FakeClient:
        def get(self, url):
            return FakeResponse()
        def close(self):
            pass

    client = HTTPClient()
    client._client = FakeClient()
    result = client.fetch("example.com")
    assert result.status_code == 200
    assert result.final_url == "https://example.com/"
    assert result.content == "hello"
    assert result.content_length == 5
    client.close()


def test_fetch_handles_request_error(monkeypatch):
    class FakeClient:
        def get(self, url):
            raise httpx.ConnectError("offline")
        def close(self):
            pass

    client = HTTPClient()
    client._client = FakeClient()
    result = client.fetch("https://example.com")
    assert result.status_code == 0
    assert result.error
    client.close()
