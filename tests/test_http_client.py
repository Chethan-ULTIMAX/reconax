import httpx
import respx

from reconax.http_client import HTTPClient


@respx.mock
def test_get_collects_response_metadata():
    route = respx.get("https://example.com/").mock(
        return_value=httpx.Response(200, text="<html>Hello</html>", headers={"content-type": "text/html"})
    )
    response = HTTPClient().get("example.com")
    assert route.called
    assert response.status_code == 200
    assert response.final_url == "https://example.com/"
    assert response.content_type == "text/html"
    assert response.elapsed_ms >= 0


def test_normalize_url_adds_https():
    assert HTTPClient.normalize_url("example.com") == "https://example.com"
