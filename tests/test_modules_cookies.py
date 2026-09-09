from unittest.mock import Mock

from reconax.models import HTTPResponse
from reconax.modules.cookies import CookiesModule


def test_cookie_parser_does_not_expose_value():
    cookie = CookiesModule._parse_cookie("session=secret; Secure; HttpOnly; SameSite=Lax")
    assert cookie is not None
    assert cookie.name == "session"
    assert cookie.secure and cookie.httponly
    assert cookie.samesite == "Lax"
    assert "secret" not in str(cookie)


def test_cookie_module_warns_on_weak_cookie():
    response = HTTPResponse("https://example.com", "https://example.com/", 200, 1, "HTTP/2", "text/html", 1, headers={"Set-Cookie": "session=abc"})
    context = Mock()
    context.response.return_value = response
    result = CookiesModule(context).analyze()
    assert result.count == 1
    assert result.verdict == "WARN"
    assert result.cookies[0].secure is False
