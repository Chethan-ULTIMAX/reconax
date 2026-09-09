from __future__ import annotations

from http.cookies import SimpleCookie

from ..models import CookieInfo


def parse_cookies(set_cookie: str) -> list[CookieInfo]:
    if not set_cookie:
        return []
    cookie = SimpleCookie()
    try:
        cookie.load(set_cookie)
    except Exception:
        return []

    result: list[CookieInfo] = []
    for name, morsel in cookie.items():
        same_site = morsel["samesite"] or None
        result.append(
            CookieInfo(
                name=name,
                http_only=bool(morsel["httponly"]),
                secure=bool(morsel["secure"]),
                same_site=same_site,
            )
        )
    return result
