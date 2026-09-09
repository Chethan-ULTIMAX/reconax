from __future__ import annotations

from ..models import CookieInfo


def _split_set_cookie_header(
    header: str,
) -> list[str]:
    """
    Split a Set-Cookie header into individual cookies.

    This handles common cases where multiple Set-Cookie
    values have been combined into one header string.
    """

    if not header:
        return []

    cookies: list[str] = []
    current: list[str] = []

    # Cookie attributes can contain commas inside Expires.
    # We therefore only split on commas that appear to begin
    # another cookie.
    parts = header.split(",")

    for index, part in enumerate(parts):

        stripped = part.strip()

        if not stripped:
            continue

        # If this segment contains '=' in its first section,
        # it may start a new cookie.
        first_section = stripped.split(";", 1)[0]

        if "=" in first_section:
            if current:
                cookies.append(",".join(current).strip())

            current = [stripped]
        else:
            current.append(stripped)

    if current:
        cookies.append(",".join(current).strip())

    return cookies


def _parse_cookie(
    cookie_string: str,
) -> CookieInfo | None:
    """Parse one Set-Cookie value safely."""

    sections = [
        section.strip()
        for section in cookie_string.split(";")
        if section.strip()
    ]

    if not sections:
        return None

    first = sections[0]

    if "=" not in first:
        return None

    name, _value = first.split(
        "=",
        1,
    )

    name = name.strip()

    if not name:
        return None

    secure = False
    httponly = False
    samesite: str | None = None

    for attribute in sections[1:]:

        if "=" in attribute:
            key, value = attribute.split(
                "=",
                1,
            )

            key = key.strip().lower()
            value = value.strip()

            if key == "samesite":
                samesite = value

        else:
            key = attribute.strip().lower()

            if key == "secure":
                secure = True

            elif key == "httponly":
                httponly = True

    return CookieInfo(
        name=name,
        secure=secure,
        httponly=httponly,
        samesite=samesite,
    )


def parse_cookies(
    set_cookie_header: str,
) -> list[CookieInfo]:
    """
    Parse Set-Cookie response data.

    Cookie values are intentionally discarded.
    """

    if not set_cookie_header:
        return []

    cookie_strings = _split_set_cookie_header(
        set_cookie_header,
    )

    cookies: list[CookieInfo] = []

    seen_names: set[str] = set()

    for cookie_string in cookie_strings:

        cookie = _parse_cookie(
            cookie_string,
        )

        if cookie is None:
            continue

        # Keep the report clean if the same cookie appears
        # more than once.
        if cookie.name in seen_names:
            continue

        seen_names.add(cookie.name)
        cookies.append(cookie)

    return cookies