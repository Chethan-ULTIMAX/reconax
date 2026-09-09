"""
Cookie security analysis module.
"""

from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Iterable

from ..context import AnalysisContext
from ..models import CookieAnalysis, CookieInfo
from .base import Module


class CookiesModule(Module[CookieAnalysis]):
    """Inspect cookie attributes without exposing cookie values."""

    name = "cookies"

    @staticmethod
    def _get_set_cookie_headers(
        response_headers: dict[str, str],
    ) -> list[str]:
        """
        Extract Set-Cookie values.

        httpx normally exposes combined header information through its
        Headers object. The internal HTTPResponse stores a normal dict,
        so this method handles the common combined representation.
        """
        values: list[str] = []

        for key, value in response_headers.items():
            if key.lower() != "set-cookie":
                continue

            if not value:
                continue

            # Most normal responses contain one cookie per header.
            # Do not blindly split on commas because Expires attributes
            # themselves can contain commas.
            values.append(value)

        return values

    @staticmethod
    def _parse_cookie(
        raw_cookie: str,
    ) -> CookieInfo | None:
        """
        Parse a Set-Cookie string while never returning its value.
        """
        cookie = SimpleCookie()

        try:
            cookie.load(raw_cookie)
        except Exception:
            return None

        if not cookie:
            return None

        morsel = next(
            iter(cookie.values())
        )

        name = morsel.key

        secure = bool(
            morsel["secure"]
        )

        httponly = bool(
            morsel["httponly"]
        )

        samesite_value = (
            morsel["samesite"]
            or None
        )

        path = (
            morsel["path"]
            or None
        )

        domain = (
            morsel["domain"]
            or None
        )

        expires = (
            morsel["expires"]
            or None
        )

        max_age: int | None = None

        if morsel["max-age"]:
            try:
                max_age = int(
                    morsel["max-age"]
                )
            except ValueError:
                max_age = None

        attributes = []

        if secure:
            attributes.append("Secure")

        if httponly:
            attributes.append("HttpOnly")

        if samesite_value:
            attributes.append(
                f"SameSite={samesite_value}"
            )

        flags: list[str] = []

        if not secure:
            flags.append(
                "Cookie does not have the Secure attribute."
            )

        if not httponly:
            flags.append(
                "Cookie does not have the HttpOnly attribute."
            )

        if not samesite_value:
            flags.append(
                "Cookie does not declare a SameSite attribute."
            )

        return CookieInfo(
            name=name,
            secure=secure,
            httponly=httponly,
            samesite=samesite_value,
            path=path,
            domain=domain,
            expires=expires,
            max_age=max_age,
            raw_attributes=attributes,
            flags=flags,
        )

    def analyze(self) -> CookieAnalysis:
        response = self.context.response()

        raw_headers = self._get_set_cookie_headers(
            response.headers
        )

        cookies: list[CookieInfo] = []

        for raw_cookie in raw_headers:
            parsed = self._parse_cookie(
                raw_cookie
            )

            if parsed is not None:
                cookies.append(parsed)

        flags: list[str] = []
        explanations: list[str] = []

        for cookie in cookies:
            flags.extend(
                f"{cookie.name}: {flag}"
                for flag in cookie.flags
            )

        if not cookies:
            verdict = "INFO"
            explanations.append(
                "No Set-Cookie headers were observed in "
                "the primary HTTP response."
            )
        elif flags:
            verdict = "WARN"
            explanations.append(
                "Cookie attributes were inspected without "
                "exposing cookie values."
            )
        else:
            verdict = "PASS"

        return CookieAnalysis(
            cookies=cookies,
            count=len(cookies),
            verdict=verdict,
            flags=flags,
            explanations=explanations,
        )