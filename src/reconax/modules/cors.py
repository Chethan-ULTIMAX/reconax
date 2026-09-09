"""
Passive CORS analysis module.

The module inspects CORS headers from the normal HTTP response.
It does not send Origin variations or perform CORS exploitation.
"""

from __future__ import annotations

from ..context import AnalysisContext
from ..models import CORSAnalysis
from .base import Module


class CORSModule(Module[CORSAnalysis]):
    """Inspect publicly exposed CORS response headers."""

    name = "cors"

    def analyze(self) -> CORSAnalysis:
        response = self.context.response()

        headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        allow_origin = headers.get(
            "access-control-allow-origin"
        )

        allow_credentials_value = headers.get(
            "access-control-allow-credentials"
        )

        allow_credentials: bool | None = None

        if allow_credentials_value:
            allow_credentials = (
                allow_credentials_value.lower()
                == "true"
            )

        allow_methods = headers.get(
            "access-control-allow-methods"
        )

        allow_headers = headers.get(
            "access-control-allow-headers"
        )

        expose_headers = headers.get(
            "access-control-expose-headers"
        )

        max_age = headers.get(
            "access-control-max-age"
        )

        flags: list[str] = []
        explanations: list[str] = []

        if allow_origin == "*":
            flags.append(
                "Access-Control-Allow-Origin uses a wildcard."
            )
            explanations.append(
                "A wildcard permits cross-origin reads for "
                "requests where browser CORS rules allow it. "
                "This is not automatically a vulnerability."
            )

        if (
            allow_origin == "*"
            and allow_credentials is True
        ):
            flags.append(
                "Wildcard origin and credentials were both observed."
            )
            explanations.append(
                "Browsers generally reject credentialed CORS "
                "when the server returns a wildcard origin."
            )

        has_cors_headers = any(
            value is not None
            for value in (
                allow_origin,
                allow_methods,
                allow_headers,
                expose_headers,
                max_age,
            )
        )

        if has_cors_headers:
            verdict = (
                "WARN"
                if flags
                else "INFO"
            )
        else:
            verdict = "INFO"

        return CORSAnalysis(
            allow_origin=allow_origin,
            allow_credentials=allow_credentials,
            allow_methods=allow_methods,
            allow_headers=allow_headers,
            expose_headers=expose_headers,
            max_age=max_age,
            verdict=verdict,
            flags=flags,
            explanations=explanations,
        )