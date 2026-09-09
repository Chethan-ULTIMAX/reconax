"""
HTTP analysis module.
"""

from __future__ import annotations

from ..models import HTTPResponse
from ..context import AnalysisContext
from .base import Module


class HTTPModule(Module[HTTPResponse]):
    """Analyze the primary HTTP response."""

    name = "http"

    def analyze(self) -> HTTPResponse:
        """
        Return the HTTP response already cached by AnalysisContext.

        No second request is made if the context has already fetched
        the target.
        """
        return self.context.response()