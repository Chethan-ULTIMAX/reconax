"""
Content-Security-Policy analysis module.

This parser examines the CSP header from the normal HTTP response.
It does not attempt to bypass the policy.
"""

from __future__ import annotations

from ..context import AnalysisContext
from ..models import CSPAnalysis
from .base import Module


class CSPModule(Module[CSPAnalysis]):
    """Parse and summarize Content-Security-Policy."""

    name = "csp"

    def analyze(self) -> CSPAnalysis:
        response = self.context.response()

        policy = None

        for key, value in response.headers.items():
            if key.lower() == (
                "content-security-policy"
            ):
                policy = value
                break

        if not policy:
            return CSPAnalysis(
                present=False,
                verdict="WARN",
                flags=[
                    "Content-Security-Policy is not present."
                ],
                explanations=[
                    "A CSP can provide an additional browser-side "
                    "defense against certain content-injection attacks."
                ],
            )

        directives: dict[str, list[str]] = {}

        unsafe_inline = False
        unsafe_eval = False
        wildcard_sources: list[str] = []

        for section in policy.split(";"):
            section = section.strip()

            if not section:
                continue

            parts = section.split()

            if not parts:
                continue

            directive = parts[0].lower()
            values = parts[1:]

            directives[directive] = values

            for value in values:
                lower_value = value.lower()

                if lower_value == "'unsafe-inline'":
                    unsafe_inline = True

                if lower_value == "'unsafe-eval'":
                    unsafe_eval = True

                if value == "*":
                    wildcard_sources.append(
                        f"{directive} *"
                    )

        flags: list[str] = []
        explanations: list[str] = []

        if unsafe_inline:
            flags.append(
                "CSP permits 'unsafe-inline'."
            )
            explanations.append(
                "Allowing inline script or style content can "
                "weaken the protection provided by CSP."
            )

        if unsafe_eval:
            flags.append(
                "CSP permits 'unsafe-eval'."
            )
            explanations.append(
                "Allowing eval-like execution can weaken CSP's "
                "protection against certain script injection scenarios."
            )

        if wildcard_sources:
            flags.append(
                "CSP contains wildcard source expressions."
            )

        if flags:
            verdict = "WARN"
        else:
            verdict = "PASS"

        return CSPAnalysis(
            present=True,
            directives=directives,
            unsafe_inline=unsafe_inline,
            unsafe_eval=unsafe_eval,
            wildcard_sources=wildcard_sources,
            verdict=verdict,
            flags=flags,
            explanations=explanations,
        )