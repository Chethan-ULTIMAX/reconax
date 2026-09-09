"""
security.txt analysis module.

Analyzes the standardized /.well-known/security.txt location.
"""

from __future__ import annotations

from urllib.parse import urljoin

import httpx

from ..context import AnalysisContext
from ..models import SecurityTxtAnalysis
from .base import Module


class SecurityTxtModule(Module[SecurityTxtAnalysis]):
    """Analyze /.well-known/security.txt."""

    name = "security_txt"

    def analyze(self) -> SecurityTxtAnalysis:
        url = urljoin(
            self.context.final_url,
            "/.well-known/security.txt",
        )

        try:
            response = self.context._client._client.get(
                url
            )
        except httpx.RequestError as exc:
            return SecurityTxtAnalysis(
                found=False,
                verdict="INFO",
                flags=[
                    f"Unable to retrieve security.txt: {exc}"
                ],
            )

        if response.status_code != 200:
            return SecurityTxtAnalysis(
                found=False,
                status_code=response.status_code,
                verdict="INFO",
                flags=[
                    "security.txt was not found at the standard location."
                ],
            )

        contacts: list[str] = []
        policies: list[str] = []
        canonicals: list[str] = []
        expires: str | None = None

        for raw_line in response.text.splitlines():
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if ":" not in line:
                continue

            field, value = line.split(
                ":",
                1,
            )

            field = field.strip().lower()
            value = value.strip()

            if field == "contact" and value:
                contacts.append(value)

            elif field == "policy" and value:
                policies.append(value)

            elif field == "canonical" and value:
                canonicals.append(value)

            elif field == "expires" and value:
                expires = value

        flags: list[str] = []
        explanations: list[str] = []

        if not contacts:
            flags.append(
                "security.txt does not declare a Contact field."
            )

        if not expires:
            flags.append(
                "security.txt does not declare an Expires field."
            )

        if flags:
            verdict = "WARN"
        else:
            verdict = "PASS"

        return SecurityTxtAnalysis(
            found=True,
            status_code=response.status_code,
            contact=contacts,
            expires=expires,
            policy=policies,
            canonical=canonicals,
            verdict=verdict,
            flags=flags,
            explanations=explanations,
        )