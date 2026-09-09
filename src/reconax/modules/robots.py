"""
robots.txt analysis module.
"""

from __future__ import annotations

from urllib.parse import urljoin

import httpx

from ..context import AnalysisContext
from ..models import RobotsAnalysis
from .base import Module


class RobotsModule(Module[RobotsAnalysis]):
    """Fetch and parse the target's robots.txt."""

    name = "robots"

    def analyze(self) -> RobotsAnalysis:
        base_url = self.context.final_url

        robots_url = urljoin(
            base_url,
            "/robots.txt",
        )

        try:
            response = self.context._client._client.get(
                robots_url
            )
        except httpx.RequestError as exc:
            return RobotsAnalysis(
                found=False,
                verdict="INFO",
                flags=[
                    f"Unable to retrieve robots.txt: {exc}"
                ],
            )

        if response.status_code != 200:
            return RobotsAnalysis(
                found=False,
                status_code=response.status_code,
                verdict="INFO",
                flags=[
                    "robots.txt was not available at the expected path."
                ],
                explanations=[
                    "ReconAx only analyzes the standard public "
                    "/robots.txt location."
                ],
            )

        # The underlying httpx response exposes bytes, while the lightweight
        # HTTPResponse used by tests/integrations may expose decoded text.
        raw_content = response.content
        if isinstance(raw_content, bytes):
            content = raw_content.decode(
                getattr(response, "encoding", None) or "utf-8",
                errors="replace",
            )
        else:
            content = str(raw_content or "")

        user_agents: list[str] = []
        allow_rules: list[str] = []
        disallow_rules: list[str] = []
        sitemap_urls: list[str] = []

        for raw_line in content.splitlines():
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if ":" not in line:
                continue

            directive, value = line.split(":", 1)

            directive = directive.strip().lower()
            value = value.strip()

            if directive == "user-agent":
                if value and value not in user_agents:
                    user_agents.append(value)

            elif directive == "allow":
                if value:
                    allow_rules.append(value)

            elif directive == "disallow":
                if value:
                    disallow_rules.append(value)

            elif directive == "sitemap":
                if value:
                    sitemap_urls.append(
                        urljoin(
                            robots_url,
                            value,
                        )
                    )

        flags: list[str] = []
        explanations: list[str] = []

        if disallow_rules:
            flags.append(
                f"robots.txt contains {len(disallow_rules)} "
                "disallow rule(s)."
            )
            explanations.append(
                "robots.txt is a crawler-control mechanism and "
                "should not be treated as an access-control boundary."
            )

        return RobotsAnalysis(
            found=True,
            status_code=response.status_code,
            user_agents=user_agents,
            allow_rules=allow_rules,
            disallow_rules=disallow_rules,
            sitemap_urls=sitemap_urls,
            raw_content=content,
            verdict="INFO",
            flags=flags,
            explanations=explanations,
        )
