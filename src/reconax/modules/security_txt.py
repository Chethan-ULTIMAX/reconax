"""security.txt analysis module."""

from __future__ import annotations

from datetime import datetime, timezone

from ..models import SecurityTxtAnalysis
from .base import Module


class SecurityTxtModule(Module):
    """Inspect the standard /.well-known/security.txt file."""

    name = "security_txt"

    def analyze(self) -> SecurityTxtAnalysis:
        url = f"{self.context.origin}/.well-known/security.txt"

        try:
            response = self.context.get(url)
        except Exception as exc:
            return SecurityTxtAnalysis(
                found=False,
                url=url,
                status_code=None,
                contact=[],
                policy=[],
                canonical=[],
                expires=None,
                errors=[str(exc)],
            )

        if response.status_code != 200:
            return SecurityTxtAnalysis(
                found=False,
                url=url,
                status_code=response.status_code,
                contact=[],
                policy=[],
                canonical=[],
                expires=None,
                errors=[],
            )

        raw_content = response.content
        if isinstance(raw_content, bytes):
            content = raw_content.decode(
                getattr(response, "encoding", None) or "utf-8",
                errors="replace",
            )
        else:
            content = str(raw_content or "")

        contact: list[str] = []
        policy: list[str] = []
        canonical: list[str] = []
        expires: str | None = None
        errors: list[str] = []

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue

            field, value = line.split(":", 1)
            field = field.strip().lower()
            value = value.strip()

            if field == "contact":
                contact.append(value)
            elif field == "policy":
                policy.append(value)
            elif field == "canonical":
                canonical.append(value)
            elif field == "expires":
                expires = value

        if expires:
            try:
                parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                if parsed < datetime.now(timezone.utc):
                    errors.append("security.txt is expired")
            except ValueError:
                errors.append("Invalid Expires value")

        return SecurityTxtAnalysis(
            found=True,
            url=url,
            status_code=response.status_code,
            contact=contact,
            policy=policy,
            canonical=canonical,
            expires=expires,
            errors=errors,
        )
