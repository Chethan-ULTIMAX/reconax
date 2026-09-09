"""
Website Hygiene Score module.

The score is deliberately transparent and conservative.

It represents observable website security hygiene and configuration
signals. It is NOT a vulnerability severity score, penetration-test
result, or guarantee of security.
"""

from __future__ import annotations

from ..context import AnalysisContext
from ..models import ScoreItem, ScoreReport
from .base import Module


class ScoreModule(Module[ScoreReport]):
    """Calculate the transparent Website Hygiene Score."""

    name = "score"

    def analyze(self) -> ScoreReport:
        headers = self.context.headers_result()
        cookies = self.context.cookies_result()
        csp = self.context.csp_result()
        tls = self.context.tls_result()
        cors = self.context.cors_result()

        categories: list[ScoreItem] = []

        # ---------------------------------------------------------
        # Security headers: 30 points
        # ---------------------------------------------------------
        security_header_names = (
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        )

        present_count = sum(
            1
            for name in security_header_names
            if name in headers.present
        )

        header_score = round(
            (
                present_count
                / len(security_header_names)
            )
            * 30
        )

        categories.append(
            ScoreItem(
                name="Security headers",
                score=header_score,
                maximum=30,
                explanation=(
                    f"{present_count}/"
                    f"{len(security_header_names)} "
                    "recommended security headers were observed."
                ),
            )
        )

        # ---------------------------------------------------------
        # TLS: 25 points
        # ---------------------------------------------------------
        tls_score = 0

        if tls.tls_version:
            tls_score += 10

        if tls.hostname_match is True:
            tls_score += 5

        if (
            tls.days_remaining is not None
            and tls.days_remaining > 30
        ):
            tls_score += 5

        if tls.cipher:
            tls_score += 5

        categories.append(
            ScoreItem(
                name="TLS",
                score=tls_score,
                maximum=25,
                explanation=(
                    "TLS score reflects the observed TLS connection, "
                    "certificate hostname matching, certificate lifetime, "
                    "and negotiated cipher information."
                ),
            )
        )

        # ---------------------------------------------------------
        # Cookies: 15 points
        # ---------------------------------------------------------
        cookie_score = 15

        if cookies.cookies:
            secure_cookies = sum(
                1
                for cookie in cookies.cookies
                if cookie.secure
            )

            httponly_cookies = sum(
                1
                for cookie in cookies.cookies
                if cookie.httponly
            )

            samesite_cookies = sum(
                1
                for cookie in cookies.cookies
                if cookie.samesite
            )

            total = len(
                cookies.cookies
            )

            security_ratio = (
                secure_cookies
                + httponly_cookies
                + samesite_cookies
            ) / (
                total * 3
            )

            cookie_score = round(
                security_ratio * 15
            )

        categories.append(
            ScoreItem(
                name="Cookies",
                score=cookie_score,
                maximum=15,
                explanation=(
                    "Cookie score considers Secure, HttpOnly, "
                    "and SameSite attributes when cookies are observed."
                ),
            )
        )

        # ---------------------------------------------------------
        # CSP: 15 points
        # ---------------------------------------------------------
        csp_score = 0

        if csp.present:
            csp_score = 10

            if not csp.unsafe_inline:
                csp_score += 2

            if not csp.unsafe_eval:
                csp_score += 2

            if not csp.wildcard_sources:
                csp_score += 1

        categories.append(
            ScoreItem(
                name="Content Security Policy",
                score=csp_score,
                maximum=15,
                explanation=(
                    "CSP score reflects whether a policy is present "
                    "and whether common weakening directives were observed."
                ),
            )
        )

        # ---------------------------------------------------------
        # CORS: 10 points
        # ---------------------------------------------------------
        cors_score = 10

        if cors.allow_origin == "*":
            cors_score -= 5

        if (
            cors.allow_origin == "*"
            and cors.allow_credentials is True
        ):
            cors_score -= 2

        cors_score = max(
            0,
            cors_score,
        )

        categories.append(
            ScoreItem(
                name="CORS",
                score=cors_score,
                maximum=10,
                explanation=(
                    "CORS score is conservative and only considers "
                    "headers visible in the normal response."
                ),
            )
        )

        total_score = sum(
            category.score
            for category in categories
        )

        maximum_score = sum(
            category.maximum
            for category in categories
        )

        normalized_score = round(
            (
                total_score
                / maximum_score
            )
            * 100
        ) if maximum_score else 0

        if normalized_score >= 90:
            grade = "Excellent"
        elif normalized_score >= 75:
            grade = "Good"
        elif normalized_score >= 60:
            grade = "Fair"
        elif normalized_score >= 40:
            grade = "Needs improvement"
        else:
            grade = "Poor"

        flags: list[str] = []

        if normalized_score < 60:
            flags.append(
                "Several observable website hygiene signals "
                "could be improved."
            )

        explanations = [
            "This 0-100 score measures observable website hygiene "
            "signals and is not a vulnerability or security guarantee."
        ]

        return ScoreReport(
            score=normalized_score,
            maximum=100,
            grade=grade,
            categories=categories,
            verdict=(
                "PASS"
                if normalized_score >= 75
                else "WARN"
            ),
            flags=flags,
            explanations=explanations,
        )