from __future__ import annotations

from .http_client import HTTPClient
from .models import ReconReport

from .parsers.cookies import parse_cookies
from .parsers.dns_lookup import lookup_dns
from .parsers.headers import analyze_headers
from .parsers.html_parser import parse_html
from .parsers.robots import fetch_robots


class ReconAx:
    """Main public API for the ReconAx website analyzer."""

    def __init__(
        self,
        url: str,
        timeout: float = 10.0,
        enable_dns: bool = True,
    ):
        self.url = url
        self.timeout = timeout
        self.enable_dns = enable_dns

    def analyze(self) -> ReconReport:
        """
        Analyze a website using lightweight public-information checks.

        The pipeline is:

        URL
          ↓
        HTTP request
          ↓
        Response
          ↓
        ├── Headers
        ├── Cookies
        ├── HTML
        ├── robots.txt
        └── DNS
          ↓
        ReconReport
        """

        client = HTTPClient(
            timeout=self.timeout,
        )

        # ---------------------------------------------------------
        # 1. Main HTTP request
        # ---------------------------------------------------------

        response = client.get(self.url)

        # ---------------------------------------------------------
        # 2. HTML analysis
        # ---------------------------------------------------------

        html = parse_html(
            response.body,
            response.final_url,
        )

        # ---------------------------------------------------------
        # 3. Security headers
        # ---------------------------------------------------------

        headers = analyze_headers(
            response.headers,
        )

        # ---------------------------------------------------------
        # 4. Cookies
        # ---------------------------------------------------------

        cookies = parse_cookies(
            response.headers.get("set-cookie", ""),
        )

        # ---------------------------------------------------------
        # 5. robots.txt + sitemap
        # ---------------------------------------------------------

        robots = fetch_robots(
            client,
            response.final_url,
        )

        # ---------------------------------------------------------
        # 6. DNS
        # ---------------------------------------------------------

        if self.enable_dns:
            dns = lookup_dns(
                response.final_url,
            )
        else:
            from .models import DNSAnalysis

            dns = DNSAnalysis()

        # ---------------------------------------------------------
        # 7. Build final report
        # ---------------------------------------------------------

        return ReconReport(
            requested_url=response.requested_url,
            final_url=response.final_url,
            status_code=response.status_code,
            reason_phrase=response.reason_phrase,
            http_version=response.http_version,
            content_type=response.content_type,
            content_length=response.content_length,
            elapsed_ms=response.elapsed_ms,
            headers=headers,
            cookies=cookies,
            html=html,
            robots=robots,
            dns=dns,
        )