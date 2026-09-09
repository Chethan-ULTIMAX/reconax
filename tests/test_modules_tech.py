from unittest.mock import Mock

from bs4 import BeautifulSoup

from reconax.models import HTTPResponse
from reconax.modules.tech import TechModule


def test_tech_module_detects_server_header():
    html = "<html><head><title>Demo</title></head><body></body></html>"
    response = HTTPResponse(
        "https://example.com", "https://example.com/", 200, 1,
        "HTTP/2", "text/html", len(html),
        content=html, headers={"Server": "nginx"},
    )
    context = Mock()
    context.response.return_value = response
    context.html.return_value = BeautifulSoup(html, "lxml")
    result = TechModule(context).analyze()
    assert result.technologies
    assert any("nginx" in technology.name.lower() for technology in result.technologies)
