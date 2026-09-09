from unittest.mock import Mock

from reconax.models import HTTPResponse
from reconax.modules.tech import TechModule


def test_tech_module_detects_server_header():
    response = HTTPResponse("https://example.com", "https://example.com/", 200, 1, "HTTP/2", "text/html", 1, headers={"Server": "nginx"})
    context = Mock()
    context.response.return_value = response
    context.html.return_value = Mock()
    result = TechModule(context).analyze()
    assert result.technologies
    assert any("nginx" in technology.name.lower() for technology in result.technologies)
