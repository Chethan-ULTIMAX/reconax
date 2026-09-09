from unittest.mock import Mock

from reconax.models import HTTPResponse
from reconax.modules.robots import RobotsModule


def test_robots_module_handles_robots_response():
    response = HTTPResponse(
        "https://example.com/robots.txt", "https://example.com/robots.txt",
        200, 1, "HTTP/2", "text/plain", 40,
        content="User-agent: *\nDisallow: /admin\n",
    )
    context = Mock()
    context.get.return_value = response
    context.normalized_url = "https://example.com/"
    context.final_url = "https://example.com/"
    result = RobotsModule(context).analyze()
    assert result.found is True
    assert "/admin" in result.disallow_rules
