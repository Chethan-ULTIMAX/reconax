from unittest.mock import Mock

from reconax.models import HTTPResponse
from reconax.modules.cors import CORSModule


def test_cors_module_reads_response_headers():
    response = HTTPResponse("https://example.com", "https://example.com/", 200, 1, "HTTP/2", "text/html", 1, headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    context = Mock()
    context.response.return_value = response
    result = CORSModule(context).analyze()
    assert result.allow_origin == "*"
    assert result.allow_credentials is True
    assert result.verdict in {"INFO", "WARN", "PASS"}
