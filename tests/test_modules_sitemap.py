from unittest.mock import Mock

from reconax.models import HTTPResponse
from reconax.modules.sitemap import SitemapModule


def test_sitemap_module_handles_missing_sitemap():
    context = Mock()
    context.normalized_url = "https://example.com/"
    context.get.return_value = HTTPResponse("https://example.com/sitemap.xml", "https://example.com/sitemap.xml", 404, 1, "HTTP/2", "text/plain", 0, content="")
    result = SitemapModule(context).analyze()
    assert result.found is False
    assert result.discovered_urls == []
