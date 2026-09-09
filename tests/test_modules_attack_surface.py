from unittest.mock import Mock

from reconax.models import AttackSurfaceAnalysis, EndpointAnalysis, ResourceAnalysis, RobotsAnalysis, SitemapAnalysis
from reconax.modules.attack_surface import AttackSurfaceModule


def test_attack_surface_module_combines_passive_results():
    context = Mock()
    context.endpoints_result.return_value = EndpointAnalysis(pages=["https://example.com/about"], forms=["https://example.com/login"], api_like=["https://example.com/api/users"])
    context.resources_result.return_value = ResourceAnalysis(first_party_count=1, third_party_count=1)
    context.robots_result.return_value = RobotsAnalysis(disallow_rules=["/admin"])
    context.sitemap_result.return_value = SitemapAnalysis(discovered_urls=["https://example.com/home"])
    context.html_result.return_value = Mock(scripts=["https://example.com/app.js"], external_links=["https://cdn.example.net/"])
    result = AttackSurfaceModule(context).analyze()
    assert isinstance(result, AttackSurfaceAnalysis)
    assert result.pages
    assert result.forms
    assert result.api_like_urls
    assert result.robots_rules == ["/admin"]
