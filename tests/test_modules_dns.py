from unittest.mock import Mock

from reconax.models import DNSAnalysis
from reconax.modules.dns import DNSModule


def test_dns_module_returns_parser_result(monkeypatch):
    expected = DNSAnalysis(hostname="example.com", records={"A": ["93.184.216.34"]})
    context = Mock()
    context.normalized_url = "https://example.com/"
    monkeypatch.setattr("reconax.modules.dns.lookup_dns", lambda hostname: expected)
    result = DNSModule(context).analyze()
    assert isinstance(result, DNSAnalysis)
    assert result.records["A"] == ["93.184.216.34"]
