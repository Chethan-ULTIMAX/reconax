from unittest.mock import Mock

import dns.resolver

from reconax.models import DNSAnalysis
from reconax.modules.dns import DNSModule


def test_dns_hostname_parsing():
    context = Mock()
    context.normalized_url = "https://example.com/path"
    context.timeout = 2.0
    assert DNSModule(context)._hostname() == "example.com"


def test_dns_module_uses_resolver(monkeypatch):
    class Answer:
        def __str__(self):
            return "93.184.216.34"

    resolver = Mock()

    def resolve(hostname, record_type):
        if record_type == "A":
            return [Answer()]
        raise dns.resolver.NoAnswer()

    resolver.resolve.side_effect = resolve
    monkeypatch.setattr("reconax.modules.dns.dns.resolver.Resolver", lambda: resolver)

    context = Mock()
    context.normalized_url = "https://example.com/"
    context.timeout = 1.0
    result = DNSModule(context).analyze()

    assert isinstance(result, DNSAnalysis)
    assert result.hostname == "example.com"
    assert result.records["A"] == ["93.184.216.34"]
