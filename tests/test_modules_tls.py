from unittest.mock import Mock

from reconax.modules.tls import TLSModule


def test_tls_target_parsing():
    context = Mock()
    context.normalized_url = "https://example.com:8443/path"
    context.timeout = 5.0
    module = TLSModule(context)
    assert module._get_target() == ("example.com", 8443)


def test_tls_helpers_parse_certificate():
    cert = {"subject": [[("commonName", "example.com")]], "issuer": [[("organizationName", "Example CA")]], "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")]}
    assert TLSModule._name_attributes(cert, "subject")["commonName"] == "example.com"
    assert TLSModule._name_attributes(cert, "issuer")["organizationName"] == "Example CA"
    assert TLSModule._subject_alt_names(cert) == ["example.com", "www.example.com"]
