from unittest.mock import Mock

from reconax.modules.tls import TLSModule


def test_tls_target_parsing():
    context = Mock()
    context.normalized_url = "https://example.com:8443/path"
    context.timeout = 5.0
    module = TLSModule(context)
    assert module._get_target() == ("example.com", 8443)


def test_tls_helpers_parse_certificate():
    cert = {
        "subject": [[("commonName", "example.com")]],
        "issuer": [[("organizationName", "Example CA")]],
        "subjectAltName": [
            ("DNS", "example.com"),
            ("DNS", "www.example.com"),
        ],
    }
    assert TLSModule._name_attributes(cert, "subject")["commonName"] == "example.com"
    assert TLSModule._name_attributes(cert, "issuer")["organizationName"] == "Example CA"
    assert TLSModule._subject_alt_names(cert) == ["example.com", "www.example.com"]


def test_tls_analysis_does_not_depend_on_ssl_match_hostname(monkeypatch):
    certificate = {
        "subject": [[("commonName", "example.com")]],
        "issuer": [[("organizationName", "Example CA")]],
        "subjectAltName": [("DNS", "example.com")],
        "serialNumber": "1234",
        "notBefore": "Jan 01 00:00:00 2026 GMT",
        "notAfter": "Jan 01 00:00:00 2027 GMT",
    }

    class FakeTLSSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def getpeercert(self):
            return certificate

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def version(self):
            return "TLSv1.3"

    class FakeSSLContext:
        def wrap_socket(self, raw_socket, server_hostname):
            assert server_hostname == "example.com"
            return FakeTLSSocket()

    monkeypatch.setattr(
        "reconax.modules.tls.socket.create_connection",
        lambda address, timeout: Mock(),
    )
    monkeypatch.setattr(
        "reconax.modules.tls.ssl.create_default_context",
        lambda: FakeSSLContext(),
    )

    context = Mock()
    context.normalized_url = "https://example.com/"
    context.timeout = 5.0

    result = TLSModule(context).analyze()

    assert result.hostname == "example.com"
    assert result.tls_version == "TLSv1.3"
    assert result.hostname_match is True
    assert result.error is None
