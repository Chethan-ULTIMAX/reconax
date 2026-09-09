from unittest.mock import Mock

from reconax.models import CookieAnalysis, CORSAnalysis, CSPAnalysis, HeaderAnalysis, TLSAnalysis
from reconax.modules.score import ScoreModule


def test_score_is_normalized_to_100():
    context = Mock()
    context.headers_result.return_value = HeaderAnalysis(present={name: "x" for name in ("Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy")})
    context.cookies_result.return_value = CookieAnalysis()
    context.csp_result.return_value = CSPAnalysis(present=True)
    context.tls_result.return_value = TLSAnalysis(hostname="example.com", tls_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", hostname_match=True, days_remaining=100)
    context.cors_result.return_value = CORSAnalysis(allow_origin="https://example.com")
    result = ScoreModule(context).analyze()
    assert 0 <= result.score <= 100
    assert result.maximum == 100
    assert result.categories


def test_score_grade_matches_score():
    context = Mock()
    context.headers_result.return_value = HeaderAnalysis()
    context.cookies_result.return_value = CookieAnalysis()
    context.csp_result.return_value = CSPAnalysis()
    context.tls_result.return_value = TLSAnalysis(hostname="example.com")
    context.cors_result.return_value = CORSAnalysis()
    result = ScoreModule(context).analyze()
    assert result.grade == "Poor"
    assert result.verdict == "WARN"
