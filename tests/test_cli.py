from typer.testing import CliRunner

from reconax.cli import app


runner = CliRunner()


def test_cli_help_works():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "analyze" in result.stdout
    assert "headers" in result.stdout


def test_cli_exposes_analysis_commands():
    result = runner.invoke(app, ["--help"])
    for command in ("cookies", "html", "robots", "dns", "tls", "tech", "sitemap", "cors", "csp", "sri", "security-txt", "metadata", "resources", "endpoints", "attack-surface", "score"):
        assert command in result.stdout
