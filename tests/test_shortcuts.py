from unittest.mock import Mock

from reconax import shortcuts


def test_shortcut_delegates_to_reconax(monkeypatch):
    fake = Mock()
    fake.headers.return_value = "ok"
    fake.close.return_value = None

    constructor = Mock(return_value=fake)
    monkeypatch.setattr(shortcuts, "ReconAx", constructor)

    result = shortcuts.headers("example.com", timeout=3, verify_ssl=False)
    assert result == "ok"
    constructor.assert_called_once_with("example.com", timeout=3, verify_ssl=False)
    fake.headers.assert_called_once_with()
    fake.close.assert_called_once_with()


def test_all_shortcuts_are_callable():
    for name in ("analyze", "headers", "cookies", "html", "robots", "dns", "tls", "tech", "sitemap", "cors", "csp", "sri", "security_txt", "metadata", "resources", "endpoints", "attack_surface", "score"):
        assert callable(getattr(shortcuts, name))
