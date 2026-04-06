from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

from core.config.loader import load_resolved_config
from core.config.models import ScanTarget
from core.findings.normalize import normalize_finding
from core.orchestration.runner import resolve_scan_root
from core.plugins.base import ScanContext

from modules.dast.plugin import HttpDastPlugin


class _FakeResp:
    def __init__(self, url: str, code: int, hdrs: dict[str, str], body: bytes) -> None:
        self._url = url
        self._body = body
        self.status = code
        self.headers = EmailMessage()
        for k, v in hdrs.items():
            self.headers[k] = v

    def read(self) -> bytes:
        return self._body

    def geturl(self) -> str:
        return self._url

    def getcode(self) -> int:
        return self.status


def _fake_urlopen(req, timeout=None):  # noqa: ANN001
    u = req.full_url
    return _FakeResp(
        u,
        200,
        {"Content-Type": "text/html"},
        b"<html><body>ok</body></html>",
    )


def test_plugin_validate_rejects_missing_url() -> None:
    plugin = HttpDastPlugin()
    cfg = load_resolved_config(
        None,
        {"scan": {"modules": ["http_dast"], "profile": "fast"}, "dast": {"crawl": {"enabled": False}}},
    )
    errs = plugin.validate_target(ScanTarget(), cfg)
    assert errs


def test_plugin_scan_returns_findings_with_stable_fingerprint() -> None:
    plugin = HttpDastPlugin()
    cfg = load_resolved_config(
        None,
        {
            "scan": {"modules": ["http_dast"], "profile": "fast"},
            "dast": {"target_url": "https://fixture.test/app", "crawl": {"enabled": False}},
        },
    )
    target = ScanTarget(url="https://fixture.test/app")
    log = __import__("logging").getLogger("test")
    root = resolve_scan_root(target)
    ctx = ScanContext(
        logger=log,
        scan_root=root,
        limits=cfg.limits,
        policies=cfg.policies,
        module_config=dict(cfg.dast),
        deadline_monotonic=None,
    )
    with patch("modules.dast.http.client.urllib.request.urlopen", side_effect=_fake_urlopen):
        result = plugin.scan(target, cfg, ctx)
    assert not result.errors
    assert result.metrics.requests_sent is not None
    assert result.metrics.requests_sent >= 1
    assert result.findings
    nf = normalize_finding(result.findings[0], root)
    assert nf.fingerprint.startswith("fp1:")
    assert len(nf.fingerprint) == 4 + 64
