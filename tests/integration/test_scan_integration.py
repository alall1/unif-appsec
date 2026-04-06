from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from core.config.loader import load_resolved_config
from core.config.models import ScanTarget
from core.exports.json_writer import prepare_aggregate_for_export
from core.orchestration.planner import inferred_module_names, planned_module_names
from core.orchestration.runner import run_scan
from core.plugins.registry import PluginRegistry
from modules.dast.plugin import HttpDastPlugin
from modules.sast.plugin import PythonSastPlugin


@pytest.fixture
def cmd_injection_fixture() -> Path:
    p = Path("modules/sast/fixtures/vulnerable/cmd_injection.py").resolve()
    assert p.is_file(), f"missing fixture: {p}"
    return p


def test_planned_modules_inference_explicit_empty_respected() -> None:
    cfg = load_resolved_config(
        None,
        {"config_version": "1", "scan": {"modules": [], "profile": "balanced"}},
    )
    assert planned_module_names(cfg, ScanTarget(path=Path("."))) == []


def test_planned_modules_inference_from_path_only() -> None:
    cfg = load_resolved_config(None, {"config_version": "1", "scan": {"profile": "balanced"}})
    p = Path("modules/sast/fixtures/vulnerable").resolve()
    assert planned_module_names(cfg, ScanTarget(path=p)) == ["python_sast"]


def test_inferred_module_names_path_and_config_dast_url() -> None:
    cfg = load_resolved_config(
        None,
        {
            "config_version": "1",
            "scan": {"profile": "balanced"},
            "dast": {"target_url": "http://127.0.0.1:9/"},
        },
    )
    names = inferred_module_names(ScanTarget(path=Path(".")), cfg)
    assert names == ["python_sast", "http_dast"]


def test_sast_scan_json_envelope_and_stable_fingerprint_order(cmd_injection_fixture: Path) -> None:
    reg = PluginRegistry()
    reg.register(PythonSastPlugin())
    cfg = load_resolved_config(
        None,
        {
            "config_version": "1",
            "scan": {"modules": ["python_sast"], "profile": "fast"},
            "policies": {"fail_on_severity": "critical", "confidence_threshold": "low"},
        },
    )
    result, code = run_scan(reg, cfg, ScanTarget(path=cmd_injection_fixture))
    assert code in (0, 1, 2)
    payload = prepare_aggregate_for_export(result, cfg.limits)
    assert payload["scan_result_schema_version"] == "1.0.0"
    assert isinstance(payload["findings"], list)
    assert isinstance(payload["module_results"], list)
    assert len(payload["module_results"]) == 1
    assert payload["module_results"][0]["module"] == "python_sast"
    for f in payload["findings"]:
        assert f["fingerprint"].startswith("fp1:")
        assert len(f["fingerprint"]) == 4 + 64
        assert f["status"] in ("open", "suppressed")
    fps = [f["fingerprint"] for f in payload["findings"]]
    assert fps == sorted(fps)


class _QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Server", "integration-test")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><a href=\"/x\">x</a></body></html>")

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return


def test_dast_local_server_envelope() -> None:
    server = HTTPServer(("127.0.0.1", 0), _QuietHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        reg = PluginRegistry()
        reg.register(HttpDastPlugin())
        url = f"http://127.0.0.1:{port}/"
        cfg = load_resolved_config(
            None,
            {
                "config_version": "1",
                "scan": {"modules": ["http_dast"], "profile": "fast"},
                "dast": {
                    "target_url": url,
                    "crawl": {"enabled": False},
                },
                "policies": {"fail_on_severity": "critical", "confidence_threshold": "low"},
            },
        )
        result, code = run_scan(reg, cfg, ScanTarget(url=url))
        assert code in (0, 1, 2)
        payload = prepare_aggregate_for_export(result, cfg.limits)
        assert payload["scan_result_schema_version"]
        assert len(payload["module_results"]) == 1
        assert payload["module_results"][0]["module"] == "http_dast"
        fps = [f["fingerprint"] for f in payload["findings"]]
        assert fps == sorted(fps)
        for f in payload["findings"]:
            assert f["engine"] == "dast"
            assert f["location_type"] == "http"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_combined_sast_and_dast_partial_results(cmd_injection_fixture: Path) -> None:
    server = HTTPServer(("127.0.0.1", 0), _QuietHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        reg = PluginRegistry()
        reg.register(PythonSastPlugin())
        reg.register(HttpDastPlugin())
        url = f"http://127.0.0.1:{port}/"
        cfg = load_resolved_config(
            None,
            {
                "config_version": "1",
                "scan": {"modules": ["python_sast", "http_dast"], "profile": "fast"},
                "dast": {"target_url": url, "crawl": {"enabled": False}},
                "policies": {"fail_on_severity": "critical", "confidence_threshold": "low"},
            },
        )
        target = ScanTarget(path=cmd_injection_fixture, url=url)
        result, code = run_scan(reg, cfg, target)
        assert code in (0, 1, 2)
        mods = {m["module"] for m in result.to_export_dict()["module_results"]}
        assert mods == {"python_sast", "http_dast"}
        assert any(f.module == "python_sast" for f in result.findings)
        raw = json.dumps(prepare_aggregate_for_export(result, cfg.limits), sort_keys=True)
        json.loads(raw)
    finally:
        server.shutdown()
        thread.join(timeout=5)
