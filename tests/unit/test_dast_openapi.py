from __future__ import annotations

from pathlib import Path

from modules.dast.discovery.openapi import endpoints_from_openapi


def test_openapi_expands_path_and_parameters() -> None:
    p = Path(__file__).resolve().parents[2] / "modules" / "dast" / "fixtures" / "minimal_openapi.json"
    eps = endpoints_from_openapi(p, "https://fallback.example/")
    assert len(eps) == 1
    ep = eps[0]
    assert ep.method == "GET"
    assert "{itemId}" in ep.url or "itemId" in ep.url
    names = {(x.name, x.location) for x in ep.insertion_points}
    assert ("itemId", "path") in names
    assert ("q", "query") in names
