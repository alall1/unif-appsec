from __future__ import annotations

from core.config.models import LimitsConfig

from modules.dast.http.client import replace_path_param, with_query_param


def test_with_query_param_sorting_stable() -> None:
    u = "https://ex.test/a?z=1&a=2"
    u2 = with_query_param(u, "q", "v")
    assert "a=2" in u2
    assert "q=v" in u2


def test_replace_path_param() -> None:
    u = "https://ex.test/items/{itemId}/x"
    assert "7" in replace_path_param(u, "itemId", "7")


def test_limits_defaults() -> None:
    lim = LimitsConfig()
    assert lim.max_response_body_bytes >= 1024
