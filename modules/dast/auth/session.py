from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from modules.dast.http.client import HttpResponse


@dataclass(frozen=True)
class ReauthHookPlaceholder:
    """V1: optional config key `auth.reauth_hook` is accepted and ignored except for warnings.

    Future versions may load a callable or subprocess hook to refresh tokens.
    """

    configured_path: str | None


@dataclass
class AuthSession:
    static_headers: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    cookies: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.static_headers = dict(self.static_headers)
        self.cookies = dict(self.cookies)

    def request_headers(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        h = dict(self.static_headers)
        if self.bearer_token:
            h["Authorization"] = f"Bearer {self.bearer_token}"
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in sorted(self.cookies.items()))
        if extra:
            for k, v in extra.items():
                h[str(k)] = str(v)
        return h

    def absorb_set_cookie(self, resp: HttpResponse) -> None:
        raw = resp.headers.get("set-cookie")
        if not raw:
            return
        # First cookie pair only (V1); multiple Set-Cookie not fully modeled
        part = raw.split(";")[0].strip()
        if "=" in part:
            name, val = part.split("=", 1)
            self.cookies[name.strip()] = val.strip()
