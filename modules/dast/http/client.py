from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.message import Message
from typing import Any, Callable, Mapping

from core.config.models import LimitsConfig

from modules.dast.http.rate_limit import RateLimiter
from modules.dast.http.summarize import summarize_request, summarize_response


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    body_text: str
    request_method: str
    request_url: str
    request_headers: dict[str, str]


_Opener = Callable[..., Any]


def _headers_from_message(msg: Message) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in msg.items():
        lk = key.lower()
        if lk in out:
            out[lk] = f"{out[lk]}, {value}"
        else:
            out[lk] = value
    return out


def _merge_headers(base: Mapping[str, str], extra: Mapping[str, str] | None) -> dict[str, str]:
    merged = {k: str(v) for k, v in base.items()}
    if extra:
        for k, v in extra.items():
            merged[str(k)] = str(v)
    return merged


@dataclass
class HttpClient:
    limits: LimitsConfig
    rate_limiter: RateLimiter
    timeout: float
    follow_redirects: bool = True
    default_headers: dict[str, str] = field(default_factory=dict)
    opener: _Opener | None = None
    requests_sent: int = 0

    def __post_init__(self) -> None:
        if self.opener is None:
            self.opener = urllib.request.urlopen

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> HttpResponse:
        self.rate_limiter.wait_turn()
        merged = _merge_headers(self.default_headers, headers)
        if "user-agent" not in {k.lower() for k in merged}:
            merged["User-Agent"] = "unif-appsec-dast/0.1"

        req = urllib.request.Request(url, data=body, headers=merged, method=method.upper())
        self.requests_sent += 1

        final_url = url
        try:
            resp = self.opener(req, timeout=self.timeout)  # type: ignore[misc]
            status = getattr(resp, "status", None) or resp.getcode()
            hdrs = _headers_from_message(resp.headers)
            raw = resp.read()
            if hasattr(resp, "geturl"):
                final_url = resp.geturl()
        except urllib.error.HTTPError as e:
            status = e.code
            hdrs = _headers_from_message(e.headers)
            raw = e.read()

        max_body = self.limits.max_response_body_bytes
        text = raw.decode("utf-8", errors="replace")
        if len(text.encode("utf-8")) > max_body:
            text = text.encode("utf-8")[: max_body - 30].decode("utf-8", errors="ignore") + "\n...[truncated]..."

        return HttpResponse(
            url=final_url,
            status_code=int(status),
            headers=hdrs,
            body_text=text,
            request_method=method.upper(),
            request_url=url,
            request_headers=dict(merged),
        )

    def summarize_pair(self, resp: HttpResponse) -> tuple[str, str]:
        req_s = summarize_request(
            resp.request_method,
            resp.request_url,
            resp.request_headers,
            None,
            max_bytes=self.limits.max_evidence_bytes,
        )
        res_s = summarize_response(
            resp.status_code,
            resp.headers,
            resp.body_text,
            max_bytes=self.limits.max_response_body_bytes,
        )
        return req_s, res_s


def with_query_param(url: str, name: str, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    q = [(k, v) for k, v in q if k != name]
    q.append((name, value))
    new_query = urllib.parse.urlencode(q, doseq=True)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def replace_path_param(url: str, param_name: str, value: str) -> str:
    """Replace first `{param}` or `:param` style segment (OpenAPI-style)."""
    parts = urllib.parse.urlsplit(url)
    path = parts.path
    for token in (f"{{{param_name}}}", f":{param_name}"):
        if token in path:
            path = path.replace(token, urllib.parse.quote(value, safe=""), 1)
            break
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))
