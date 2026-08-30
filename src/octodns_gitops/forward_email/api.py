"""Minimal Forward Email REST client (stdlib only, injectable transport).

Listing safety: every list call pages explicitly with `page`/`limit` until a page comes
back shorter than `limit`. No total, header count or `count` field is ever trusted — a
truncated listing is what makes a prune delete live aliases.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

BASE_URL = "https://api.forwardemail.net"

# transport(method, url, headers, body_dict_or_None) -> (status, decoded_json_or_None)
Transport = Callable[[str, str, dict, dict | None], tuple[int, object]]


class ForwardEmailApiError(RuntimeError):
    """Non-2xx response from the API."""

    def __init__(self, status: int, message: str, method: str, url: str):
        super().__init__(f"{method} {url} -> {status}: {message}")
        self.status = status


def urllib_transport(method: str, url: str, headers: dict, body: dict | None) -> tuple[int, object]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    if not raw:
        return status, None
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, {"message": raw.decode(errors="replace")[:200]}


class ForwardEmailClient:
    def __init__(
        self,
        token: str,
        transport: Transport = urllib_transport,
        base_url: str = BASE_URL,
        page_size: int = 100,
    ):
        self._transport = transport
        self._base = base_url.rstrip("/")
        self._page_size = page_size
        cred = base64.b64encode(f"{token}:".encode()).decode()
        self._headers = {"Authorization": f"Basic {cred}", "Accept": "application/json"}

    # -- plumbing -----------------------------------------------------------------

    def _call(self, method: str, path: str, body: dict | None = None, params: dict | None = None):
        url = f"{self._base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = dict(self._headers)
        if body is not None:
            headers["Content-Type"] = "application/json"
        status, payload = self._transport(method, url, headers, body)
        if not 200 <= status < 300:
            msg = payload.get("message") if isinstance(payload, dict) else str(payload)
            raise ForwardEmailApiError(status, msg or "", method, url)
        return payload

    def _paged(self, path: str) -> list[dict]:
        out: list[dict] = []
        page = 1
        while True:
            chunk = self._call("GET", path, params={"page": page, "limit": self._page_size})
            if not isinstance(chunk, list):
                raise ForwardEmailApiError(200, f"expected a list from {path}", "GET", path)
            out.extend(chunk)
            if len(chunk) < self._page_size:
                return out
            page += 1

    @staticmethod
    def _d(domain: str) -> str:
        return urllib.parse.quote(domain, safe="")

    # -- reads --------------------------------------------------------------------

    def list_domains(self) -> list[dict]:
        return self._paged("/v1/domains")

    def get_domain(self, domain: str) -> dict:
        return self._call("GET", f"/v1/domains/{self._d(domain)}")

    def list_aliases(self, domain: str) -> list[dict]:
        return self._paged(f"/v1/domains/{self._d(domain)}/aliases")

    # -- writes -------------------------------------------------------------------

    def update_domain(self, domain: str, body: dict) -> dict:
        return self._call("PUT", f"/v1/domains/{self._d(domain)}", body=body)

    def create_alias(self, domain: str, body: dict) -> dict:
        return self._call("POST", f"/v1/domains/{self._d(domain)}/aliases", body=body)

    def update_alias(self, domain: str, alias_id: str, body: dict) -> dict:
        return self._call("PUT", f"/v1/domains/{self._d(domain)}/aliases/{alias_id}", body=body)

    def delete_alias(self, domain: str, alias_id: str) -> None:
        self._call("DELETE", f"/v1/domains/{self._d(domain)}/aliases/{alias_id}")
