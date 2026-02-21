"""Tiny local TestClient shim."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI


@dataclass
class _Response:
    status_code: int
    _body: dict[str, Any]

    def json(self) -> dict[str, Any]:
        return self._body


class TestClient:
    __test__ = False

    def __init__(self, app: FastAPI) -> None:
        self.app = app

    def __enter__(self) -> TestClient:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    def post(
        self,
        path: str,
        json: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> _Response:
        route = self.app.routes[("POST", path)]
        payload = dict(json)
        if headers:
            payload["_headers"] = headers
        body = route.handler(payload)
        status_code = int(body.get("_status_code", 200))
        body.pop("_status_code", None)
        return _Response(status_code=status_code, _body=body)
