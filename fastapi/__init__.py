"""Tiny local FastAPI-compatible shim for offline deterministic tests."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class Route:
    method: str
    path: str
    handler: Callable[[dict[str, Any]], dict[str, Any]]


PostHandler = Callable[[dict[str, Any]], dict[str, Any]]
PostDecorator = Callable[[PostHandler], PostHandler]


class FastAPI:
    def __init__(self, title: str = "App") -> None:
        self.title = title
        self.routes: dict[tuple[str, str], Route] = {}

    def post(self, path: str) -> PostDecorator:
        def decorator(func: PostHandler) -> PostHandler:
            self.routes[("POST", path)] = Route(method="POST", path=path, handler=func)
            return func

        return decorator
