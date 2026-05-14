from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Header:
    name: str
    value: str


@dataclass
class Cookie:
    name: str
    value: str
    domain: str = ''
    path: str = '/'
    secure: bool = False
    http_only: bool = False


@dataclass
class Token:
    token_type: str
    value: str
    source: str


@dataclass
class Request:
    method: str
    url: str
    headers: list[Header] = field(default_factory=list)
    cookies: list[Cookie] = field(default_factory=list)
    body: str = ''


@dataclass
class Response:
    status_code: int
    headers: list[Header] = field(default_factory=list)
    body: str = ''


@dataclass
class Session:
    session_id: str
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


def headers_from_dict(items: dict[str, str]) -> list[Header]:
    return [Header(name=k, value=v) for k, v in items.items()]
