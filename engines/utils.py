import re
from html import unescape
from typing import Any, Dict, List, Union
from urllib.parse import unquote
import orjson
from .exceptions import ClientSearchException

REGEX_STRIP_TAGS = re.compile("<.*?>")


def json_dumps(obj: Any) -> str:
    try:
        return orjson.dumps(obj).decode("utf-8")
    except Exception as ex:
        raise ClientSearchException(f"{type(ex).__name__}: {ex}") from ex


def json_loads(obj: Union[str, bytes]) -> Any:
    try:
        return orjson.loads(obj)
    except Exception as ex:
        raise ClientSearchException(f"{type(ex).__name__}: {ex}") from ex


def _normalize(raw_html: str) -> str:
    """Strip HTML tags from the raw_html string."""
    return unescape(REGEX_STRIP_TAGS.sub("", raw_html)) if raw_html else ""


def _normalize_url(url: str) -> str:
    """Unquote URL and replace spaces with '+'."""
    return unquote(url.replace(" ", "+")) if url else ""
