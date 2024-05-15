import logging

from .client import Client
from .client_async import AsyncClient
from engines.search.duckduckgo import DDGS
from engines.search.bing import BING
from engines.search.github import GITHUB

__all__ = ["Client", "AsyncClient", "DDGS", "BING", "GITHUB"]

logging.getLogger("engines").addHandler(logging.NullHandler())