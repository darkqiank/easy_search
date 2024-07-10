class ClientSearchException(Exception):
    """Base exception class for duckduckgo_search."""


class RatelimitException(ClientSearchException):
    """Raised for rate limit exceeded errors during API requests."""


class TimeoutException(ClientSearchException):
    """Raised for timeout errors during API requests."""


class NotFoundException(ClientSearchException):
    """Raised for timeout errors during API requests."""
