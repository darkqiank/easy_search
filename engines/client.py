import asyncio
from concurrent.futures import Future
from threading import Thread
from types import TracebackType
from typing import Any, Awaitable, Dict, Optional, Type, Union
from .client_async import AsyncClient


class Client(AsyncClient):
    _loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
    Thread(target=_loop.run_forever, daemon=True).start()  # Start the event loop run in a separate thread.

    def __init__(
            self,
            headers: Optional[Dict[str, str]] = None,
            proxies: Union[Dict[str, str], str, None] = None,
            timeout: Optional[int] = 10,
            retries: Optional[int] = 3,
            delay: Optional[int] = 1,
            backoff: Optional[int] = 2
    ) -> None:
        self._exit_done = False  # 确保最先设置此属性
        super().__init__(headers=headers, proxies=proxies, timeout=timeout,
                         retries=retries, delay=delay, backoff=backoff
                         )

    def __enter__(self) -> "Client":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self._close_session()

    def __del__(self) -> None:
        self._close_session()

    def _close_session(self) -> None:
        """Close the curl-cffi async session."""
        if self._exit_done is False:
            self._run_async_in_thread(self._asession.close())
            self._exit_done = True

    def _run_async_in_thread(self, coro: Awaitable[Any]) -> Any:
        """Runs an async coroutine in a separate thread."""
        future: Future[Any] = asyncio.run_coroutine_threadsafe(coro, self._loop)
        result = future.result()
        return result