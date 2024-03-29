import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from types import TracebackType
from typing import Dict, Optional, Union
from .exceptions import ClientSearchException, RatelimitException, TimeoutException
from curl_cffi import requests


logger = logging.getLogger("engines.AsyncClient")


class AsyncClient:
    _executor: Optional[ThreadPoolExecutor] = None

    def __init__(
        self,
        headers: Optional[Dict[str, str]] = None,
        proxies: Union[Dict[str, str], str, None] = None,
        timeout: Optional[int] = 10,
    ) -> None:
        self.proxies = {"all": proxies} if isinstance(proxies, str) else proxies
        self._asession = requests.AsyncSession(
            headers=headers,
            proxies=self.proxies,
            timeout=timeout,
            impersonate="chrome",
            allow_redirects=False,
        )
        # self._asession.headers["Referer"] = "https://duckduckgo.com/"
        self._exception_event = asyncio.Event()
        self._exit_done = False

    async def __aenter__(self) -> "AsyncClient":
        return self

    async def __aexit__(
        self,
        exc_type: Optional[BaseException] = None,
        exc_val: Optional[BaseException] = None,
        exc_tb: Optional[TracebackType] = None,
    ) -> None:
        await self._session_close()

    def __del__(self) -> None:
        if self._exit_done is False:
            asyncio.create_task(self._session_close())

    async def _session_close(self) -> None:
        """Close the curl-cffi async session."""
        if self._exit_done is False:
            await self._asession.close()
            self._exit_done = True

    def _get_executor(self, max_workers: int = 1) -> ThreadPoolExecutor:
        """Get ThreadPoolExecutor. Default max_workers=1, because >=2 leads to a big overhead"""
        if AsyncClient._executor is None:
            AsyncClient._executor = ThreadPoolExecutor(max_workers=max_workers)
        return AsyncClient._executor

    async def _aget_url(
        self,
        method: str,
        url: str,
        data: Optional[Union[Dict[str, str], bytes]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> bytes:
        if self._exception_event.is_set():
            raise ClientSearchException("Exception occurred in previous call.")
        try:
            resp = await self._asession.request(method, url, data=data, params=params, stream=True)
            resp_content: bytes = await resp.acontent()
        except Exception as ex:
            self._exception_event.set()
            if "time" in str(ex).lower():
                raise TimeoutException(f"{url} {type(ex).__name__}: {ex}") from ex
            raise ClientSearchException(f"{url} {type(ex).__name__}: {ex}") from ex
        # logger.debug(f"_aget_url() {resp.url} {resp.status_code} {resp.elapsed:.2f} {len(resp_content)}")
        print(f"_aget_url() {resp.url} {resp.status_code} {resp.elapsed:.2f} {len(resp_content)}")
        if resp.status_code in (200, 302):
            return resp_content
        self._exception_event.set()
        if resp.status_code in (202, 301, 403):
            raise RatelimitException(f"{resp.url} {resp.status_code}")
        raise ClientSearchException(f"{resp.url} {resp.status_code} return None. {params=} {data=}")