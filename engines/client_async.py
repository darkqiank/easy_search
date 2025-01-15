import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from types import TracebackType
from typing import Dict, Optional, Union

from cffi.commontypes import resolve_common_type

from .exceptions import ClientSearchException, RatelimitException, TimeoutException, NotFoundException
from curl_cffi import requests
import gzip
import io

logger = logging.getLogger("engines.AsyncClient")


class AsyncClient:
    _executor: Optional[ThreadPoolExecutor] = None

    def __init__(
        self,
        headers: Optional[Dict[str, str]] = None,
        proxies: Union[Dict[str, str], str, None] = None,
        timeout: Optional[int] = 10
    ) -> None:
        self.proxies = {"all": proxies} if isinstance(proxies, str) else proxies
        self._asession = requests.AsyncSession(
            headers=headers,
            proxies=self.proxies,
            timeout=timeout,
            impersonate="chrome",
            allow_redirects=False,
            verify=False
        )
        self._exception_event = asyncio.Event()
        # self._exit_done = False

    async def __aenter__(self) -> "AsyncClient":
        return self

    async def __aexit__(
        self,
        exc_type: Optional[BaseException] = None,
        exc_val: Optional[BaseException] = None,
        exc_tb: Optional[TracebackType] = None,
    ) -> None:
        # await self._session_close()
        await self._asession.__aexit__(exc_type, exc_val, exc_tb)  # type: ignore

    def __del__(self) -> None:
        if hasattr(self, "_asession") and self._asession._closed is False:
            with suppress(RuntimeError, RuntimeWarning):
                asyncio.create_task(self._asession.close())  # type: ignore
        # if self._exit_done is False:
        #     asyncio.create_task(self._session_close())

    @classmethod
    def _get_executor(cls, max_workers: int = 1) -> ThreadPoolExecutor:
        """Get ThreadPoolExecutor. Default max_workers=1, because >=2 leads to a big overhead"""
        if cls._executor is None:
            cls._executor = ThreadPoolExecutor(max_workers=max_workers)
        return cls._executor

    @property
    def executor(cls) -> Optional[ThreadPoolExecutor]:
        return cls._get_executor()

    async def _aget_url(
        self,
            *args, **kwargs
    ) -> bytes:
        try:
            resp = await self._asession.request(*args, **kwargs)
            if resp.headers.get('Content-Encoding') == 'gzip':
                with gzip.GzipFile(fileobj=io.BytesIO(resp.content)) as decompressed_file:
                    resp_content = decompressed_file.read()
            else:
                resp_content: bytes = resp.content
        except Exception as ex:
            if "time" in str(ex).lower():
                raise TimeoutException(f"{type(ex).__name__}: {ex}") from ex
            raise ClientSearchException(f"{type(ex).__name__}: {ex}") from ex
        print(f"_aget_url() {resp.url} {resp.status_code} {resp.elapsed:.2f} {len(resp_content)}")
        if resp.status_code in (200, 302):
            return resp_content
        if resp.status_code in (202, 301, 403, 429):
            raise RatelimitException(f"{resp.url} {resp.status_code}")
        if resp.status_code in (404,):
            raise NotFoundException(f"{resp.url} {resp.status_code} not Found")
        raise ClientSearchException(f"{resp.url} {resp.status_code} return None.")

    async def _aget_url_stream(
        self,
            *args, **kwargs
    ) -> bytes:
        if self._exception_event.is_set():
            raise ClientSearchException("Exception occurred in previous call.")
        try:
            resp = await self._asession.request(*args, **kwargs)
            # resp = await self._asession.request(method, url, data=data, params=params, stream=True, headers=headers)
            resp_content: bytes = await resp.acontent()
        except Exception as ex:
            self._exception_event.set()
            if "time" in str(ex).lower():
                raise TimeoutException(f"{type(ex).__name__}: {ex}") from ex
            raise ClientSearchException(f"{type(ex).__name__}: {ex}") from ex
        # logger.debug(f"_aget_url() {resp.url} {resp.status_code} {resp.elapsed:.2f} {len(resp_content)}")
        print(f"_aget_url() {resp.url} {resp.status_code} {resp.elapsed:.2f} {len(resp_content)}")
        if resp.status_code in (200, 302):
            return resp_content
        self._exception_event.set()
        if resp.status_code in (202, 301, 403, 429):
            raise RatelimitException(f"{resp.url} {resp.status_code}")
        if resp.status_code in (404,):
            raise NotFoundException(f"{resp.url} {resp.status_code} not Found")
        raise ClientSearchException(f"{resp.url} {resp.status_code} return None.")