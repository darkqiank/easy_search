from engines.client import Client
from lxml import etree
from urllib.parse import urlparse, parse_qs
from engines.exceptions import ClientSearchException
from typing import Dict, List, Optional, Any
import asyncio
from itertools import islice
from engines.utils import _normalize, _normalize_url, json_loads


class DDGS(Client):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._asession.headers["Referer"] = "https://duckduckgo.com/"

    def text(self, *args: Any, **kwargs: Any) -> Any:
        return self._run_async_in_thread(self._text_api(*args, **kwargs))

    async def _get_preload_params(self, keywords: str, payload: dict) -> dict:
        """Get vqd value for a search query."""
        resp_content = await self._aget_url("GET", "https://duckduckgo.com",
                                            params=payload)
        # 解析HTML字符串
        tree = etree.HTML(resp_content)
        href = tree.xpath('//*[@id="deep_preload_link"]/@href')
        # 如果找到了href属性，它会被包含在一个列表中。检查列表不为空，然后获取第一个元素。
        if href:
            href_value = href[0]
            # 解析URL
            parsed_url = urlparse(href_value)
            # 使用parse_qs函数从解析后的URL中提取查询参数
            query_params = parse_qs(parsed_url.query)

            # parse_qs默认将每个参数的值放在列表中，因为同一个参数名可能对应多个值
            # 如果你知道每个参数只会出现一次，可以转换为单值
            query_params_single_value = {k: v[0] for k, v in query_params.items()}
            return query_params_single_value
        else:
            raise ClientSearchException(f"_get_preload_link() {keywords=} Could not extract preload_link.")

    async def _text_api(
        self,
        keywords: str,
        region: str = "wt-wt",
        safesearch: str = "moderate",
        timelimit: Optional[str] = None,
        max_results: Optional[int] = None,
    ) -> List[Dict[str, str]]:
        assert keywords, "keywords is mandatory"

        payload = {
            "q": keywords,
            "kl": region,
            "l": region,
            "p": "",
            "s": "0",
            "df": "",
            "ex": "",
        }

        safesearch = safesearch.lower()
        if safesearch == "moderate":
            payload["ex"] = "-1"
        elif safesearch == "off":
            payload["ex"] = "-2"
        elif safesearch == "on":  # strict
            payload["p"] = "1"
        if timelimit:
            payload["df"] = timelimit

        preload_params = await self._get_preload_params(keywords, payload)

        cache = set()
        results: List[Optional[Dict[str, str]]] = [None] * 1100

        async def _text_api_page(s: int, page: int, params: dict) -> None:
            priority = page * 100
            params["s"] = f"{s}"
            # print(payload)
            resp_content = await self._aget_url("GET", "https://links.duckduckgo.com/d.js", params=params)
            page_data = _text_extract_json(resp_content, keywords)

            for row in page_data:
                href = row.get("u", None)
                if href and href not in cache and href != f"http://www.google.com/search?q={keywords}":
                    cache.add(href)
                    body = _normalize(row["a"])
                    if body:
                        priority += 1
                        result = {
                            "title": _normalize(row["t"]),
                            "href": _normalize_url(href),
                            "body": body,
                        }
                        results[priority] = result

        tasks = [_text_api_page(0, 0, preload_params)]
        if max_results:
            max_results = min(max_results, 500)
            tasks.extend(_text_api_page(s, i, preload_params) for i, s in enumerate(range(23, max_results, 50), start=1))
        await asyncio.gather(*tasks)

        return list(islice(filter(None, results), max_results))


def _text_extract_json(html_bytes: bytes, keywords: str) -> List[Dict[str, str]]:
    """text(backend="api") -> extract json from html."""
    try:
        start = html_bytes.index(b"DDG.pageLayout.load('d',") + 24
        end = html_bytes.index(b");DDG.duckbar.load(", start)
        data = html_bytes[start:end]
        result: List[Dict[str, str]] = json_loads(data)
        return result
    except Exception as ex:
        raise ClientSearchException(f"_text_extract_json() {keywords=} {type(ex).__name__}: {ex}") from ex