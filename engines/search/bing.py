from engines.client import Client
from lxml import etree
from typing import Dict, List, Optional, Any
from fastapi.responses import HTMLResponse
from engines.utils import _normalize, _normalize_url, json_loads


class BING(Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._asession.headers["Referer"] = "https://www.bing.com/"
        self._asession.headers["Accept-Language"] = "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"

    def text(self, *args: Any, **kwargs: Any) -> Any:
        return self._run_async_in_thread(self._text_api(*args, **kwargs))

    async def _text_api(
            self,
            keywords: str
    ) -> Any:
        # -> HTMLResponse
        # -> List[Dict[str, str]]:
        assert keywords, "keywords is mandatory"

        params = {
            "q": keywords,
            "setmkt": "wt-wt",
            # "mkt" : "wt-wt",
            # "mkt": "zh-CN"
        }
        resp_content = await self._aget_url("GET", "https://www.bing.com/search", params=params)
        # 解析HTML
        # return HTMLResponse(resp_content)

        html = etree.HTML(resp_content.decode('utf-8'))
        # 用于存储提取的数据
        extracted_data = []
        items = html.xpath('//li[contains(@class, "b_algo")]')
        # print(items)
        for item in items:
            # 提取标题
            title = item.xpath('.//h2[1]//text()')
            # 提取网站地址
            href = item.xpath('.//a[@class="tilk"]/@href')
            # 提取简述
            # body = item.xpath('.//div[@class="b_lineclamp4 b_algoSlug"]/text()')
            body = item.xpath('.//p[starts-with(@class, "b_lineclamp")]/text()')

            # 将提取的数据存储为字典
            data = {
                "title": _normalize(title[0]) if title else "标题缺失",
                "href": _normalize_url(href[0]) if href else "链接缺失",
                "body": _normalize(body[0]).strip() if body else "简述缺失",
            }

            extracted_data.append(data)

        return extracted_data

        # results = []
        #
        # async def _text_api_page() -> None:
        #     resp_content = await self._aget_url("GET", "https://cn.bing.com/search", params=params)
        #     results.append(resp_content)
        #
        # tasks = [_text_api_page()]
        # await asyncio.gather(*tasks)
        # return results
