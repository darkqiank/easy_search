from engines.client import Client
from lxml import etree
from typing import Dict, List, Optional, Any
from fastapi.responses import HTMLResponse
from engines.utils import _normalize, _normalize_url, json_loads
from engines.exceptions import ClientSearchException


class GITHUB(Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._asession.headers["Referer"] = "https://github.com/"

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
            "type": "repositories",
        }
        resp_content = await self._aget_url("GET", "https://github.com/search", params=params)
        # print(resp_content.decode('utf-8'))
        # 解析HTML
        return HTMLResponse(resp_content)

        html = etree.HTML(resp_content.decode('utf-8'))
        # 用于存储提取的数据
        # extracted_data = []
        if html is not None:
            embeddedData = html.xpath('//script[@data-target="react-app.embeddedData"]/text()')
            extracted_data = json_loads(_normalize(embeddedData[0])) if embeddedData else None
            return extracted_data.get('payload', {}).get('result')
        else:
            raise ClientSearchException("Search result is None!")
