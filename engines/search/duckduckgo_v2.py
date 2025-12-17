from engines.client import Client
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

from engines.random_tools import random_impersonate, generate_random_public_ip

from collections.abc import Mapping
from typing import Any, ClassVar, TypeVar
from lxml import html
from lxml.etree import HTMLParser as LHTMLParser

T = TypeVar("T")

class DDGS_V2(Client):

    def __init__(self, *args, **kwargs):
        end_point = kwargs.pop('ddgs_end_point', 'https://html.duckduckgo.com')
        kwargs.pop('ddgslink_end_point', None)
        self.ddgs_end_point = urljoin(end_point.rstrip('/') + '/', 'html/')
        super().__init__(*args, **kwargs)
        self.items_xpath = "//div[contains(@class, 'body')]"
        self.elements_xpath: ClassVar[Mapping[str, str]] = {"title": ".//h2//text()", "href": "./a/@href", "body": "./a//text()"}

    def text(self, *args: Any, **kwargs: Any) -> Any:
        return self._run_async_in_thread(self._text_api(*args, **kwargs))


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
            "b": "",
            "l": region
        }
        impersonate, headers = random_ddgs_ua_headers()

        resp_content = await self._aget_url("POST", self.ddgs_end_point,
                                    impersonate=impersonate,
                                    headers=headers,
                                    params=payload)
        return self.extract_results(resp_content)

    def parser(self) -> LHTMLParser:
        """Get HTML parser."""
        return LHTMLParser(remove_blank_text=True, remove_comments=True, remove_pis=True, collect_ids=False)

    def extract_tree(self, html_text: str) -> html.Element:
        """Extract html tree from html text."""
        return html.fromstring(html_text, parser=self.parser())

    def pre_process_html(self, html_text: str) -> str:
        """Pre-process html_text before extracting results."""
        return html_text

    def extract_results(self, html_text: str) -> list[T]:
        """Extract search results from html text."""
        html_text = self.pre_process_html(html_text)
        tree = self.extract_tree(html_text)
        items = tree.xpath(self.items_xpath)
        results = []
        for item in items:
            result = {"title": "", "href": "", "body": ""}
            for key, value in self.elements_xpath.items():
                data = " ".join(x.strip() for x in item.xpath(value))
                result[key] = data
            results.append(result)
        return results


def random_ddgs_ua_headers():
    impersonate, ua_headers = random_impersonate()
    fake_ip = generate_random_public_ip()
    ua_headers["X-Forwarded-For"] = fake_ip
    ua_headers["X-Real-IP"] = fake_ip
    ua_headers["X-Forwarded-Host"] = "https://duckduckgo.com"
    return impersonate, ua_headers