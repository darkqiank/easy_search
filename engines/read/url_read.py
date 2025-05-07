from engines.client import Client
import asyncio
from readability import Document
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse

class URLRead(Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _get_base_url(self, url: str) -> str:
        """获取基础URL（只保留协议和域名）"""
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))

    def read_sync(self, urls: list):
        return self._run_async_in_thread(self.read(urls))

    async def read(self, urls: list):
        combined_results = {}

        async def _read(url: str):
            try:
                print(f"Reading {url}")
                response = await self._aget_url("GET", url)
                response_str = response.decode('utf-8')
                base_url = self._get_base_url(url)
                content_data = self._read_html(response_str, base_url=base_url)
                combined_results[url] = content_data
            except Exception as e:
                print(f"Error reading {url}: {e}")

        tasks = [_read(url) for url in urls]
        await asyncio.gather(*tasks)
        return combined_results
    
    def _read_html(self, html: str, base_url: str = None):
        # 先用 BeautifulSoup 解析原始 HTML
        soup = BeautifulSoup(html, 'html.parser')
        
        # 提取正文内容
        doc = Document(html)
        main_content = doc.summary()
        main_soup = BeautifulSoup(main_content, 'html.parser')
        text_content = main_soup.get_text(separator='\n').strip()
        
        # 从原始 HTML 中提取所有外链
        links = []
        for a in soup.find_all('a', href=True):
            href = a['href'].strip()
            if href.startswith(('http://', 'https://')):
                links.append(href)
            elif base_url and href:
                links.append(urljoin(base_url, href))
        
        # 从原始 HTML 中提取所有图片链接
        images = []
        for img in soup.find_all('img', src=True):
            src = img['src'].strip()
            if src.startswith(('http://', 'https://')):
                images.append(src)
            elif base_url and src:
                images.append(urljoin(base_url, src))
            
        return {
            'raw': main_content,
            'text': text_content,
            'links': list(set(links)),  # Remove duplicates
            'images': list(set(images))  # Remove duplicates
        }