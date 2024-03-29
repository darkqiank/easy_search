from fastapi import FastAPI
from engines import DDGS, BING
from typing import Optional
import os

app = FastAPI()


@app.get("/search/bing/")
async def search_bing(q: str, l: Optional[str] = 'cn-zh', m: Optional[int] = 10):
    proxy_url = os.getenv('PROXY_URL', "socks5://127.0.0.1:7890")  # 默认值是你原来硬编码的代理路径
    res = BING(proxies=proxy_url).text(keywords=q)
    return res

@app.get("/search/ddgs/")
async def search_ddgs(q: str, l: Optional[str] = 'cn-zh', m: Optional[int] = 10):
    proxy_url = os.getenv('PROXY_URL', "socks5://127.0.0.1:7890")  # 默认值是你原来硬编码的代理路径
    res = DDGS(proxies=proxy_url,
                timeout=20).text(q, max_results=m , region=l,)
    return res
