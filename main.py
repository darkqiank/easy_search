from fastapi import FastAPI, HTTPException, Response
import gzip
import json
import orjson
from engines import DDGS, BING, GITHUB, VT
from typing import Optional
import os

app = FastAPI()


def gzip_compress(data: bytes) -> bytes:
    return gzip.compress(data)


@app.get("/search/bing/")
async def search_bing(q: str, l: Optional[str] = 'cn-zh', m: Optional[int] = 10):
    proxy_url = os.getenv('PROXY_URL', None)  # 默认值是你原来硬编码的代理路径
    try:
        with BING(proxies=proxy_url) as bing:
            res = bing.text(keywords=q)
            return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/search/ddgs/")
async def search_ddgs(q: str, l: Optional[str] = 'cn-zh', m: Optional[int] = 10):
    proxy_url = os.getenv('PROXY_URL', None)  # 默认值是你原来硬编码的代理路径
    try:
        with DDGS(proxies=proxy_url,
                  ddgs_end_point='https://ddgs.catflix.cn',
                  ddgslink_end_point='https://ddgslink.catflix.cn',
                    timeout=20) as ddgs:
            res = ddgs.text(q, max_results=m , region=l,)
            return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/search/github/")
async def search_github(q: str, l: Optional[str] = 'cn-zh', m: Optional[int] = 10):
    proxy_url = os.getenv('PROXY_URL', None)  # 默认值是你原来硬编码的代理路径
    try:
        with GITHUB(proxies=proxy_url,
                    timeout=20) as github:
            res = github.text(keywords=q,)
            return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/search/vt/")
async def search_vt(q: str):
    proxy_url = os.getenv('PROXY_URL', None)  # 默认值是你原来硬编码的代理路径
    print(proxy_url)
    try:
        with VT(proxies=proxy_url, timeout=30) as vt:
            res = vt.api(q)
            # 将 JSON 数据转换为字符串
            json_data = orjson.dumps(res)
            # 压缩序列化后的 JSON 字节数据
            compressed_data = gzip_compress(json_data)
            # 返回压缩后的数据，并设置 Content-Encoding 头
            return Response(content=compressed_data, media_type="application/json",
                            headers={"Content-Encoding": "gzip"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))