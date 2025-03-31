from fastapi import FastAPI, HTTPException, Response, APIRouter, Depends,  Request, status
import gzip
import json
import orjson
from engines import DDGS, BING, GITHUB, VT
from typing import Optional
import os
import random


DEFAULT_API_KEY = os.getenv("DEFAULT_API_KEY", None)
app = FastAPI()


def gzip_compress(data: bytes) -> bytes:
    return gzip.compress(data)


# 定义API Key验证逻辑
async def verify_api_key(request: Request):
    if DEFAULT_API_KEY is None:
        # 如果未设置key，则默认不需要key
        return "default_api_key"
    else:
        api_key = request.headers.get("X-API-Key")
        if api_key != DEFAULT_API_KEY:  # 替换为你的实际API Key
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API Key"
            )
        return api_key

auth_router = APIRouter(dependencies=[Depends(verify_api_key)])


@auth_router.get("/search/bing/")
async def search_bing(q: str, l: Optional[str] = 'cn-zh', m: Optional[int] = 10):
    proxy_url = os.getenv('PROXY_URL', None)  # 默认值是你原来硬编码的代理路径
    try:
        with BING(proxies=proxy_url) as bing:
            res = bing.text(keywords=q)
            return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@auth_router.get("/search/ddgs/")
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


@auth_router.get("/search/github/")
async def search_github(q: str, l: Optional[str] = 'cn-zh', m: Optional[int] = 10):
    proxy_url = os.getenv('PROXY_URL', None)  # 默认值是你原来硬编码的代理路径
    try:
        with GITHUB(proxies=proxy_url,
                    timeout=20) as github:
            res = github.text(keywords=q,)
            return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@auth_router.get("/search/vt/")
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


@auth_router.get("/tip/search/")
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


@auth_router.get("/tip/vt/")
async def search_tip_vt(q: str, dtype: str = 'communicating_files', cursor: Optional[str] = None):
    proxy_url = os.getenv('PROXY_URL', None)  # 默认值是你原来硬编码的代理路径
    try:
        with VT(proxies=proxy_url,
                timeout=10,
                cf_end_point='https://vt.451964719.xyz/') as vt:
            if dtype == 'communicating_files':
                res = vt.cf_api(input_str=q, dtype=dtype, cursor=cursor)
                info = res.get("communicating_files")
                clean_res = {
                    "data": [
                        {
                            "id": item.get("id"),
                            "attributes": {
                                "md5": item.get("attributes", {}).get("md5"),
                                "sha1": item.get("attributes", {}).get("sha1"),
                                "sha256": item.get("attributes", {}).get("sha256"),
                                "last_submission_date": item.get("attributes", {}).get("last_submission_date"),
                                "last_analysis_date": item.get("attributes", {}).get("last_analysis_date"),
                                "first_submission_date": item.get("attributes", {}).get("first_submission_date")
                            }
                         }
                         for item in info.get("data")
                    ],
                    "meta": info.get("meta")
                }
                return clean_res
            else:
                raise Exception("输入参数错误，dtype必须为communicating_files")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

app.include_router(auth_router)