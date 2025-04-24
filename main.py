from fastapi import FastAPI, HTTPException, Response, APIRouter, Depends,  Request, status
import gzip
import json
import orjson
from engines import DDGS, BING, GITHUB, VT
from typing import Optional
import os
import random
import aiofiles
import logging


DEFAULT_API_KEY = os.getenv("DEFAULT_API_KEY", None)
app = FastAPI()

# 异步读取json文件
async def load_json_async(filepath: str):
    async with aiofiles.open(filepath, mode='rb') as f:  # 必须以二进制读取
        content = await f.read()
        data = orjson.loads(content)
        return data
# 异步写入json文件
async def write_json_async(filepath: str, data: dict):
    async with aiofiles.open(filepath, mode='wb') as f:
        await f.write(orjson.dumps(data))

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
        raise HTTPException(
            status_code=500, 
            detail={"error": str(e), "status": "failed"}
        )


@auth_router.get("/search/github/")
async def search_github(q: str, l: Optional[str] = 'cn-zh', m: Optional[int] = 10):
    proxy_url = os.getenv('PROXY_URL', None)  # 默认值是你原来硬编码的代理路径
    try:
        with GITHUB(proxies=proxy_url,
                    timeout=20) as github:
            res = github.text(keywords=q,)
            return res
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={"error": str(e), "status": "failed"}
        )


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
        raise HTTPException(
            status_code=500, 
            detail={"error": str(e), "status": "failed"}
        )


@auth_router.get("/tip/search/")
async def search_ddgs(q: str, l: Optional[str] = 'wt-wt', m: Optional[int] = 10):
    proxy_url = os.getenv('PROXY_URL', None)  # 默认值是你原来硬编码的代理路径
    try:
        with DDGS(proxies=proxy_url,
                    ddgs_end_point='https://ddgs.catflix.cn',
                    ddgslink_end_point='https://ddgslink.catflix.cn',
                    timeout=20) as ddgs:
            q = f'"{q}"'
            res = ddgs.text(q, max_results=m , region=l,)
            return res
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={"error": str(e), "status": "failed"}
        )


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
        raise HTTPException(
            status_code=500, 
            detail={"error": str(e), "status": "failed"}
        )

@auth_router.get("/tip/vt/file/{sha256}")
async def search_file_vt(sha256: str):
    proxy_url = os.getenv('PROXY_URL', None)
    cache_dir = os.getenv('CACHE_DIR', './cache')
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    cache_file = os.path.join(cache_dir, f"{sha256}.json")
            
    if not sha256 or len(sha256) != 64:
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid SHA256 hash - must be 64 characters", "status": "failed"}
        )
    try:
        if os.path.exists(cache_file):
            logging.info(f"Loading cache file: {cache_file}")
            res = await load_json_async(cache_file)
        else:
            with VT(proxies=proxy_url,
                    timeout=10,
                    cf_end_point='https://vt.catflix.cn/') as vt:
                res = vt.cf_api(input_str=sha256)
                if not res:
                    raise HTTPException(
                        status_code=404,
                        detail={"error": "File not found", "status": "failed"}
                    )
                await write_json_async(cache_file, res)
                logging.info(f"Writing cache file: {cache_file}")
        
        # Extract data from nested structure
        analyse_data = res.get("analyse", {}).get("data", {}).get("attributes", {})
        behaviour_data = res.get("behaviour", {}).get("data", {})
        file_behaviour_data = res.get("file_behaviour", {}).get("data", [])
        last_analysis_results = analyse_data.get("last_analysis_results", {})
        popular_threat_category = analyse_data.get("popular_threat_classification", {}).get("popular_threat_category", [])
        if not popular_threat_category:
            # 先找kaspersky
            kaspersky_category = last_analysis_results.get("Kaspersky", {}).get("category", None)
            kaspersky_result = last_analysis_results.get("Kaspersky", {}).get("result", None)
            if kaspersky_category == "malicious" and kaspersky_result and kaspersky_result != "detected" and kaspersky_result != "":
                popular_threat_category.append({"value": kaspersky_result, "source": "Kaspersky", "count": 1})
            else:
                # 再找其他av
                for k in last_analysis_results.keys():
                    av_category = last_analysis_results.get(k, {}).get("category", None)
                    av_result = last_analysis_results.get(k, {}).get("result", None)
                    if av_category == "malicious" and av_result and av_result != "detected" and av_result != "":
                        popular_threat_category.append({"value":av_result, "source": k, "count": 1})
                        break
        # 处理behaviour_mitre_trees
        behaviour_mitre_trees_atts = {}
        for key in behaviour_data.keys():
            key_data = behaviour_data[key]
            behaviour_mitre_trees_atts[key] = {"tactics": []}
            
            # 处理每个 tactic
            for tactic in key_data.get("tactics", []):
                simplified_tactic = {
                    "id": tactic.get("id", ""),
                    "name": tactic.get("name", ""),
                    "techniques": []
                }
                
                # 处理每个 technique
                for technique in tactic.get("techniques", []):
                    simplified_technique = {
                        "id": technique.get("id", ""),
                        "name": technique.get("name", ""),
                        "signatures": technique.get("signatures", [])
                    }
                    simplified_tactic["techniques"].append(simplified_technique)
                    
                behaviour_mitre_trees_atts[key]["tactics"].append(simplified_tactic)

        # 处理network_communication
        network_communication_atts = []
        for file_behaviour in file_behaviour_data:
            att = {}
            file_behaviour_attributes = file_behaviour.get("attributes", {})
            att["sandbox_name"] = file_behaviour_attributes.get("sandbox_name", "")
            att["http_conversations"] = file_behaviour_attributes.get("http_conversations", [])
            att["memory_pattern_domains"] = file_behaviour_attributes.get("memory_pattern_domains", [])
            att["memory_pattern_urls"] = file_behaviour_attributes.get("memory_pattern_urls", [])
            att["ip_traffic"] = file_behaviour_attributes.get("ip_traffic", [])
            att["ja3_digests"] = file_behaviour_attributes.get("ja3_digests", [])
            att["dns_lookups"] = file_behaviour_attributes.get("dns_lookups", [])
            att["tls"] = file_behaviour_attributes.get("tls", [])
            network_communication_atts.append(att)

        clean_res = {
            "vt_hit": True,
            "meaningful_name": analyse_data.get("meaningful_name"),
            "type_tag": analyse_data.get("type_tag"),
            "size": analyse_data.get("size"),
            "sha256": analyse_data.get("sha256"),
            "sha1": analyse_data.get("sha1"),
            "md5": analyse_data.get("md5"),
            "creation_date": analyse_data.get("creation_date"),
            "last_submission_date": analyse_data.get("last_submission_date"),
            "first_submission_date": analyse_data.get("first_submission_date"),
            "behaviour_mitre_trees": behaviour_mitre_trees_atts,
            "popular_threat_category": popular_threat_category,
            "network_communication": network_communication_atts
        }
        return clean_res
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": str(e), "status": "failed"}
        )


    


app.include_router(auth_router)