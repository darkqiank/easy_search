from fastapi import FastAPI, HTTPException, Response, APIRouter, Depends,  Request, status
import gzip
import json
import orjson
from engines import DDGS, BING, GITHUB, VT, URLRead
from typing import Optional
import os
import random
import logging
import re
from engines.utils import write_json_gzip_async, load_json_gzip_async
import ipaddress
import tldextract
import hashlib

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
async def search_ddgs(q: str, l: Optional[str] = 'cn-zh', m: Optional[int] = 10):
    proxy_url = os.getenv('PROXY_URL', None)  # 默认值是你原来硬编码的代理路径
    try:
        with DDGS(proxies=proxy_url,
                    ddgs_end_point='https://ddgs.catflix.cn',
                    ddgslink_end_point='https://ddgslink.catflix.cn',
                    timeout=20) as ddgs:
            q = f'"{q}"'
            res = ddgs.text(q, max_results=m , region=l,)
        
        # with URLRead(proxies=proxy_url, timeout=3) as url_read:
        #     urls = [item.get("href") for item in res]
        #     content_res = url_read.read_sync(urls)
        #     for item in res:
        #         item["content"] = content_res.get(item["href"])
        return res
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={"error": str(e), "status": "failed"}
        )


def check_q_type(q: str):
    def is_ip_address(input_str):
        try:
            ipaddress.ip_address(input_str)
            return True
        except ValueError:
            return False

    def is_domain(input_str):
        extracted = tldextract.extract(input_str)
        return bool(extracted.domain) and bool(extracted.suffix)
    # 判断是否为域名
    if is_domain(q):
        return 'DOMAIN'
    # 判断是否为ip地址
    if is_ip_address(q):
        return 'IP'
    # 判断是否为url
    if q.startswith('http'):
        return 'URL'
    # 其他文件类型
    if re.match(r'^[a-f0-9]{32}$', q, re.IGNORECASE):
        return 'MD5'
    elif re.match(r'^[a-f0-9]{40}$', q, re.IGNORECASE):
        return 'SHA-1'
    elif re.match(r'^[a-f0-9]{64}$', q, re.IGNORECASE):
        return 'SHA-256'
    else:
        return None

@auth_router.get("/tip/vt/")
async def search_tip_vt(q: str, dtype: Optional[str] = None, cursor: Optional[str] = None):
    q_type = check_q_type(q)
    q_id = q
    if q_type == 'URL':
        q_id = hashlib.sha256(q.encode()).hexdigest()
    elif q_type in ['MD5', 'SHA-1']:
        # 获取真正的fileid
        search_res = await read_from_cf_api(q)
        search_items = search_res.get("search_result", {}).get("data", [])
        if len(search_items) > 0:
            q_id = search_items[0].get('id')
        else:
            raise HTTPException(
                status_code=404,
                detail={"error": "File not found", "status": "failed"}
            )

    if dtype:
        # 如果dtype不为空，则进行单独进行dtype和cursor查询
        if q_type not in ["MD5", 'SHA-1', 'SHA-256', 'IP', 'DOMAIN']:
            raise HTTPException(
                status_code=400,
                detail={"error": '不支持的数据类型，仅支持 MD5, SHA-1, SHA-256, IP, DOMAIN', "status": "failed"}
            ) 
        return await tip_fetch_file_cursor(q_id, dtype, cursor)
    else:
        # 如果dtype为空，则进行fileid查询
        if q_type not in ["MD5", 'SHA-1', 'SHA-256']:
            raise HTTPException(
                status_code=400,
                detail={"error": '不支持的数据类型，仅支持 MD5, SHA-1, SHA-256', "status": "failed"}
            ) 
        return await tip_fetch_file_info(q_id)


def handle_communicating_files(data: dict) -> dict:
    return {
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
            for item in data.get("data", [])
        ],
        "meta": data.get("meta", {})
    }


def handle_contacted_domains(data: dict) -> dict:
    return {
        "data": [
            {
                "id": item.get("id"),
                "ioc": item.get("id"),
                "attributes": {
                    "last_analysis_date": item.get("attributes", {}).get("last_analysis_date")
                }
            }
            for item in data.get("data", [])
        ],
        "meta": data.get("meta", {})
    }


def handle_contacted_ips(data: dict) -> dict:
    return {
        "data": [
            {
                "id": item.get("id"),
                "ioc": item.get("id"),
                "attributes": {
                    "last_analysis_date": item.get("attributes", {}).get("last_analysis_date")
                }
            }
            for item in data.get("data", [])
        ],
        "meta": data.get("meta", {})
    }


def handle_contacted_urls(data: dict) -> dict:
    return {
        "data": [
            {
                "id": item.get("id"),
                "ioc": item.get("context_attributes", {}).get("url"),
                "attributes": {
                    "last_analysis_date": item.get("attributes", {}).get("last_analysis_date")
                }
            }
            for item in data.get("data", [])
        ],
        "meta": data.get("meta", {})
    }


async def read_from_cf_api(_f):
    proxy_url = os.getenv('PROXY_URL', None)
    cache_dir = os.getenv('CACHE_DIR', './cache')
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    
    cache_file = os.path.join(cache_dir, f"{_f}.gz")
    if os.path.exists(cache_file):
        logging.info(f"Loading cache file: {cache_file}")
        _res = await load_json_gzip_async(cache_file)
    else:
        with VT(
            proxies=proxy_url,
            timeout=10,
            cf_end_point='https://vt.catflix.cn/'
        ) as vt:
            _res = vt.cf_api(input_str=_f)
        await write_json_gzip_async(cache_file, _res)
        logging.info(f"Writing cache file: {cache_file}")
    return _res

    
async def tip_fetch_file_cursor(q: str, dtype: str, cursor: str):
    proxy_url = os.getenv('PROXY_URL', None)  # 默认值是你原来硬编码的代理路径
    try:
        with VT(proxies=proxy_url,
                timeout=10,
                cf_end_point='https://vt.451964719.xyz/') as vt:
            res = vt.cf_api(input_str=q, dtype=dtype, cursor=cursor)
            if dtype == 'communicating_files':
                info = res.get("communicating_files", {})
                return handle_communicating_files(info)
            
            elif dtype == 'contacted_domains':
                contacted_domains = res.get("contacted_domains", {})
                return handle_contacted_domains(contacted_domains)
            
            elif dtype == 'contacted_ips':
                contacted_ips = res.get("contacted_ips", {})
                return handle_contacted_ips(contacted_ips)
    
            elif dtype == 'contacted_urls':
                contacted_urls = res.get("contacted_urls", {})
                return handle_contacted_urls(contacted_urls)  
            else:
                raise Exception("输入参数错误，dtype不符合要求")
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail={"error": str(e), "status": "failed"}
        )


async def tip_fetch_file_info(fileid: str): 
    try:
        res = await read_from_cf_api(fileid)
        
        # 若存在返回结果，进行返回结果处理
        final_res = {}
        analyse_data = res.get("analyse", {}).get("data", {}).get("attributes", {})
        contacted_domains = res.get("contacted_domains", {})
        contacted_ips = res.get("contacted_ips", {})
        contacted_urls = res.get("contacted_urls", {})
        final_res["meaningful_name"] = analyse_data.get("meaningful_name", None)
        final_res["type_description"] = analyse_data.get("type_description", None)
        final_res["type_tags"] = analyse_data.get("type_tags", [])
        final_res["type_extension"] = analyse_data.get("type_extension", None)
        final_res["md5"] = analyse_data.get("md5", None)
        final_res["sha1"] = analyse_data.get("sha1", None)
        final_res["sha256"] = analyse_data.get("sha256", None)
        final_res["imphash"] = analyse_data.get("pe_info", {}).get("imphash", None)
        final_res["ssdeep"] = analyse_data.get("ssdeep", None)
        final_res["size"] = analyse_data.get("size", None)
        final_res["last_submission_date"] = analyse_data.get("last_submission_date", None)
        final_res["first_submission_date"] = analyse_data.get("first_submission_date", None)
        final_res["contacted_domains"] = handle_contacted_domains(contacted_domains)
        final_res["contacted_ips"] = handle_contacted_ips(contacted_ips)
        final_res["contacted_urls"] = handle_contacted_urls(contacted_urls)
        return final_res
    except HTTPException as he:
        raise he
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
    cache_file = os.path.join(cache_dir, f"{sha256}.gz")
            
    if not sha256 or len(sha256) != 64:
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid SHA256 hash - must be 64 characters", "status": "failed"}
        )
    try:
        if os.path.exists(cache_file):
            logging.info(f"Loading cache file: {cache_file}")
            res = await load_json_gzip_async(cache_file)
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
                if res.get("analyse", {}).get("error", None):
                    # 返回原始错误码
                    error_detail = res["analyse"].get("error", "Unknown error")
                    error_status = res["analyse"].get("status", 500)
                    raise HTTPException(
                        status_code=error_status,
                        detail={"error": error_detail, "status": error_status}
                    )
                    
                await write_json_gzip_async(cache_file, res)
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
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": str(e), "status": "failed"}
        )


    


app.include_router(auth_router)