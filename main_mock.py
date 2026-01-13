from fastapi import FastAPI, HTTPException, Response, APIRouter, Depends, Request, status, Query
import gzip
from typing import Optional
from datetime import datetime, timedelta
import random
import string
import time
import re
app = FastAPI()

def gzip_compress(data: bytes) -> bytes:
    return gzip.compress(data)

async def verify_api_key(request: Request):
    api_key = request.headers.get("X-API-Key")
    if api_key != "default_api_key":  # 替换为你的实际API Key
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
    )
    return api_key

auth_router = APIRouter(dependencies=[Depends(verify_api_key)])


MOCK_VT_FILE_DATA = {
    "vt_hit": True,
    "meaningful_name": "malware_sample.exe",
    "type_tag": "exe",
    "size": 56320,
    "sha256": "cf4b367e49cb43a02c9b8f9e9872f6f5a65e01f34b49b54b6e3f4e2e159f5975",
    "sha1": "a65e01f34b49b54b6e3f4e2e159f5975cf4b367e",
    "md5": "cf4b367e49cb43a02c9b8f9e9872f6f5",
    "creation_date": int((datetime.now() - timedelta(days=60)).timestamp()),
    "last_submission_date": int((datetime.now() - timedelta(days=7)).timestamp()),
    "first_submission_date": int((datetime.now() - timedelta(days=30)).timestamp()),
    "behaviour_mitre_trees": {
        "sandbox1": {
            "tactics": [
                {
                    "id": "TA0002",
                    "name": "Execution",
                    "techniques": [
                        {
                            "id": "T1059",
                            "name": "Command and Scripting Interpreter",
                            "signatures": ["Uses PowerShell to execute commands"]
                        }
                    ]
                },
                {
                    "id": "TA0005",
                    "name": "Defense Evasion",
                    "techniques": [
                        {
                            "id": "T1027",
                            "name": "Obfuscated Files or Information",
                            "signatures": ["Uses obfuscated code"]
                        }
                    ]
                }
            ]
        }
    },
    "popular_threat_category": [
        {
            "value": "Trojan.Win32.Generic",
            "source": "Kaspersky",
            "count": 1
        }
    ],
    "network_communication": [
        {
            "sandbox_name": "sandbox1",
            "http_conversations": [
                {
                    "url": "http://malicious-example.com/payload",
                    "method": "GET"
                }
            ],
            "memory_pattern_domains": ["malicious-example.com"],
            "memory_pattern_urls": ["http://malicious-example.com/payload"],
            "ip_traffic": [
                {
                    "dst": "192.168.1.100",
                    "transport_layer_protocol": "tcp"
                }
            ],
            "ja3_digests": ["a0e9f5d64349fb13191bc781f81f42e1"],
            "dns_lookups": [
                {
                    "hostname": "malicious-example.com",
                    "resolved_ips": ["192.168.1.100"]
                }
            ],
            "tls": [
                {
                    "dst_port": 443,
                    "dst_ip": "192.168.1.100"
                }
            ]
        }
    ]
}

def is_valid_input(q):
    # 正则表达式验证 IP 地址
    ip_pattern = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    # 正则表达式验证域名
    domain_pattern = re.compile(
        r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]')
    # 正则表达式验证 MD5
    md5_pattern = re.compile(r'^[a-fA-F0-9]{32}$')
    # 正则表达式验证 SHA1
    sha1_pattern = re.compile(r'^[a-fA-F0-9]{40}$')
    # 正则表达式验证 SHA256
    sha256_pattern = re.compile(r'^[a-fA-F0-9]{64}$')

    return (
        bool(ip_pattern.match(q)) or
        bool(domain_pattern.match(q)) or
        bool(md5_pattern.match(q)) or
        bool(sha1_pattern.match(q)) or
        bool(sha256_pattern.match(q))
    )



@auth_router.get("/tip/search/")
def search(q: str = Query(..., description="需要查找结果的 ioc 参数（需校验请求为 ip、域名、md5、sha1 或 sha256），最多 10 个")):
    if not is_valid_input(q):
        return {"detail": "请求参数内容不对，q 必须是有效的 ip、域名、md5、sha1 或 sha256"}, 500
    # 模拟的标题列表
    titles = [
        "示例标题1",
        "示例标题2",
        "示例标题3",
        "示例标题4",
        "示例标题5",
        "示例标题6",
        "示例标题7",
        "示例标题8",
        "示例标题9",
        "示例标题10"
    ]

    # 模拟的链接列表
    hrefs = [
        "https://example.com/link1",
        "https://example.com/link2",
        "https://example.com/link3",
        "https://example.com/link4",
        "https://example.com/link5",
        "https://example.com/link6",
        "https://example.com/link7",
        "https://example.com/link8",
        "https://example.com/link9",
        "https://example.com/link10"
    ]

    # 模拟的摘要列表
    bodies = [
        f"这是示例摘要1 {q}",
        f"这是示例摘要2 {q}",
        f"这是示例摘要3 {q}",
        f"这是示例摘要4 {q}",
        f"这是示例摘要5 {q}",
        f"这是示例摘要6 {q}",
        f"这是示例摘要7 {q}",
        f"这是示例摘要8 {q}",
        f"这是示例摘要9 {q}",
        f"这是示例摘要10 {q}"
    ]

    # 随机生成响应数据
    result_count = 10  # 可以根据需要修改随机结果的数量
    result = []
    for _ in range(result_count):
        data = {
            "title": random.choice(titles),
            "href": random.choice(hrefs),
            "body": random.choice(bodies)
        }
        result.append(data)

    return result


def generate_random_hash(hash_length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=hash_length))


def generate_random_date():
    return int(time.time() - random.randint(0, 31536000 * 5))

def random_domains_data(sample_count: int = 5):
    data = []
    for _ in range(sample_count):
        _id = random.randint(1, 1000000)
        sample = {
            "id": f"example-{_id}.com",
            "ioc": f"example-{_id}.com",
            "attributes": {
                "last_analysis_date": generate_random_date()
            }
        }
        data.append(sample)
    meta = {
        "count": random.randint(100, 1000),
        "cursor": generate_random_hash(20)
    }
    return {"data": data, "meta": meta}

def random_ips_data(sample_count: int = 5):
    data = []
    for _ in range(sample_count):
        _id = random.randint(1, 255)
        sample = {
            "id": f"192.168.1.{_id}",
            "ioc": f"192.168.1.{_id}",
            "attributes": {
                "last_analysis_date": generate_random_date()
            }
        }
        data.append(sample)
    meta = {
        "count": random.randint(100, 1000),
        "cursor": generate_random_hash(20)
    }
    return {"data": data, "meta": meta}

def random_urls_data(sample_count: int = 5):
    data = []
    for _ in range(sample_count):
        _id = random.randint(1, 1000000)
        sample = {
            "id": generate_random_hash(40),
            "ioc": f"http://example-{_id}.com",
            "attributes": {
                "last_analysis_date": generate_random_date()
            }
        }
        data.append(sample)
    meta = {
        "count": random.randint(100, 1000),
        "cursor": generate_random_hash(20)
    }
    return {"data": data, "meta": meta}


@auth_router.get("/tip/vt/")
async def search_tip_vt(q: str, dtype: Optional[str] = None, cursor: Optional[str] = None):
    if dtype is None:
        sample_data = {
            "meaningful_name": "example.exe",
            "type_description": "Win32 EXE",
            "type_tags": ["peexe", "executable"],
            "type_extension": "exe",
            "md5": generate_random_hash(32),
            "sha1": generate_random_hash(40),
            "sha256": generate_random_hash(64),
            "imphash": generate_random_hash(32),
            "ssdeep": generate_random_hash(32),
            "size": 123456,
            "last_submission_date": 1678886400,
            "first_submission_date": 1678886400,
            "contacted_domains": random_domains_data(5),
            "contacted_ips": random_ips_data(5),
            "contacted_urls": random_urls_data(5)
        }
        return sample_data

    if dtype == 'communicating_files':
        # 模拟的样本数量
        sample_count = 10
        data = []
        for _ in range(sample_count):
            sample = {
                "id": generate_random_hash(40),
                "attributes": {
                    "md5": generate_random_hash(32),
                    "sha1": generate_random_hash(40),
                    "sha256": generate_random_hash(64),
                    "last_submission_date": generate_random_date(),
                    "last_analysis_date": generate_random_date(),
                    "first_submission_date": generate_random_date()
                }
            }
            data.append(sample)

        meta = {
            "count": random.randint(100, 1000000),
            "cursor": generate_random_hash(20)
        }

        response = {
            "data": data,
            "meta": meta
        }
        return response
    elif dtype == 'contacted_domains':
            # 模拟的样本数量
            return random_domains_data(5)
    elif dtype == 'contacted_ips':
        return random_ips_data(5)
    elif dtype == 'contacted_urls':
        return random_urls_data(5)
    else:
        raise HTTPException(
            status_code=400,
            detail={"error": "输入参数错误，dtype必须为communicating_files", "status": "failed"}
        )
    

def random_risk_events_data(sample_count: int = 5, source_types: Optional[str] = None):
    datas = []
    sources = source_types.split(',') if source_types else ["biz", "blog", "twitter"]
    for _ in range(sample_count):
        _id = random.randint(1, 1000000)
        sample_event = {
            "id": _id,
            "insertedAt": "2025-06-09 20:00:06.979151+08",
            "link": f"https://example.com/{_id}",
            "meta": {
                "desc": f"测试数据{_id}摘要",
                "source": "测试源",
                "source_type": random.choice(sources)
            }
        }
        datas.append(sample_event)
    return datas

@app.get("/tip/search-ioc")
async def search_ioc_event(ioc: str, source_types: Optional[str] = None, pn: int = 1, ps: int = 5):
    if pn * ps > 10:
        # 如果总数大于10，则pn为整除10/ps
        pn = int(10/ps)
    return {
        "success": True,
        "data": random_risk_events_data(5, source_types),
        "pagination": {
            "totalPages": 2,
            "totalRecords": 10,
            "pageNumber": pn,
            "pageSize": ps
        },
        "searchTerm": ioc,
    }



@auth_router.get("/tip/vt/file/{sha256}")
async def search_file_vt(sha256: str):
    if not sha256 or len(sha256) != 64:
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid SHA256 hash - must be 64 characters", "status": "failed"}
        )
        # 模拟的文件数据
    new_data = MOCK_VT_FILE_DATA.copy()
    new_data['sha256'] = sha256
    return new_data


app.include_router(auth_router)