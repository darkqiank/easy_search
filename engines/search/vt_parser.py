import json
import datetime
import logging
import os
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv()

logger = logging.getLogger(__name__)

ES_HOSTS = os.getenv('ES_HOSTS', 'localhost:9200').split(',')
ES_USER = os.getenv('ES_USER')
ES_PASSWORD = os.getenv('ES_PASSWORD')
ES_INDEX = os.getenv('VT_PARSER_ES_INDEX', 'vt_parser_results')

_es_client: Optional[Elasticsearch] = None


def _get_es_client() -> Elasticsearch:
    """
    Build or reuse a singleton ES客户端.
    """
    global _es_client
    if _es_client:
        return _es_client

    config: Dict[str, Any] = {
        'hosts': ES_HOSTS,
        'request_timeout': 30,
        'max_retries': 3,
        'retry_on_timeout': True
    }
    if ES_USER and ES_PASSWORD:
        config['basic_auth'] = (ES_USER, ES_PASSWORD)
    _es_client = Elasticsearch(**config)
    return _es_client

def extract_basic_and_mitre(data):
    attrs = data.get('analyse', {}).get('data', {}).get('attributes', {})

    # 1. 样本基础信息 (Basic Info)
    basic_info = {
        "hashes": {
            "md5": attrs.get('md5'),
            "sha1": attrs.get('sha1'),
            "sha256": attrs.get('sha256'),
            "ssdeep": attrs.get('ssdeep'), # 模糊哈希
            "tlsh": attrs.get('tlsh')      # 趋势科技局部敏感哈希
        },
        "file_metadata": {
            "file_names": attrs.get('names', []),
            "file_size": attrs.get('size'),
            "file_type": attrs.get('type_description'), # e.g. Compiled HTML Help
            "magic_header": attrs.get('magic'),         # e.g. MS Windows HtmlHelp Data
            "trid": [t['file_type'] for t in attrs.get('trid', []) if t.get('probability', 0) > 80],
            "tags": attrs.get('tags', []),
            "first_submission": datetime.datetime.utcfromtimestamp(attrs.get('first_submission_date')).isoformat() if attrs.get('first_submission_date') else None,
            "last_analysis": datetime.datetime.utcfromtimestamp(attrs.get('last_analysis_date')).isoformat() if attrs.get('last_analysis_date') else None,
        }
    }

    # 2. MITRE ATT&CK 技战术 (Tactics & Techniques)
    tactics = set()
    techniques_map = {} # ID -> Name/Description

    # 来源 A: 聚合行为分析
    behaviour_data = data.get('behaviour', {}).get('data', {})
    for _, details in behaviour_data.items():
        for tactic in details.get('tactics', []):
            tactics.add(tactic.get('name'))
            for tech in tactic.get('techniques', []):
                if tech.get('id'):
                    techniques_map[tech.get('id')] = tech.get('name')

    # 来源 B: 沙箱详细报告 (补充子技术或描述)
    file_behaviour = data.get('file_behaviour', {}).get('data', [])
    for report in file_behaviour:
        fb_attrs = report.get('attributes', {})
        for tech in fb_attrs.get('mitre_attack_techniques', []):
            tid = tech.get('id')
            desc = tech.get('signature_description')
            if tid and tid not in techniques_map:
                techniques_map[tid] = desc

    mitre_info = {
        "tactics": sorted(list(tactics)),
        "technique_ids": sorted(list(techniques_map.keys())),
        "techniques_details": [{"id": k, "name": v} for k, v in techniques_map.items()]
    }

    return {
        "basic_info": basic_info,
        "mitre_attack": mitre_info
    }


def extract_extended_vt_data(data):

    # 结果容器
    extracted = {
        "http_requests": set(),
        "dns_resolutions": set(),
        "ip_traffic": set(),
        "memory_pattern_domains": set(),
        "memory_pattern_urls": set(),
        "files_opened": set(),
        "files_written": set(),
        "files_deleted": set(),
        "files_dropped": set(),
        "registry_opened": set(),
        "registry_set": set(),
        "registry_deleted": set(),
        "processes_created": set(),
        "services_started": set(),
        "processes_tree": set(),
        "processes_terminated": set(),
        "command_executions": set(),
        "mutexes": set(),
        "modules_loaded": set(),
        "calls_highlighted": set(),
        "text_highlighted": set(),
    }

    # 遍历所有沙箱报告 (CAPE, VMRay, Zenbox等)
    reports = data.get('file_behaviour', {}).get('data', [])
    for report in reports:
        attrs = report.get('attributes', {})

        # 1. 网络行为 (Network)
        # HTTP
        for req in attrs.get('http_conversations', []):
            if isinstance(req, dict):
                # 格式化: METHOD URL
                url = req.get('url', '')
                method = req.get('request_method', '')
                if url: extracted['http_requests'].add(f"{method} {url}".strip())
            elif isinstance(req, str):
                extracted['http_requests'].add(req)
        
        # DNS
        for dns in attrs.get('dns_lookups', []):
            if isinstance(dns, dict):
                hostname = dns.get('hostname')
                ips = dns.get('resolved_ips', [])
                if hostname: extracted['dns_resolutions'].add(f"{hostname} -> {ips}")
            elif isinstance(dns, str):
                extracted['dns_resolutions'].add(dns)

        # IP Traffic
        for traffic in attrs.get('ip_traffic', []):
            if isinstance(traffic, dict):
                entry = f"{traffic.get('transport_layer_protocol')}:{traffic.get('destination_ip')}:{traffic.get('destination_port')}"
                extracted['ip_traffic'].add(entry)

        # 2. 内存特征 (Memory Patterns)
        extracted['memory_pattern_domains'].update(attrs.get('memory_pattern_domains', []))
        extracted['memory_pattern_urls'].update(attrs.get('memory_pattern_urls', []))

        # 3. 文件系统 (File System)
        extracted['files_opened'].update(attrs.get('files_opened', []))
        extracted['files_written'].update(attrs.get('files_written', []))
        extracted['files_deleted'].update(attrs.get('files_deleted', []))
        # Dropped files sometimes are dicts
        for f in attrs.get('files_dropped', []):
            if isinstance(f, dict): extracted['files_dropped'].add(f.get('path'))
            else: extracted['files_dropped'].add(f)

        # 4. 注册表 (Registry)
        extracted['registry_opened'].update(attrs.get('registry_keys_opened', []))
        extracted['registry_deleted'].update(attrs.get('registry_keys_deleted', []))
        for r in attrs.get('registry_keys_set', []):
            if isinstance(r, dict): extracted['registry_set'].add(f"{r.get('key')} = {r.get('value')}")
            else: extracted['registry_set'].add(r)

        # 5. 进程与服务 (Process & Service)
        extracted['processes_created'].update(attrs.get('processes_created', []))
        extracted['services_started'].update(attrs.get('services_started', []))
        processes_tree = attrs.get('processes_tree', [])
        def parse_processes_tree(processes_tree):
            for process in processes_tree:
                name = process.get('name')
                children = process.get('children', [])
                extracted['processes_tree'].add(name)
                for child in children:
                    extracted['processes_tree'].add(child.get('name'))
        parse_processes_tree(processes_tree)
        extracted['processes_terminated'].update(attrs.get('processes_terminated', []))
        extracted['command_executions'].update(attrs.get('command_executions', []))

        # 6. 同步与信号 (Synchronization)
        extracted['mutexes'].update(attrs.get('mutexes_created', []))
        extracted['mutexes'].update(attrs.get('mutexes_opened', []))

        # 7. 模块与高亮行为 (Modules & Highlights)
        extracted['modules_loaded'].update(attrs.get('modules_loaded', []))
        extracted['calls_highlighted'].update(attrs.get('calls_highlighted', []))
        extracted['text_highlighted'].update(attrs.get('text_highlighted', []))

    basic_and_mitre = extract_basic_and_mitre(data)
    # 转换为列表以便JSON序列化
    output = {k: list(v) for k, v in extracted.items()}
    output.update(basic_and_mitre)
    return output


def push_parsed_result_to_es(parsed_data: Dict[str, Any], doc_id: Optional[str] = None,
                             es_client: Optional[Elasticsearch] = None) -> Dict[str, Any]:
    """
    将解析出的VT数据推送到Elasticsearch。

    Args:
        parsed_data: extract_extended_vt_data 的结构化结果
        doc_id: 指定ES文档ID，默认使用样本SHA256/MD5
        es_client: 自定义Elasticsearch客户端，便于测试

    Returns:
        ES index操作的响应
    """
    if not parsed_data:
        raise ValueError("parsed_data 不能为空")

    client = es_client or _get_es_client()

    if not doc_id:
        hashes = parsed_data.get('basic_info', {}).get('hashes', {}) if isinstance(parsed_data, dict) else {}
        doc_id = hashes.get('sha256') or hashes.get('md5')

    document = parsed_data.copy()
    document['indexed_at'] = datetime.datetime.utcnow().isoformat()

    try:
        response = client.index(index=ES_INDEX, id=doc_id, document=document)
        logger.info("推送解析结果至ES成功, id=%s", doc_id or response.get('_id'))
        return response
    except Exception as exc:
        logger.error("推送解析结果至ES失败: %s", exc)
        raise

# 示例调用
# result = extract_extended_vt_data('vt_summary.json')
# print(json.dumps(result, indent=4))
