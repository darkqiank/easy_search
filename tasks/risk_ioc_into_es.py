import requests
import json
import os
from datetime import datetime
from dotenv import load_dotenv
from engines import VT
from elasticsearch import Elasticsearch
from typing import List, Dict, Any
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

# 加载 .env 文件
load_dotenv()

# IOC endpoint配置
IOC_ENDPOINT = os.getenv('IOC_ENDPOINT', 'http://ioc_endpoint:3000')
IOC_API_URL = f"{IOC_ENDPOINT}/api/threat"

# VT配置
VT_PROXIES = os.getenv('VT_PROXIES', 'socks5://127.0.0.1:10808')
VT_TIMEOUT = int(os.getenv('VT_TIMEOUT', '10'))
VT_CF_END_POINT = os.getenv('VT_CF_END_POINT', 'https://xxxx/')

# Elasticsearch配置
ES_HOSTS = os.getenv('ES_HOSTS', 'localhost:9200').split(',')
ES_INDEX = os.getenv('ES_INDEX', 'risk_ioc_vt')
ES_USER = os.getenv('ES_USER', None)
ES_PASSWORD = os.getenv('ES_PASSWORD', None)

# 初始化Elasticsearch客户端
es_config = {
    'hosts': ES_HOSTS,
    'request_timeout': 30,              # 原 timeout 改为 request_timeout
    'max_retries': 3,                   # 保持不变，但需注意 8.x 默认已启用
    'retry_on_timeout': True
}
if ES_USER and ES_PASSWORD:
    es_config['basic_auth'] = (ES_USER, ES_PASSWORD)

es = Elasticsearch(**es_config)


def get_ioc_data(page: int = 1) -> Dict[str, Any]:
    """
    从IOC endpoint获取威胁数据
    
    Args:
        page: 页码，默认为1
        
    Returns:
        包含威胁数据的字典
    """
    try:
        url = f"{IOC_API_URL}?page={page}"
        logging.info(f"正在获取IOC数据: {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        logging.info(f"成功获取IOC数据，共 {len(data.get('data', []))} 条记录")
        return data
    except Exception as e:
        logging.error(f"获取IOC数据失败: {e}")
        raise


def extract_sample_iocs(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    从数据中提取样本类的IOC
    
    Args:
        data: IOC endpoint返回的数据
        
    Returns:
        样本类IOC列表，每个IOC包含原始记录信息和IOC详情
    """
    sample_iocs = []
    records = data.get('data', [])
    
    for record in records:
        extraction_result = record.get('extractionResult', {})
        extraction_data = extraction_result.get('data', {})
        iocs = extraction_data.get('iocs', [])
        
        for ioc in iocs:
            # 只取样本类的IOC（类型为SHA256、MD5、SHA-1等哈希类型，通常是样本）
            ioc_type = ioc.get('类型', '').strip().upper()
            # 支持多种格式：SHA256, SHA-256, SHA1, SHA-1, MD5等
            hash_types = ['SHA256', 'SHA-256', 'MD5', 'SHA-1', 'SHA1']
            if any(ht in ioc_type for ht in hash_types):
                ioc_value = ioc.get('IOC', '').strip()
                if not ioc_value:
                    continue
                    
                sample_ioc = {
                    'ioc_value': ioc_value,
                    'ioc_info': ioc,
                    'source_record': {
                        'id': record.get('id'),
                        'url': record.get('url', '').strip(),
                        'content': record.get('content', ''),
                        'insertedAt': record.get('insertedAt'),
                        'source': record.get('source', '').strip(),
                        'link': record.get('link', '')
                    }
                }
                sample_iocs.append(sample_ioc)
                logging.info(f"提取到样本IOC: {ioc_value[:20]}... (类型: {ioc.get('类型', '').strip()})")
    
    logging.info(f"共提取到 {len(sample_iocs)} 个样本类IOC")
    return sample_iocs


def query_vt_for_ioc(ioc_value: str) -> Dict[str, Any]:
    """
    使用VT的cf_api查询IOC
    
    Args:
        ioc_value: IOC值（如SHA256哈希）
        
    Returns:
        VT查询结果
    """
    try:
        logging.info(f"正在查询VT: {ioc_value[:20]}...")
        with VT(
            proxies=VT_PROXIES,
            timeout=VT_TIMEOUT,
            cf_end_point=VT_CF_END_POINT
        ) as vt:
            res = vt.cf_api(input_str=ioc_value)
        logging.info(f"成功查询VT: {ioc_value[:20]}...")
        return res
    except Exception as e:
        logging.error(f"查询VT失败 {ioc_value[:20]}...: {e}")
        return {}


def save_to_es(ioc_value: str, ioc_info: Dict[str, Any], source_record: Dict[str, Any], vt_result: Dict[str, Any]) -> bool:
    """
    将结果保存到Elasticsearch
    
    Args:
        ioc_value: IOC值
        ioc_info: IOC详细信息
        source_record: 原始记录信息
        vt_result: VT查询结果
        
    Returns:
        是否保存成功
    """
    try:
        # 提取VT结果中的各个字段（如果存在）
        vt_result_clean = {}
        expected_fields = [
            'analyse', 'contacted_urls', 'contacted_domains', 'contacted_ips',
            'behaviour', 'file_behaviour', 'comments', 'behaviour_mbc_trees',
            'execution_parents', 'pe_resource_parents', 'bundled_files',
            'pe_resource_children'
        ]
        
        for field in expected_fields:
            if field in vt_result:
                vt_result_clean[field] = vt_result[field]
        
        # 如果vt_result中还有其他字段，也一并保存
        for key, value in vt_result.items():
            if key not in expected_fields:
                vt_result_clean[key] = value
        
        # 构建要保存的文档
        doc = {
            'ioc_value': ioc_value,
            'ioc_info': ioc_info,
            'source_record': source_record,
            'vt_result': vt_result_clean,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        # 使用IOC值作为文档ID
        doc_id = ioc_value
        
        # 保存到ES（如果文档已存在则更新）
        result = es.index(
            index=ES_INDEX,
            id=doc_id,
            document=doc
        )
        
        logging.info(f"成功保存到ES: {ioc_value[:20]}... (ID: {result.get('_id')})")
        return True
    except Exception as e:
        logging.error(f"保存到ES失败 {ioc_value[:20]}...: {e}")
        return False


def process_ioc(sample_ioc: Dict[str, Any]) -> bool:
    """
    处理单个IOC：查询VT并保存到ES
    
    Args:
        sample_ioc: 样本IOC信息
        
    Returns:
        是否处理成功
    """
    ioc_value = sample_ioc['ioc_value']
    ioc_info = sample_ioc['ioc_info']
    source_record = sample_ioc['source_record']
    
    # 查询VT
    vt_result = query_vt_for_ioc(ioc_value)
    
    if not vt_result:
        logging.warning(f"VT查询结果为空: {ioc_value[:20]}...")
        return False
    
    # 保存到ES
    success = save_to_es(ioc_value, ioc_info, source_record, vt_result)
    return success


def main(page: int = 1):
    """
    主函数：获取IOC数据，提取样本类IOC，查询VT并保存到ES
    
    Args:
        page: 要处理的页码，默认为1
    """
    try:
        # 1. 获取IOC数据
        ioc_data = get_ioc_data(page=page)
        
        # 2. 提取样本类IOC
        sample_iocs = extract_sample_iocs(ioc_data)
        
        if not sample_iocs:
            logging.warning("未找到样本类IOC")
            return
        
        # 3. 处理每个IOC
        success_count = 0
        fail_count = 0
        
        for sample_ioc in sample_iocs:
            try:
                if process_ioc(sample_ioc):
                    success_count += 1
                else:
                    fail_count += 1
            except Exception as e:
                logging.error(f"处理IOC失败: {e}")
                fail_count += 1
            break
        
        logging.info(f"处理完成: 成功 {success_count} 个，失败 {fail_count} 个")
        
    except Exception as e:
        logging.error(f"主流程执行失败: {e}")
        raise


if __name__ == "__main__":
    import sys
    
    # 可以从命令行参数获取页码
    page = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    main(page=page)
