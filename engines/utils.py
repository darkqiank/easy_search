import re
from html import unescape
from typing import Any, Dict, List, Union
from urllib.parse import unquote
import orjson
import aiofiles
import gzip
from .exceptions import ClientSearchException

REGEX_STRIP_TAGS = re.compile("<.*?>")


def json_dumps(obj: Any) -> str:
    try:
        return orjson.dumps(obj).decode("utf-8")
    except Exception as ex:
        raise ClientSearchException(f"{type(ex).__name__}: {ex}") from ex


def json_loads(obj: Union[str, bytes]) -> Any:
    try:
        return orjson.loads(obj)
    except Exception as ex:
        raise ClientSearchException(f"{type(ex).__name__}: {ex}") from ex


def _normalize(raw_html: str) -> str:
    """Strip HTML tags from the raw_html string."""
    return unescape(REGEX_STRIP_TAGS.sub("", raw_html)) if raw_html else ""


def _normalize_url(url: str) -> str:
    """Unquote URL and replace spaces with '+'."""
    return unquote(url.replace(" ", "+")) if url else ""


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

# 异步压缩保存json文件
async def write_json_gzip_async(filepath: str, data: Any):
    """
    将JSON数据异步压缩保存为gzip文件
    
    Args:
        filepath: 目标文件路径，建议使用.json.gz后缀
        data: 要保存的数据对象
    """
    try:
        # 将数据转换为JSON二进制
        json_data = orjson.dumps(data)
        # 压缩数据
        compressed_data = gzip.compress(json_data)
        # 异步写入文件
        async with aiofiles.open(filepath, mode='wb') as f:
            await f.write(compressed_data)
    except Exception as ex:
        raise ClientSearchException(f"压缩JSON保存失败: {type(ex).__name__}: {ex}") from ex

# 异步读取压缩的json文件
async def load_json_gzip_async(filepath: str):
    """
    异步读取gzip压缩的JSON文件并解析
    
    Args:
        filepath: 压缩文件路径
        
    Returns:
        解析后的JSON数据对象
    """
    try:
        async with aiofiles.open(filepath, mode='rb') as f:
            compressed_data = await f.read()
            # 解压数据
            json_data = gzip.decompress(compressed_data)
            # 解析JSON
            data = orjson.loads(json_data)
            return data
    except Exception as ex:
        raise ClientSearchException(f"读取压缩JSON失败: {type(ex).__name__}: {ex}") from ex


