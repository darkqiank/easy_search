# VT Parser Elasticsearch 搜索优化指南

## 📋 问题背景

之前搜索命令行字符串（如 `"xterm -hold -e sh -c /tmp/init_start"`）时，ES会将其分词成多个独立的词元，导致搜索结果不相关。

## ✅ 优化方案

### 1. 索引映射优化

为所有关键字段配置了**三层字段类型**：

```
command_executions (字段名)
├── wildcard 类型 (主字段) - 支持通配符和完整字符串搜索
├── .text 子字段 - 支持分词搜索和相关性排序
└── .keyword 子字段 - 支持精确匹配和聚合
```

### 2. 优化的字段列表

以下字段已优化为 wildcard 类型：

**进程和命令字段：**
- `command_executions` - 命令执行 ⭐ 核心字段
- `processes_created` - 进程创建
- `processes_tree` - 进程树
- `processes_terminated` - 进程终止
- `services_started` - 服务启动

**文件系统字段：**
- `files_opened` - 打开的文件
- `files_written` - 写入的文件
- `files_deleted` - 删除的文件
- `files_dropped` - 释放的文件
- `modules_loaded` - 加载的模块

**网络字段：**
- `http_requests` - HTTP请求
- `dns_resolutions` - DNS解析
- `memory_pattern_urls` - 内存中的URL

**注册表字段：**
- `registry_opened` - 打开的注册表键
- `registry_set` - 设置的注册表值
- `registry_deleted` - 删除的注册表键

## 🚀 使用方法

### 步骤1: 重建索引映射

⚠️ **重要：必须先重建索引才能应用新的映射**

```bash
# 方式1: 使用管理脚本（推荐）
python manage_vt_index.py --recreate

# 方式2: 使用Python代码
from engines.search.vt_parser import _get_es_client, ensure_index_exists
client = _get_es_client()
ensure_index_exists(es_client=client, recreate=True)
```

### 步骤2: 重新导入数据

重建索引后需要重新导入所有VT数据：

```bash
# 示例：重新运行数据导入任务
python -m tasks.risk_ioc_into_es
```

### 步骤3: 使用优化后的搜索

## 📝 搜索查询示例

### 方法1: Wildcard 查询（推荐用于完整命令搜索）

**适用场景：** 搜索包含特定字符串的命令，支持通配符

```python
from elasticsearch import Elasticsearch

client = Elasticsearch(...)

# 搜索包含完整命令的文档
result = client.search(
    index="vt_parser_results",
    body={
        "query": {
            "wildcard": {
                "command_executions": {
                    "value": "*xterm -hold -e sh -c /tmp/init_start*",
                    "case_insensitive": True
                }
            }
        },
        "size": 10
    }
)
```

**通配符语法：**
- `*` - 匹配任意字符序列
- `?` - 匹配单个字符
- 示例：`*tmp*.exe` - 匹配所有包含"tmp"的.exe文件

### 方法2: Match 查询（用于关键词搜索）

**适用场景：** 搜索包含多个关键词的文档，自动分词

```python
result = client.search(
    index="vt_parser_results",
    body={
        "query": {
            "match": {
                "command_executions.text": {
                    "query": "xterm tmp init_start",
                    "operator": "and"  # 所有词都必须存在
                }
            }
        }
    }
)
```

### 方法3: Term 查询（精确匹配）

**适用场景：** 精确匹配整个字段值

```python
result = client.search(
    index="vt_parser_results",
    body={
        "query": {
            "term": {
                "command_executions.keyword": "xterm -hold -e sh -c /tmp/init_start"
            }
        }
    }
)
```

### 方法4: Multi-Match 查询（跨字段搜索）

**适用场景：** 在多个字段中同时搜索

```python
result = client.search(
    index="vt_parser_results",
    body={
        "query": {
            "multi_match": {
                "query": "/tmp/malware.exe",
                "fields": [
                    "command_executions",
                    "processes_created",
                    "files_opened",
                    "files_dropped"
                ],
                "type": "phrase"  # 短语匹配
            }
        }
    }
)
```

### 方法5: Bool 复合查询（高级搜索）

**适用场景：** 组合多个条件

```python
result = client.search(
    index="vt_parser_results",
    body={
        "query": {
            "bool": {
                "must": [
                    # 必须包含xterm命令
                    {
                        "wildcard": {
                            "command_executions": "*xterm*"
                        }
                    }
                ],
                "should": [
                    # 最好包含这些MITRE战术
                    {
                        "term": {
                            "mitre_attack.tactics": "Execution"
                        }
                    }
                ],
                "filter": [
                    # 文件大小过滤
                    {
                        "range": {
                            "basic_info.file_metadata.file_size": {
                                "gte": 1024,
                                "lte": 10485760
                            }
                        }
                    }
                ]
            }
        }
    }
)
```

## 🔧 管理工具使用

### 查看索引信息

```bash
python manage_vt_index.py --info
```

输出示例：
```
📊 索引信息: vt_parser_results
============================================================
文档数量: 1234
存储大小: 45.67 MB
分片数量: 5

字段映射概览:
  - basic_info: nested
  - command_executions: wildcard
  - files_opened: wildcard
  ...
```

### 测试搜索查询

```bash
# 测试命令搜索
python manage_vt_index.py --search "xterm -hold -e sh -c /tmp/init_start"

# 测试文件路径搜索
python manage_vt_index.py --search "/tmp/malware.exe"

# 测试URL搜索
python manage_vt_index.py --search "http://evil.com/payload"
```

## 📊 性能对比

### 优化前
- 查询类型：Text 分词查询
- 搜索 `"xterm -hold -e sh"`：返回数千个包含任意单词的文档
- 相关性：❌ 低（大量误报）

### 优化后
- 查询类型：Wildcard 完整字符串查询
- 搜索 `"xterm -hold -e sh"`：只返回包含完整字符串的文档
- 相关性：✅ 高（精确匹配）

## 🎯 最佳实践

### 1. 选择合适的查询类型

| 查询需求 | 推荐查询类型 | 字段后缀 |
|---------|-------------|---------|
| 精确命令/路径搜索 | `wildcard` | 无后缀 |
| 关键词模糊搜索 | `match` | `.text` |
| 完全精确匹配 | `term` | `.keyword` |
| 跨字段搜索 | `multi_match` | 无后缀 |

### 2. 搜索字符串特殊字符处理

Wildcard查询中，以下字符需要转义：
- `*` - 通配符（不需要转义，除非要搜索字面星号）
- `?` - 单字符通配符
- `/` - 路径分隔符（不需要转义）

### 3. 性能优化建议

```python
# ✅ 好的做法：限制返回字段
result = client.search(
    index="vt_parser_results",
    body={
        "query": {...},
        "_source": ["basic_info.hashes.sha256", "command_executions"],  # 只返回需要的字段
        "size": 10  # 限制返回数量
    }
)

# ❌ 不好的做法：返回所有字段
result = client.search(
    index="vt_parser_results",
    body={
        "query": {...},
        "size": 1000  # 返回太多文档
    }
)
```

### 4. 分页查询

```python
# 使用 from + size 分页（适合浅层分页）
result = client.search(
    index="vt_parser_results",
    body={
        "query": {...},
        "from": 0,
        "size": 10
    }
)

# 使用 search_after 分页（适合深度分页）
result = client.search(
    index="vt_parser_results",
    body={
        "query": {...},
        "size": 10,
        "sort": [{"indexed_at": "desc"}],
        "search_after": [last_sort_value]  # 上一页最后一条的sort值
    }
)
```

## 🐛 故障排查

### 问题1: 搜索结果仍然不相关

**可能原因：** 索引映射未更新

**解决方法：**
```bash
# 1. 删除旧索引并重建
python manage_vt_index.py --recreate

# 2. 重新导入数据
python -m tasks.risk_ioc_into_es
```

### 问题2: 查询报错 "no such index"

**可能原因：** 索引不存在

**解决方法：**
```bash
python manage_vt_index.py --create
```

### 问题3: Wildcard查询太慢

**可能原因：** Wildcard以 `*` 开头会导致全表扫描

**优化方法：**
```python
# ❌ 慢查询
"value": "*target*"  # 前缀通配符会很慢

# ✅ 快查询
"value": "target*"   # 固定前缀会很快

# 🔄 折中方案：使用 ngram 分词器（需要重新配置mapping）
```

### 问题4: 特殊字符搜索问题

**示例：** 搜索包含反斜杠的路径

```python
# Windows路径搜索
query = r"C:\\Windows\\System32\\cmd.exe"  # 使用原始字符串
# 或
query = "C:\\\\Windows\\\\System32\\\\cmd.exe"  # 双转义
```

## 📚 参考资料

- [Elasticsearch Wildcard字段类型](https://www.elastic.co/guide/en/elasticsearch/reference/current/keyword.html#wildcard-field-type)
- [Elasticsearch Wildcard查询](https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-wildcard-query.html)
- [Elasticsearch 搜索性能优化](https://www.elastic.co/guide/en/elasticsearch/reference/current/tune-for-search-speed.html)

## 💡 快速参考

### 常用命令

```bash
# 索引管理
python manage_vt_index.py --info           # 查看索引信息
python manage_vt_index.py --create         # 创建索引
python manage_vt_index.py --recreate       # 重建索引

# 测试搜索
python manage_vt_index.py --search "关键词"
```

### Python搜索代码模板

```python
from engines.search.vt_parser import _get_es_client

client = _get_es_client()

# Wildcard搜索模板
result = client.search(
    index="vt_parser_results",
    body={
        "query": {
            "wildcard": {
                "command_executions": {
                    "value": "*your_search_term*",
                    "case_insensitive": True
                }
            }
        },
        "_source": ["basic_info.hashes.sha256", "command_executions"],
        "size": 10
    }
)

# 处理结果
for hit in result['hits']['hits']:
    sha256 = hit['_source']['basic_info']['hashes']['sha256']
    commands = hit['_source']['command_executions']
    print(f"SHA256: {sha256}")
    for cmd in commands:
        print(f"  - {cmd}")
```

---

**更新日期：** 2026-01-09
**版本：** 1.0
