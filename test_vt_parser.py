import json
from engines.search.vt_parser import extract_extended_vt_data

def summarize_json(data, key_threshold=40):
    """
    保留真实数据的结构提取器：
    1. list: 仅保留第一个元素的真实内容
    2. dict: 超过 40 个 key 时仅保留前 3 个，并标注剩余数量
    3. str: 长度超过 150 时截断并标注
    4. 其他: 保留原始值 (int, float, bool, None)
    """
    # 处理字典 (Object)
    if isinstance(data, dict):
        keys = list(data.keys())
        num_keys = len(keys)
        
        if num_keys > key_threshold:
            # 仅取前 3 个 key
            truncated_keys = keys[:3]
            summary = {k: summarize_json(data[k]) for k in truncated_keys}
            # 添加带有剩余数量说明的占位符
            summary[f"👉 ... ({num_keys - 3} more keys omitted)"] = "..."
            return summary
        else:
            return {k: summarize_json(v) for k, v in data.items()}
    
    # 处理列表 (Array)
    elif isinstance(data, list):
        if not data:
            return []
        # 仅展示第一个元素的真实内容
        return [summarize_json(data[0])]
    
    # 处理字符串 (String)
    elif isinstance(data, str):
        max_len = 150
        if len(data) > max_len:
            return data[:max_len] + f"... (truncated, total len: {len(data)})"
        return data
    
    # 其他基础类型直接返回原值
    return data

with open('vt.json', 'r', encoding='utf-8') as f:
    raw_data = json.load(f)

# summary = summarize_json(raw_data)
# print(summary)

# with open("vt_summary.json", 'w', encoding='utf-8') as f:
#     json.dump(summary, f, indent=4, ensure_ascii=False)

extended_data = extract_extended_vt_data(raw_data)
# print(extended_data)

with open("vt_extended_data.json", 'w', encoding='utf-8') as f:
    json.dump(extended_data, f, indent=4, ensure_ascii=False)
