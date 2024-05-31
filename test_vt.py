from engines import VT
import json

with VT(proxies="socks5://100.77.221.27:7890", timeout=20) as vt:
    res = vt.api(input_str='74.211.105.19')
    with open('vt.json', 'w', encoding='utf-8') as f:
        json.dump(res, f, ensure_ascii=False, indent=4)
