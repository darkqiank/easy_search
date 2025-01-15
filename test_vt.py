from engines import VT
import json
import time
import random


def get_rand_vt_end_point():
    vt_end_points = ["https://www.virustotal.com/",
                     "https://vtfastlycdn.451964719.xyz/",
                     "https://vtcdn.darkqiank.work/",
                     # "https://vtgcorecdn.451964719.xyz/"
                     "https://proxy.451964719.xyz/proxy/https://www.virustotal.com/"
                     ]
    weights = [0.1, 0.1, 0.1, 1]
    vt_end_point = random.choices(vt_end_points, weights=weights, k=1)[0]
    return vt_end_point


for i in range(1):
    print(i)
    start_time = time.time()
    with VT(
            proxies="socks5://127.0.0.1:10808",
            timeout=10, vt_end_point=get_rand_vt_end_point()) as vt:
        # res = vt.api(input_str='413d0aacddad41105f9f04de12cae9420919083796ed856df47ee2c7b3767fda')
        res = vt.cf_api(input_str='413d0aacddad41105f9f04de12cae9420919083796ed856df47ee2c7b3767fda')
        # res = vt.api(input_str='baidu.com')
        # res = vt.cf_api(input_str='baidu.com')
        # res = vt.api(input_str='comments')
        with open('vt.json', 'w', encoding='utf-8') as f:
            json.dump(res, f, ensure_ascii=False, indent=4)
    end_time = time.time()
    print(f"Total time taken: {end_time-start_time} seconds")
