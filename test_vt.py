from engines import VT
import json
import time
import random


def get_rand_vt_end_point():
    vt_end_points = ["https://www.virustotal.com/",
                     "https://vtfastlycdn.451964719.xyz/",
                     "https://vtgcorecdn.451964719.xyz/"
                     ]
    weights = [0.7, 0.3, 0.1]
    vt_end_point = random.choices(vt_end_points, weights=weights, k=1)[0]
    return vt_end_point


for i in range(1):
    print(i)
    start_time = time.time()
    with VT(proxies="socks5://100.77.221.27:7890", timeout=10, vt_end_point="https://vtfastlycdn.451964719.xyz/") as vt:
        res = vt.api(input_str='sougo.com')
        # res = vt.api(input_str='baidu.com')
        with open('vt.json', 'w', encoding='utf-8') as f:
            json.dump(res, f, ensure_ascii=False, indent=4)
    end_time = time.time()
    print(f"Total time taken: {end_time-start_time} seconds")
