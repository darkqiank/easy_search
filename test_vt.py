from engines import VT
import json
import time
import os
import traceback

files = os.listdir('/Users/jiankaiwang/Documents/工作文档/29-安全能力/vt_test/results/')

# with VT(proxies="socks5://100.77.221.27:7890", timeout=20) as vt:
#     res = vt.api(input_str='38.207.164.225')

start_time = time.time()
with open('/Users/jiankaiwang/Documents/工作文档/29-安全能力/vt_test/test_ips.txt', 'r') as f:
    lines = f.readlines()
    inputs = [str(line).strip() for line in lines]
datas = inputs
succeed = 0
failed = 0
total = len(datas)
for _input in datas:
    print(f"stats: succeed {succeed}/failed {failed}/total {total}")
    try:
        if f'{_input}.json' in files:
            succeed += 1
            continue
        with VT(proxies="socks5://100.77.221.27:7890", timeout=20) as vt:
            res = vt.api(input_str=_input)
            with open(f'/Users/jiankaiwang/Documents/工作文档/29-安全能力/vt_test/results/{_input}.json', 'w', encoding='utf-8') as f:
                # 用orjson保存res到f中
                json.dump(res, f, ensure_ascii=False, indent=4)
        succeed += 1
    except Exception as e:
        print(e)
        traceback.print_exc()
        failed += 1
end_time = time.time()
# Print performance statistics
elapsed_time = end_time - start_time
print(f"Total time taken: {elapsed_time:.2f} seconds")
print(f"Average time per query: {elapsed_time / len(datas):.2f} seconds")
