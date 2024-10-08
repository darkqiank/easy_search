from engines import DDGS

with DDGS(proxies="socks5://100.77.221.27:7890", timeout=10) as ddgs:
    for r in ddgs.text('xiaoniu321.com',
                       max_results=10,
                       # region='wt-wt',
                        region='cn-zh'
                       ):
        print(r)