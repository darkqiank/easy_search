from engines import DDGS

with DDGS(proxies="socks5://100.116.50.51:7890", timeout=20) as ddgs:
    for r in ddgs.text('xiaoniu321.com',
                       max_results=10,
                       # region='wt-wt',
                        region='cn-zh'
                       ):
        print(r)