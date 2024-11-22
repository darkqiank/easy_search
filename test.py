from engines import DDGS

with DDGS(proxies="socks5://127.0.0.1:10808", timeout=10,
          ddgs_end_point='https://ddgs.catflix.cn',
          ddgslink_end_point='https://ddgslink.catflix.cn') as ddgs:
    for r in ddgs.text('xiaoniu321.com',
                       max_results=10,
                       # region='wt-wt',
                        region='cn-zh'
                       ):
        print(r)