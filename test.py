# from engines import DDGS

# with DDGS(proxies="socks5://127.0.0.1:10808", timeout=10,
#           ddgs_end_point='https://ddgs.catflix.cn',
#           ddgslink_end_point='https://ddgslink.catflix.cn') as ddgs:
#     for r in ddgs.text('xiaoniu321.com',
#                        max_results=10,
#                        # region='wt-wt',
#                         region='cn-zh'
#                        ):
#         print(r)


from engines import DDGS_V2 as DDGS

with DDGS(proxies="socks5://127.0.0.1:10808", 
        #   ddgs_end_point='https://proxy.451964719.xyz/proxy/https://html.duckduckgo.com',
          ddgs_end_point='https://ddgs.catflix.cn',
          timeout=10) as ddgs:
    for r in ddgs.text('baiduwangpan.cc',
                       max_results=10,
                       # region='wt-wt',
                        region='cn-zh'
                       ):
        print(r)


# with DDGS(timeout=10,
#           ddgs_end_point='https://proxy.451964719.xyz/proxy/https://duckduckgo.com',
#           ddgslink_end_point='https://proxy.451964719.xyz/proxy/https://links.duckduckgo.com') as ddgs:
#     for r in ddgs.text('xiaoniu321.com',
#                        max_results=10,
#                        # region='wt-wt',
#                         region='cn-zh'
#                        ):
#         print(r)
