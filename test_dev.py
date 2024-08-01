from engines import PCOnline, ZOL

# with PCOnline() as pcol:
#     # res = zol.search_dev('小米')
#     res = pcol.get_page_info("https://product.pconline.com.cn/wireless_router/list_s1.shtml")
#     for info in res:
#         print(pcol.normalizingInfo(info))
#     # res = pcol.get_page_info("https://product.pconline.com.cn/mobile/list_25s1.shtml")
#     # print(res)

with ZOL() as zol:
    # res = zol.search_dev('小米', subcate_id=227, max_num=1)
    res = zol.get_page_info('https://detail.zol.com.cn/wireless_router/zhejiang/new.html')
    for info in res:
        print(zol.normalizingRouterInfo(info))
    # print(res)
