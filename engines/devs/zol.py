from engines.client import Client
import urllib.parse
from bs4 import BeautifulSoup
import time


class ZOL(Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._asession.headers["sec-ch-ua-mobile"] = "?0"
        self._asession.headers["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        self._asession.headers["Referer"] = "https://www.zol.com.cn/"
        self._asession.headers["Accept-Ianguage"] = "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"
        self._asession.headers["Cookie"] = f"ip_ck=5cCJ5vj2j7QuMjc4MTIxLjE3MjI0ODg2MDE%3D; lv={int(time.time())}; vn=1; z_day=rdetail=1; z_pro_city=s_provice%3Dzhejiang%26s_city%3Dhangzhou; questionnaire_pv={int(time.time())}"

        # 中关村在线报价网
        self.base_url = "https://detail.zol.com.cn"

    def search_dev(self, *args, **kwargs):
        return self._run_async_in_thread(self._search_dev(*args, **kwargs))

    async def _search_dev(self, dev_name, subcate_id=227, max_num=20):
        # subcateId = 57 手机
        # subcateId = 227 无线路由器
        try:
            q_word = urllib.parse.quote(dev_name.encode("GBK"))
            search_url = f"https://detail.zol.com.cn/index.php?c=SearchList&subcateId={subcate_id}&keyword={q_word}"
            html = await self._aget_url("GET", search_url)
            soup = BeautifulSoup(html, 'html.parser')
            items = soup.findAll("div", class_="list-item clearfix")
            dict_list = []
            for item in items:
                title = str(item.find("a", class_="title").text).strip()
                lis = item.findAll("li")
                details = [l.text for l in item.findAll("li")]
                price = item.find("div", class_="price-box").find("b", class_="price-type").text
                more_details = None
                more_url = None
                if len(lis) >= 1:
                    more = lis[-1].find("a")
                    if more is not None:
                        more_url = more["href"]
                        if more_url:
                            detail_url = self.base_url + more_url
                            more_details = await self._parse_more(detail_url)
                dict_list.append({"title": title,
                                  "details": details,
                                  "more_details": more_details,
                                  "price": price,
                                  "more_url": self.base_url + more_url if more_url else None})
                if len(dict_list) > max_num:
                    # 返回最多10条结果
                    break
                time.sleep(0.2)
            #                 time.sleep(1)
            return dict_list
        except Exception as e:
            print("爬取失败 _search_dev", e, "行号：", e.__traceback__.tb_lineno, "dev_name：", dev_name)
            return None

    def get_page_info(self, *args, **kwargs):
        return self._run_async_in_thread(self._get_page_info(*args, **kwargs))

    async def _get_page_info(self, page_url):
        try:
            html = await self._aget_url("GET", page_url)
            soup = BeautifulSoup(html, 'html.parser')
            items = soup.findAll("div", class_="list-item clearfix")
            dict_list = []
            for item in items:
                intro = item.find("div", class_="pro-intro")
                # print(intro)
                title = str(intro.find("h3").text).strip()
                price = item.find("div", class_="price-box").find("b", class_="price-type").text
                param = intro.find("ul", class_="param clearfix")
                if param is None:
                    param = intro.find("ul", class_="param param-lt-5 clearfix")
                lis = param.findAll("li")
                details = [str(l.text).strip() for l in item.findAll("li")]
                more_details = None
                more_url = None
                if len(lis) >= 1:
                    more = lis[-1].find("a")
                    if more is not None:
                        more_url = more["href"]
                        if more_url:
                            detail_url = self.base_url + more_url
                            more_details = await self._parse_more(detail_url)
                dict_list.append({"title": title,
                                  "details": details,
                                  "more_details": more_details,
                                  "price": price,
                                  "more_url": self.base_url + more_url if more_url is not None else None})
                time.sleep(0.2)
            return dict_list
        except Exception as e:
            print("爬取失败 _get_page_info", e, "行号：", e.__traceback__.tb_lineno)
            return None

    async def _parse_more(self, detail_url):
        try:
            html = await self._aget_url("GET", detail_url)
            soup = BeautifulSoup(html, 'html.parser')
            details = soup.find("div", class_="detailed-parameters")
            dict_ = {}
            tables = details.findAll("table")
            for table in tables:
                trs = table.findAll("tr")
                for tr in trs:
                    th = tr.find("th")
                    td = tr.find("td")
                    if th is not None and td is not None:
                        dict_[th.text.strip()] = td.text.strip().strip("纠错").replace("\r", " ").replace("\n", " ")
            return dict_
        except Exception as e:
            print("获取详情失败 _parse_more")
            return None

    @staticmethod
    def normalizingRouterInfo(dict_):
        """[标准化信息]

        Args:
            dict_ ([dict]): [原始信息]

        Returns:
            [dict]: [标准信息]
        """
        router_name = dict_.get("title")
        router_bandwith = None
        router_wifi6 = None
        router_dual = None
        router_lan = None
        router_price = None
        router_year = None
        if dict_.get("more_details"):
            if "最高传输速率" in dict_["more_details"]:
                router_bandwith = dict_.get("more_details")["最高传输速率"]
            if "网络标准" in dict_["more_details"]:
                net =  dict_.get("more_details")["网络标准"]
                if net.find("n")!=-1:
                    router_wifi6="4"
                if net.find("ac")!=-1:
                    router_wifi6="5"
                if net.find("ax")!=-1:
                    router_wifi6="6"
                if net.find("be")!=-1:
                    router_wifi6="7"
            if "频率范围" in dict_["more_details"]:
                router_dual = dict_.get("more_details")["频率范围"]
            if "网络接口" in dict_["more_details"]:
                router_lan = dict_.get("more_details")["网络接口"]
            router_price = dict_.get("price")
            router_year = ""
        return { "router_name":router_name,
                "router_bandwith":router_bandwith,
                "router_wifi6":router_wifi6,
                "router_dual":router_dual,
                "router_lan":router_lan,
                "router_price":router_price,
                "router_year":router_year,
                "more_url":dict_.get("more_url")
        }


