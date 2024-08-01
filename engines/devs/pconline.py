from engines.client import Client
import urllib.parse
from bs4 import BeautifulSoup
import re
import time


class PCOnline(Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._asession.headers["sec-ch-ua-mobile"] = "?0"
        self._asession.headers[
            "accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        self._asession.headers["Referer"] = "https://www.pconline.com.cn/"
        self._asession.headers["Accept-Ianguage"] = "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6"

        # 中关村在线报价网
        self.base_url = "https://product.pconline.com.cn/"

    def search_dev(self, *args, **kwargs):
        return self._run_async_in_thread(self._search_dev(*args, **kwargs))

    async def _search_dev(self, dev_name, small_type="无线路由器", max_num=20):
        """查找路由器

        Args:
            dev_name (str): [设备搜索关键词]
            small_type 检索类型
            max_num 检索个数
        """
        try:
            # <ul class="list-items list-type-tw" id="Jitems">
            # li class="item"
            q_word = urllib.parse.quote(dev_name.encode("GBK"))
            small_type_word = urllib.parse.quote(small_type.encode("GBK"))
            search_url = f"https://ks.pconline.com.cn/product.shtml?q={q_word}&smallType={small_type_word}"
            print(search_url)
            html = await self._aget_url("GET", search_url)
            # print(html)
            soup = BeautifulSoup(html, 'html.parser')
            items = soup.find('ul', id="Jitems").findAll("li", class_="item")
            # print(len(items))
            dict_list = []
            for item in items:
                title = str(item.find("a", class_="item-name").text).strip()
                # print(title)
                desc = item.find("span", class_="item-des").text
                details = [v.strip() for v in desc.split("|")]
                detail_url = item.find("a", class_="item-name")['href']
                more_url = "https:" + detail_url.rsplit(".", 1)[0] + "_detail.html"
                print(more_url)
                # price = item.find("div", class_="price price-now").text
                # price_url = item.find("div", class_="price price-now")['href']
                price_box = item.find("div", attrs={"class": re.compile(r"price(\s\w+).")})
                price = price_box.text
                more_details = await self._parse_more(more_url)
                dict_list.append(
                    {
                        "title": title,
                        "details": details,
                        "more_details": more_details,
                        "price": price,
                        "more_url": more_url
                    }
                )
                if len(dict_list) > max_num:
                    # 返回最多10条结果
                    break
                    time.sleep(0.2)
            return dict_list
        except Exception as e:
            print("爬取失败 _search_dev", e, "行号：", e.__traceback__.tb_lineno, "dev_name：", dev_name)
            return None

    def get_page_info(self, *args, **kwargs):
        return self._run_async_in_thread(self._get_page_info(*args, **kwargs))

    async def _get_page_info(self, page_url):
        """查找产品页面所有信息

        Args:
            router_name (str): [路由器搜索关键词]
        """
        try:
            html = await self._aget_url("GET", page_url)
            soup = BeautifulSoup(html, 'html.parser')
            items = soup.find("ul", id="JlistItems").findAll('li', class_="item")
            # <ul class="list-items list-type-lb clearfix" id="JlistItems">
            # <li class="item">
            dict_list = []
            for item in items:
                a = item.find("a", class_="item-title-name")
                title = str(a.text).strip()
                print(title)
                more_url = 'https:' + str(item.find("a", class_="more-specs")['href'])
                print(more_url)
                p = item.find("div", class_="price price-now")
                price = None
                if p is not None:
                    price = p.text
                    print(price)
                more_details = await self._parse_more(more_url)
                dict_list.append({"title": title,
                                  "more_details": more_details,
                                  "price": price,
                                  "more_url": more_url
                                  })
            print(dict_list)
            return dict_list
        except Exception as e:
            print("爬取失败 _get_page_info", e, "行号：", e.__traceback__.tb_lineno)
            return None

    async def _parse_more(self, detail_url):
        try:
            html = await self._aget_url("GET", detail_url)
            soup = BeautifulSoup(html, 'html.parser')
            d = soup.find("div", id="area-detailparams")
            trs = d.findAll('tr', class_="")
            dict_ = {}
            for tr in trs:
                th = tr.find('th')
                td = tr.find('td')
                if th:
                    h = str(th.text).strip()
                if td:
                    # 移除所有 class="tips" 的 div 元素
                    for div in td.find_all('div', class_='tips'):
                        div.decompose()
                    for div in td.find_all('div', class_='fr'):
                        div.decompose()
                    # d = str(td.text).strip()
                    d = td.get_text(strip=True, separator='')
                # print(h, d)
                dict_[h] = d
            # print(dict_)
            return dict_
        except Exception as e:
            print("爬取失败 _parse_more", e, "行号：", e.__traceback__.tb_lineno)
            return None

    @staticmethod
    def normalizingInfo(dict_):
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
            more_details = dict_["more_details"]
            router_bandwith = more_details.get("无线速率")
            # net = [more_details.get("协议标准"), more_details.get("协议标准")]
            wifi_fields = ("协议标准", "无线标准")
            net = next((more_details[field] for field in wifi_fields if more_details.get(field)), None)
            if net:
                if net.find("n") != -1:
                    router_wifi6 = "4"
                if net.find("ac") != -1:
                    router_wifi6 = "5"
                if net.find("ax") != -1:
                    router_wifi6 = "6"
                if net.find("be") != -1:
                    router_wifi6 = "7"
            router_dual = more_details.get("工作频段")
            lan_fields = ("接口", "局域网接口", "广域网接口")
            router_lan = ' '.join((more_details[field] for field in lan_fields if more_details.get(field)))
            router_price = dict_.get("price")
            router_year = ""
        return {"router_name": router_name,
                "router_bandwith": router_bandwith,
                "router_wifi6": router_wifi6,
                "router_dual": router_dual,
                "router_lan": router_lan,
                "router_price": router_price,
                "router_year": router_year,
                "more_url": dict_.get("more_url")
                }
