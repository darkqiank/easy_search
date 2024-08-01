import requests
from bs4 import BeautifulSoup


class TPLink():
    """tplink官网爬虫
    """

    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36",
            "Content-Type": "text/html; charset=GBK"
        }

    def get_all_wireless_routers(self):
        res = requests.get(url='https://www.tp-link.com.cn/product_list_wirelessrouter.action',
                           headers=self.headers)
        product_list = res.json().get("productList")
        data_list = []
        for p in product_list:
            title = 'TP-LINK ' + p.get("productModel")
            print(title)
            details = [p.get("productName")]
            pro_id = p.get("id")
            more_url = f'https://www.tp-link.com.cn/product_{pro_id}.html?v=specification'
            more_url_v2 = f'https://www.tp-link.com.cn/product_{pro_id}.html?source=detail#productSpe'
            # print(more_url)
            more_details = self.parse_more(more_url)
            if not more_details:
                print("爬取第二次", more_url_v2)
                more_details = self.parse_more_v2(more_url_v2)
            data_list.append({
                "title": title,
                "details": details,
                "more_details": more_details,
                "price": "",
                "more_url": more_url
            })
        return data_list

    def parse_more(self, detail_url):
        try:
            res = requests.get(url=detail_url, headers=self.headers)
            html = res.text
            soup = BeautifulSoup(html, 'html.parser')
            items = soup.find('ul', id="productData").findAll('li')
            dict_ = {}
            for item in items:
                dataTitle = str(item.find('div', class_='dataTitle').text).strip()
                dataDetail = str(item.find('div', class_='dataDetail').text).strip()
                dict_[dataTitle] = dataDetail
            return dict_
        except Exception as e:
            print("爬取失败", e, "行号：", e.__traceback__.tb_lineno)
            return None

    def parse_more_v2(self, detail_url):
        # <div id="productSpe">
        try:
            res = requests.get(url=detail_url, headers=self.headers)
            html = res.text
            soup = BeautifulSoup(html, 'html.parser')
            tables = soup.findAll('table', class_="speDetail")
            dict_ = {}
            for table in tables:
                tds = table.findAll('td')
                for td in tds:
                    h = str(td.find('span').text).strip()
                    d = str(td.find('ul').text).strip()
                    dict_[h] = d
            return dict_
        except Exception as e:
            print("爬取失败", e, "行号：", e.__traceback__.tb_lineno)
            return None


if __name__ == '__main__':
    tp = TPLink()
    res = tp.get_all_wireless_routers()
    print(res)