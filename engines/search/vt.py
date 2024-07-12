from engines.client import Client
import time
import random
import base64
import orjson
import asyncio
from typing import Any
import tldextract
import ipaddress

from engines.exceptions import NotFoundException
from engines.ua_tools import random_impersonate


class VT(Client):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._asession.headers["sec-ch-ua-mobile"] = "?0"
        self._asession.headers["content-type"] = "application/json"
        self._asession.headers["accept"] = "application/json"
        self._asession.headers["Referer"] = "https://www.virustotal.com/"
        self._asession.headers["Accept-Ianguage"] = "en-US,en;q=0.9,es;q=0.8"
        self._asession.headers[
            "X-VT-Anti-Abuse-Header"] = "MTE3NTMwOTMwOTQtWkc5dWRDQmlaU0JsZG1scy0xNzE2MzQ1MDI4LjQ1OQ=="

    def api(self, input_str: str) -> Any:
        if is_ip_address(input_str):
            return self._run_async_in_thread(self._ip_api(input_str))
        elif is_domain(input_str):
            return self._run_async_in_thread(self._domain_api(input_str))
        else:
            return self._run_async_in_thread(self._file_api(input_str))

    @staticmethod
    async def run_task_with_retries(task_func, *args, retries=3, retry_wait=2):
        attempt = 0
        while attempt < retries:
            try:
                return await task_func(*args)
            except NotFoundException as ex:
                # print(f"Task {task_func.__name__} failed with {ex}. Not retrying due to NotFoundException.")
                raise
            except Exception as ex:
                attempt += 1
                print(f"Retrying... Attempt {attempt}/{retries} Task {task_func.__name__} failed with {ex}.")
                if attempt >= retries:
                    raise
                await asyncio.sleep(retry_wait)

    async def _domain_api(self, domain: str):
        report = {'id': domain,
                  'dtype': 'domain'
                  }

        async def _analyse(dm) -> None:
            url = f'https://www.virustotal.com/ui/domains/{dm}'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            # 获取分析结果，如果键不存在则返回一个空字典
            last_analysis_results = res_json.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
            # 过滤结果
            filtered_results = {key: value for key, value in last_analysis_results.items() if
                                value.get("category") in ["suspicious", "malicious"]}
            # 将过滤后的结果更新到原始JSON中，确保所有中间键都存在
            if "data" not in res_json:
                res_json["data"] = {}
            if "attributes" not in res_json["data"]:
                res_json["data"]["attributes"] = {}
            res_json["data"]["attributes"]["last_analysis_results"] = filtered_results
            report['analyse'] = res_json

        async def _resolutions(dm) -> None:
            url = f'https://www.virustotal.com/ui/domains/{dm}/resolutions'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            report['resolutions'] = orjson.loads(res)

        async def _referrer_files(dm) -> None:
            url = f'https://www.virustotal.com/ui/domains/{dm}/referrer_files'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            for data in res_json.get("data", []):
                # 确保 "attributes" 键存在，如果不存在，则跳过这个数据项
                if "attributes" not in data:
                    continue
                data["attributes"]["pe_info"] = None
                filtered_results = {key: value for key, value in
                                    data["attributes"].get("last_analysis_results", {}).items() if
                                    value["category"] in ["suspicious", "malicious"]}
                data["attributes"]["last_analysis_results"] = filtered_results
            report['referrer_files'] = res_json

        async def _communicating_files(dm) -> None:
            url = f'https://www.virustotal.com/ui/domains/{dm}/communicating_files'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            for data in res_json.get("data", []):
                # 确保 "attributes" 键存在，如果不存在，则跳过这个数据项
                if "attributes" not in data:
                    continue
                data["attributes"]["pe_info"] = None
                # 确保 "last_analysis_results" 键存在，如果不存在，则跳过过滤步骤
                filtered_results = {key: value for key, value in
                                    data["attributes"].get("last_analysis_results", {}).items() if
                                    value["category"] in ["suspicious", "malicious"]}
                data["attributes"]["last_analysis_results"] = filtered_results
            report['communicating_files'] = res_json

        async def _subdomains(dm) -> None:
            url = f'https://www.virustotal.com/ui/domains/{dm}/subdomains?relationships=resolutions'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            for data in res_json.get("data", []):
                # 确保 "attributes" 键存在，如果不存在，则跳过这个数据项
                if "attributes" not in data:
                    continue
                filtered_results = {key: value for key, value in
                                    data["attributes"].get("last_analysis_results", {}).items() if
                                    value["category"] in ["suspicious", "malicious"]}
                data["attributes"]["last_analysis_results"] = filtered_results
            report['subdomains'] = res_json

        tasks = [
            self.run_task_with_retries(_analyse, domain),
            self.run_task_with_retries(_resolutions, domain),
            self.run_task_with_retries(_referrer_files, domain),
            self.run_task_with_retries(_communicating_files,domain),
            self.run_task_with_retries(_subdomains,domain)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return report

    async def _ip_api(self, ip: str):
        report = {'id': ip,
                  'dtype': 'ip'
                  }

        async def _analyse(_ip) -> None:
            url = f'https://www.virustotal.com/ui/ip_addresses/{_ip}'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            # 获取分析结果，如果键不存在则返回一个空字典
            print(res_json)
            last_analysis_results = res_json.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
            # 过滤结果
            filtered_results = {key: value for key, value in last_analysis_results.items() if
                                value.get("category") in ["suspicious", "malicious"]}
            # 将过滤后的结果更新到原始JSON中，确保所有中间键都存在
            if "data" not in res_json:
                res_json["data"] = {}
            if "attributes" not in res_json["data"]:
                res_json["data"]["attributes"] = {}
            res_json["data"]["attributes"]["last_analysis_results"] = filtered_results
            report['analyse'] = res_json

        async def _resolutions(_ip) -> None:
            url = f'https://www.virustotal.com/ui/ip_addresses/{_ip}/resolutions'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            report['resolutions'] = orjson.loads(res)

        async def _referrer_files(_ip) -> None:
            url = f'https://www.virustotal.com/ui/ip_addresses/{_ip}/referrer_files'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            for data in res_json.get("data", []):
                # 确保 "attributes" 键存在，如果不存在，则跳过这个数据项
                if "attributes" not in data:
                    continue
                data["attributes"]["pe_info"] = None
                # 确保 "last_analysis_results" 键存在，如果不存在，则跳过过滤步骤
                filtered_results = {key: value for key, value in
                                    data["attributes"].get("last_analysis_results", {}).items() if
                                    value["category"] in ["suspicious", "malicious"]}
                data["attributes"]["last_analysis_results"] = filtered_results
            report['referrer_files'] = res_json

        async def _communicating_files(_ip) -> None:
            url = f'https://www.virustotal.com/ui/ip_addresses/{_ip}/communicating_files'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            for data in res_json.get("data", []):
                # 确保 "attributes" 键存在，如果不存在，则跳过这个数据项
                if "attributes" not in data:
                    continue
                data["attributes"]["pe_info"] = None
                # 确保 "last_analysis_results" 键存在，如果不存在，则跳过过滤步骤
                filtered_results = {key: value for key, value in
                                    data["attributes"].get("last_analysis_results", {}).items() if
                                    value["category"] in ["suspicious", "malicious"]}
                data["attributes"]["last_analysis_results"] = filtered_results
            report['communicating_files'] = res_json

        tasks = [
            self.run_task_with_retries(_analyse, ip),
            self.run_task_with_retries(_resolutions, ip),
            self.run_task_with_retries(_referrer_files, ip),
            self.run_task_with_retries(_communicating_files, ip)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return report

    async def _file_api(self, file: str):
        report = {'id': file,
                  'dtype': 'files'
                  }

        async def _analyse(_file) -> None:
            url = f'https://www.virustotal.com/ui/files/{_file}'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            # 获取分析结果，如果键不存在则返回一个空字典
            last_analysis_results = res_json.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
            # 过滤结果
            filtered_results = {key: value for key, value in last_analysis_results.items() if
                                value.get("category") in ["suspicious", "malicious"]}
            # 将过滤后的结果更新到原始JSON中，确保所有中间键都存在
            if "data" not in res_json:
                res_json["data"] = {}
            if "attributes" not in res_json["data"]:
                res_json["data"]["attributes"] = {}
            res_json["data"]["attributes"]["pe_info"] = None
            res_json["data"]["attributes"]["last_analysis_results"] = filtered_results
            report['analyse'] = res_json

        async def _contacted_urls(_file) -> None:
            url = f'https://www.virustotal.com/ui/files/{_file}/contacted_urls'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            for data in res_json.get("data", []):
                # 确保 "attributes" 键存在，如果不存在，则跳过这个数据项
                if "attributes" not in data:
                    continue
                data["attributes"]["pe_info"] = None
                # 确保 "last_analysis_results" 键存在，如果不存在，则跳过过滤步骤
                filtered_results = {key: value for key, value in
                                    data["attributes"].get("last_analysis_results", {}).items() if
                                    value["category"] in ["suspicious", "malicious"]}
                data["attributes"]["last_analysis_results"] = filtered_results
            report['contacted_urls'] = res_json

        async def _contacted_domains(_file) -> None:
            url = f'https://www.virustotal.com/ui/files/{_file}/contacted_domains'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            for data in res_json.get("data", []):
                # 确保 "attributes" 键存在，如果不存在，则跳过这个数据项
                if "attributes" not in data:
                    continue
                data["attributes"]["pe_info"] = None
                # 确保 "last_analysis_results" 键存在，如果不存在，则跳过过滤步骤
                filtered_results = {key: value for key, value in
                                    data["attributes"].get("last_analysis_results", {}).items() if
                                    value["category"] in ["suspicious", "malicious"]}
                data["attributes"]["last_analysis_results"] = filtered_results
            report['contacted_domains'] = res_json

        async def _contacted_ips(_file) -> None:
            url = f'https://www.virustotal.com/ui/files/{_file}/contacted_ips'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            for data in res_json.get("data", []):
                # 确保 "attributes" 键存在，如果不存在，则跳过这个数据项
                if "attributes" not in data:
                    continue
                data["attributes"]["pe_info"] = None
                # 确保 "last_analysis_results" 键存在，如果不存在，则跳过过滤步骤
                filtered_results = {key: value for key, value in
                                    data["attributes"].get("last_analysis_results", {}).items() if
                                    value["category"] in ["suspicious", "malicious"]}
                data["attributes"]["last_analysis_results"] = filtered_results
            report['contacted_ips'] = res_json

        tasks = [
            self.run_task_with_retries(_analyse, file),
            self.run_task_with_retries(_contacted_urls, file),
            self.run_task_with_retries(_contacted_domains, file),
            self.run_task_with_retries(_contacted_ips, file)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        print(report.keys())
        return report


def is_ip_address(input_str):
    try:
        ipaddress.ip_address(input_str)
        return True
    except ValueError:
        return False


def is_domain(input_str):
    extracted = tldextract.extract(input_str)
    return bool(extracted.domain) and bool(extracted.suffix)


def categorize_input(input_str):
    if is_ip_address(input_str):
        return "ip"
    elif is_domain(input_str):
        return "domain"
    else:
        return "file"


def random_vt_ua_headers():
    impersonate, ua_headers = random_impersonate()
    ua_headers["X-VT-Anti-Abuse-Header"] = get_vt_anti()
    ua_headers["X-App-Version"] = 'v1x278x0'
    ua_headers["X-Tool"] = 'vt-ui-main'
    return impersonate, ua_headers


def get_vt_anti():
    # 获取当前时间的秒数
    current_time = time.time()

    # 生成一个随机数
    random_number = 1e10 * (1 + random.random() % 5e4)

    # 如果随机数小于50，设置为"-1"，否则格式化为无小数点的字符串
    if random_number < 50:
        random_number_str = "-1"
    else:
        random_number_str = f"{int(random_number)}"
    # 拼接字符串
    combined_string = f"{random_number_str}-ZG9udCBiZSBldmls-{current_time:.3f}"

    # 转换为Base64编码
    encoded_string = base64.b64encode(combined_string.encode()).decode()

    return encoded_string


# 调用函数并打印结果
# print(get_vt_anti())
print(categorize_input('baidu.com'))
