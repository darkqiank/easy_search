from engines.client import Client
import time
import random
import base64
import orjson
import asyncio
from typing import Any
import tldextract
import ipaddress
import re
from urllib.parse import quote
from urllib.parse import urlparse, urlunparse, urlencode

from engines.exceptions import NotFoundException
from engines.random_tools import random_impersonate, generate_random_public_ip


class VT(Client):

    def __init__(self, *args, **kwargs):
        self.vt_end_point = kwargs.pop('vt_end_point', 'https://www.virustotal.com/')
        self.cf_end_point = kwargs.pop('cf_end_point', 'https://vt.451964719.xyz/')
        super().__init__(*args, **kwargs)
        self._asession.headers["sec-ch-ua-mobile"] = "?0"
        self._asession.headers["content-type"] = "application/json"
        self._asession.headers["accept"] = "application/json"
        self._asession.headers["Referer"] = "https://www.virustotal.com/"
        self._asession.headers["Accept-Ianguage"] = "en-US,en;q=0.9,es;q=0.8"
        self._asession.headers[
            "X-VT-Anti-Abuse-Header"] = "MTE3NTMwOTMwOTQtWkc5dWRDQmlaU0JsZG1scy0xNzE2MzQ1MDI4LjQ1OQ=="

    def api(self, input_str: str) -> Any:
        if input_str == "comments":
            return self._run_async_in_thread(self._comments_api())

        if input_str.startswith('user/'):
            u = input_str[len('user/'):]
            return self._run_async_in_thread(self._user_api(u))

        if is_ip_address(input_str):
            return self._run_async_in_thread(self._ip_api(input_str))
        elif is_domain(input_str):
            return self._run_async_in_thread(self._domain_api(input_str))
        else:
            hash_type = identify_hash(input_str)
            if hash_type in ('MD5', 'SHA-1'):
                return self._run_async_in_thread(self._search_api(input_str))
            elif hash_type == 'SHA-256':
                return self._run_async_in_thread(self._file_api(input_str))

    def cf_api(self, input_str: str, dtype: str = None, cursor: str = None) -> Any:
        return self._run_async_in_thread(self._cf_api(input_str, dtype, cursor))


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
            url = f'{self.vt_end_point}ui/domains/{dm}'
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
            url = f'{self.vt_end_point}ui/domains/{dm}/resolutions'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            report['resolutions'] = orjson.loads(res)

        async def _referrer_files(dm) -> None:
            url = f'{self.vt_end_point}ui/domains/{dm}/referrer_files'
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
            url = f'{self.vt_end_point}ui/domains/{dm}/communicating_files'
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
            url = f'{self.vt_end_point}ui/domains/{dm}/subdomains?relationships=resolutions'
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

        async def _siblings(dm) -> None:
            url = f'{self.vt_end_point}ui/domains/{dm}/siblings?relationships=resolutions'
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
            report['siblings'] = res_json

        async def _comments(dm) -> None:
            url = f'{self.vt_end_point}ui/domains/{dm}/comments?relationships=item%2Cauthor'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            report['comments'] = res_json

        tasks = [
            self.run_task_with_retries(_analyse, domain),
            self.run_task_with_retries(_resolutions, domain),
            self.run_task_with_retries(_referrer_files, domain),
            self.run_task_with_retries(_communicating_files, domain),
            self.run_task_with_retries(_subdomains, domain),
            self.run_task_with_retries(_siblings, domain),
            self.run_task_with_retries(_comments, domain)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return report

    async def _ip_api(self, ip: str):
        report = {'id': ip,
                  'dtype': 'ip'
                  }

        async def _analyse(_ip) -> None:
            url = f'{self.vt_end_point}ui/ip_addresses/{_ip}'
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
            url = f'{self.vt_end_point}ui/ip_addresses/{_ip}/resolutions'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            report['resolutions'] = orjson.loads(res)

        async def _referrer_files(_ip) -> None:
            url = f'{self.vt_end_point}ui/ip_addresses/{_ip}/referrer_files'
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
            url = f'{self.vt_end_point}ui/ip_addresses/{_ip}/communicating_files'
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

        async def _comments(_ip) -> None:
            url = f'{self.vt_end_point}ui/ip_addresses/{_ip}/comments?relationships=item%2Cauthor'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            report['comments'] = res_json

        tasks = [
            self.run_task_with_retries(_analyse, ip),
            self.run_task_with_retries(_resolutions, ip),
            self.run_task_with_retries(_referrer_files, ip),
            self.run_task_with_retries(_communicating_files, ip),
            self.run_task_with_retries(_comments, ip)
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return report

    async def _file_api(self, file: str):
        report = {'id': file,
                  'dtype': 'files'
                  }

        async def _analyse(_file) -> None:
            url = f'{self.vt_end_point}ui/files/{_file}'
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
            url = f'{self.vt_end_point}ui/files/{_file}/contacted_urls'
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
            url = f'{self.vt_end_point}ui/files/{_file}/contacted_domains'
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
            url = f'{self.vt_end_point}ui/files/{_file}/contacted_ips'
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

        async def _comments(_file) -> None:
            url = f'{self.vt_end_point}ui/files/{_file}/comments?relationships=item%2Cauthor'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            report['comments'] = res_json

        async def _behaviour(_file) -> None:
            url = f'{self.vt_end_point}ui/files/{_file}/behaviour_mitre_trees'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            report['behaviour'] = res_json

        async def _file_behaviour(_file) -> None:
            url = f'{self.vt_end_point}ui/files/{_file}/behaviours?limit=40'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            ip_traffic_list = []
            dns_lookups_list = []
            for data in res_json.get("data", []):
                # 确保 "attributes" 键存在，如果不存在，则跳过这个数据项
                if "attributes" not in data:
                    continue
                ip_traffic = data.get("attributes").get("ip_traffic")
                if isinstance(ip_traffic, list):
                    ip_traffic_list.extend(ip_traffic)
                dns_lookups = data.get("attributes").get("dns_lookups")
                if isinstance(dns_lookups, list):
                    dns_lookups_list.extend(dns_lookups)
            report['ip_traffic'] = ip_traffic_list
            report['dns_lookups'] = dns_lookups_list

        async def _behaviour_mbc_trees(_file) -> None:
            url = f'{self.vt_end_point}ui/files/{_file}/behaviours_mbc_trees'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            report['behaviour_mbc_trees'] = res_json

        async def _execution_parents(_file) -> None:
            url = f'{self.vt_end_point}ui/files/{_file}/execution_parents'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            report['execution_parents'] = res_json

        async def _pe_resource_parents(_file) -> None:
            url = f'{self.vt_end_point}ui/files/{_file}/pe_resource_parents'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            report['pe_resource_parents'] = res_json

        async def _bundled_files(_file) -> None:
            url = f'{self.vt_end_point}ui/files/{_file}/bundled_files'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            report['bundled_files'] = res_json

        async def _pe_resource_children(_file) -> None:
            url = f'{self.vt_end_point}ui/files/{_file}/pe_resource_children'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            report['pe_resource_children'] = res_json

        tasks = [
            self.run_task_with_retries(_analyse, file),
            self.run_task_with_retries(_contacted_urls, file),
            self.run_task_with_retries(_contacted_domains, file),
            self.run_task_with_retries(_contacted_ips, file),
            self.run_task_with_retries(_comments, file),
            self.run_task_with_retries(_behaviour, file),
            self.run_task_with_retries(_file_behaviour, file),
            self.run_task_with_retries(_behaviour_mbc_trees, file),
            self.run_task_with_retries(_execution_parents, file),
            self.run_task_with_retries(_pe_resource_parents, file),
            self.run_task_with_retries(_bundled_files, file),
            self.run_task_with_retries(_pe_resource_children, file),
        ]

        await asyncio.gather(*tasks, return_exceptions=True)
        print(report.keys())
        return report

    async def _search_api(self, query: str):
        async def _search(_q):
            url = f'{self.vt_end_point}ui/search?limit=20&relationships%5Bcomment%5D=author%2Citem&query={query}'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            return res_json.get("data", [])
        result = await self.run_task_with_retries(_search, query)
        return result

    async def _user_api(self, user: str):
        async def _get_user(_q):
            url = f'{self.vt_end_point}ui/users/{_q}/comments?relationships=author%2Citem'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            return res_json.get("data", [])

        result = await self.run_task_with_retries(_get_user, user)
        return result

    async def _comments_api(self):
        async def _get_comments():
            url = f'{self.vt_end_point}ui/comments?relationships=author%2Citem&filter=tag%3A%22_%3Aweb%22&limit=5'
            impersonate, headers = random_vt_ua_headers()
            res = await self._aget_url("GET", url, impersonate=impersonate, headers=headers)
            res_json = orjson.loads(res)
            return res_json.get("data", [])

        result = await self.run_task_with_retries(_get_comments, )
        return result

    async def _cf_api(self, input_str: str, dtype=None, cursor=None):
        apiEndpoints = {}
        if is_ip_address(input_str):
            apiEndpoints = {
                "analyse": f"/ui/ip_addresses/{input_str}",
                "resolutions": f"/ui/ip_addresses/{input_str}/resolutions",
                "referrer_files": f"/ui/ip_addresses/{input_str}/referrer_files",
                "communicating_files": f"/ui/ip_addresses/{input_str}/communicating_files",
                "comments": f"/ui/ip_addresses/{input_str}/comments?relationships=item%2Cauthor",
            }
        elif is_domain(input_str):
            apiEndpoints = {
                "analyse": f"/ui/domains/{input_str}",
                "resolutions": f"/ui/domains/{input_str}/resolutions",
                "referrer_files": f"/ui/domains/{input_str}/referrer_files",
                "communicating_files": f"/ui/domains/{input_str}/communicating_files",
                "subdomains": f"/ui/domains/{input_str}/subdomains?relationships=resolutions",
                "comments": f"/ui/domains/{input_str}/comments?relationships=item%2Cauthor",
            }
        else:
            hash_type = identify_hash(input_str)
            if hash_type in ('MD5', 'SHA-1'):
                apiEndpoints = {
                    "search_result": f"/ui/search?limit=20&relationships%5Bcomment%5D=author%2Citem&query={input_str}"
                }
            elif hash_type == 'SHA-256':
                apiEndpoints = {
                    "analyse": f"/ui/files/{input_str}",
                    "contacted_urls": f"/ui/files/{input_str}/contacted_urls",
                    "contacted_domains": f"/ui/files/{input_str}/contacted_domains",
                    "contacted_ips": f"/ui/files/{input_str}/contacted_ips",
                    "behaviour": f"/ui/files/{input_str}/behaviour_mitre_trees",
                    "file_behaviour": f"/ui/files/{input_str}/behaviours?limit=40",
                    "comments": f"/ui/files/{input_str}/comments?relationships=item%2Cauthor",
                    "behaviour_mbc_trees": f"/ui/files/{input_str}/behaviours_mbc_trees",
                    "execution_parents": f"/ui/files/{input_str}/execution_parents",
                    "pe_resource_parents": f"/ui/files/{input_str}/pe_resource_parents",
                    "bundled_files": f"/ui/files/{input_str}/bundled_files",
                    "pe_resource_children": f"/ui/files/{input_str}/pe_resource_children",
                }

        if dtype is None:
            payload = {
                "q": input_str,
                "apiEndpoints": apiEndpoints
            }
        else:
            apiEndpoint = apiEndpoints.get(dtype)
            apiEndpoint = add_cursor_to_endpoints(apiEndpoint, cursor) if cursor is not None else apiEndpoint
            print(apiEndpoint)
            payload = {
                "q": input_str,
                "apiEndpoints": {
                    dtype: apiEndpoint
                }
        }

        impersonate, headers = random_vt_ua_headers()
        res= await self._aget_url("POST", self.cf_end_point, impersonate=impersonate, headers=headers,
                                  data=orjson.dumps(payload))
        if isinstance(res, bytes):
            res = res.decode("utf-8", errors="replace")  # 替换错误字符
            print(res)
        res_json = orjson.loads(res)
        return res_json


def add_cursor_to_endpoints(url, cursor):
    parsed_url = urlparse(url)
    query_dict = dict()
    if parsed_url.query:
        query_dict = dict(q.split('=') for q in parsed_url.query.split('&'))
    query_dict['cursor'] = cursor
    new_query = urlencode(query_dict)
    return urlunparse(parsed_url._replace(query=new_query))


def is_ip_address(input_str):
    try:
        ipaddress.ip_address(input_str)
        return True
    except ValueError:
        return False


def is_domain(input_str):
    extracted = tldextract.extract(input_str)
    return bool(extracted.domain) and bool(extracted.suffix)


def identify_hash(hash_str):
    if re.match(r'^[a-f0-9]{32}$', hash_str, re.IGNORECASE):
        return 'MD5'
    elif re.match(r'^[a-f0-9]{40}$', hash_str, re.IGNORECASE):
        return 'SHA-1'
    elif re.match(r'^[a-f0-9]{64}$', hash_str, re.IGNORECASE):
        return 'SHA-256'
    else:
        return None


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
    ua_headers["X-App-Version"] = 'v1x282x3'
    ua_headers["X-Tool"] = 'vt-ui-main'
    fake_ip = generate_random_public_ip()
    ua_headers["X-Forwarded-For"] = fake_ip
    ua_headers["X-Real-IP"] = fake_ip
    ua_headers["X-Forwarded-Host"] = "www.virustotal.com"
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
print(add_cursor_to_endpoints("/sdsd/dsds?x=1", "dsdsdu=="))
