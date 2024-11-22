from engines import DDGS
import random
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import pandas as pd
import sys


def get_rand_ddgs_end_point():
    end_points = ["https://duckduckgo.com",
                     "https://ddgs.catflix.cn",
                     ]
    weights = [0.5, 0.5]
    end_point = random.choices(end_points, weights=weights, k=1)[0]
    return end_point


def get_rand_ddgslink_end_point():
    end_points = ["https://links.duckduckgo.com",
                     "https://ddgslink.catflix.cn",
                     ]
    weights = [0.5, 0.5]
    end_point = random.choices(end_points, weights=weights, k=1)[0]
    return end_point


def search(domain, retry=2):
    try:
        with DDGS(proxies="socks5://127.0.0.1:10808", timeout=20,
                  ddgs_end_point=get_rand_ddgs_end_point(),
                  ddgslink_end_point=get_rand_ddgslink_end_point()
                  ) as ddgs:
            q = f'{quote(str(domain))}'
            r = ddgs.text(q, max_results=10, region='cn-zh')
            return domain, r
    except Exception as e:
        print(f'请求{domain}错误，{e},重试第{retry}次！')
        if retry > 0:
            retry = retry - 1
            return search(domain, retry)
        return domain, None


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]


def main(domains, thread_count=20):
    success_num = 0

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        results = []
        batch_size = 40
        for batch in chunks(domains, batch_size):
            futures = [executor.submit(search, dm) for dm in batch]

            for future in concurrent.futures.as_completed(futures):
                domain, res = future.result()
                if res:
                    for item in res:
                        results.append({"domain": domain,
                                        "title": item.get("title"),
                                        "href": item.get("href"),
                                        "body": item.get("body")
                                        })
                    success_num += 1
            df_res = pd.DataFrame(results)
            df_res.to_excel("E:\\apprun\\domain_files\\domains_search_result.xlsx", index=False)
            print(f"成功处理数量：{success_num}")


if __name__ == "__main__":
    file_path = sys.argv[1]
    try:
        df = pd.read_csv(file_path)
        if "top_domain" in df.columns:
            domains = df["top_domain"].tolist()
        else:
            raise ValueError("No 'top_domain' field present.")
    except ValueError:
        # If the CSV doesn't have the 'top_domain' column or if it has only one column
        df = pd.read_csv(file_path, header=None)
        domains = df[0].tolist()  # Assuming the first column contains the domain data

    # 执行主函数
    main(domains)