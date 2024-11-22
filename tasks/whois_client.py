import psycopg2
from psycopg2.extras import execute_batch
from psycopg2 import pool
import requests
import json
import sys
import pandas as pd
import csv
import tldextract
from collections import defaultdict, deque
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import concurrent.futures
import time
import threading
from dotenv import load_dotenv
import os


# 加载 .env 文件
load_dotenv()

# 从环境变量中读取数据库连接信息
dbname = os.getenv('DB_NAME')
user = os.getenv('DB_USER')
password = os.getenv('DB_PASSWORD')
host = os.getenv('DB_HOST')
port = os.getenv('DB_PORT')


# 创建连接池
connection_pool = psycopg2.pool.ThreadedConnectionPool(1, 20,
                                                       dbname=dbname,
                                                       user=user,
                                                       password=password,
                                                       host=host,
                                                       port=port)

# 创建线程锁
lock = threading.Lock()

# 循环次数
turns = 3

# 设置每秒的请求次数上限
tps = 60

# whois的请求接口
whois_end_point = "http://127.0.0.1:5007/"
whois_end_point_en = "http://127.0.0.1:5008/"


def turn_to_register_domain(domain):
    extracted = tldextract.extract(domain)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    else:
        return None


def get_domain_dict(domains):
    # 使用字典来存储每个顶级域名的域名列表
    domain_dict = defaultdict(deque)
    for domain in tqdm(domains, total=len(domains)):
        tld = tldextract.extract(str(domain)).suffix
        # 将域名添加到对应的顶级域名列表中
        domain_dict[tld].append(domain)
    return domain_dict


def preprocess_domains(domains):
    domain_dict = defaultdict(deque)
    n = 0
    for domain in tqdm(domains, desc="取主域名"):
        domain = str(domain)
        extracted = tldextract.extract(domain)
        tld = extracted.suffix
        sub = extracted.domain
        if sub and tld:
            domain_dict[tld].append(domain)
            n+=1

    # 按tld均匀排序
    new_dms = []
    progress_bar = tqdm(total=n, desc="按tld均匀排序")
    while domain_dict:
        keys_to_remove = []
        for tld in list(domain_dict.keys()):
            new_dms.append(domain_dict[tld].popleft())
            # 更新进度条
            progress_bar.update(1)
            if not domain_dict[tld]:
                keys_to_remove.append(tld)
        for tld in keys_to_remove:
            del domain_dict[tld]

    progress_bar.close()
    print(f"查询数据库{len(new_dms)}")
    existing_domains = look_in_db(new_dms)
    print(f"查询成功{len(existing_domains)}")
    new_dms_final = []
    for dm in tqdm(new_dms, desc="最终聚合"):
        if dm not in existing_domains:
            new_dms_final.append(dm)

    return new_dms_final


def parallel_pre_process_domains(domains):
    # 创建进程池
    num_workers = 10
    # 分割数据
    chunk_size = len(domains) // num_workers
    chunks = [domains[i:i + chunk_size] for i in range(0, len(domains), chunk_size)]

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        # 提交所有任务
        futures = [executor.submit(preprocess_domains, chunk) for chunk in chunks]

        combined_dms = []
        # 使用 tqdm 显示进度条
        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing Domains"):
            new_dms = future.result()
            combined_dms.extend(new_dms)

    return combined_dms


def save_to_db(domain, data, level=0):
    conn = connection_pool.getconn()
    try:
        with lock:
            cur = conn.cursor()
            # 查询是否已经存在 domain 数据
            cur.execute("SELECT level FROM whois_info WHERE domain = %s", (domain,))
            result = cur.fetchone()
            # print(f"查询结果: {result}")

            if result is not None:
                current_level = result[0]
                # 比较 level 值
                if level > current_level:
                    if level > current_level:
                        cur.execute('''
                                    UPDATE whois_info 
                                    SET data = %s, level = %s, insert_time = CURRENT_TIMESTAMP
                                    WHERE domain = %s
                                ''', (data, level, domain))
            else:
                # 插入新记录
                cur.execute('''
                            INSERT INTO whois_info (domain, data, level, insert_time)
                            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                        ''', (domain, data, level))
            conn.commit()
    except Exception as e:
        print(f"保存失败：{e}")
    finally:
        connection_pool.putconn(conn)


def save_to_db_batch(domains, datas, levels):
    conn = connection_pool.getconn()
    try:
        with lock:
            cur = conn.cursor()
            # 预查询以检查是否已存在的 domain 数据
            query = "SELECT domain, level FROM whois_info WHERE domain IN %s"
            cur.execute(query, (tuple(domains),))
            existing_records = cur.fetchall()
            existing_domains = {record[0]: record[1] for record in existing_records}

            insert_data = []
            update_data = []
            for domain, data, level in zip(domains, datas, levels):
                if domain in existing_domains:
                    current_level = existing_domains[domain]
                    if level > current_level:
                        update_data.append((data, level, domain))
                else:
                    insert_data.append((domain, data, level))

            # 批量插入新记录
            if insert_data:
                insert_query = '''
                            INSERT INTO whois_info (domain, data, level, insert_time)
                            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                        '''
                execute_batch(cur, insert_query, insert_data)

            # 批量更新现有记录
            if update_data:
                update_query = '''
                            UPDATE whois_info
                            SET data = %s, level = %s, insert_time = CURRENT_TIMESTAMP
                            WHERE domain = %s
                        '''
                execute_batch(cur, update_query, update_data)

            # 提交事务
            conn.commit()
            print(f"批量保存成功：插入 {len(insert_data)} 条，更新 {len(update_data)} 条")
    except Exception as e:
        print(f"批量保存失败：{e}")
    finally:
        connection_pool.putconn(conn)


def fetch_data(domain, end_point=whois_end_point, ref=1, retry=1):
    if ref > 0:
        api = f"{end_point}{domain}?ref={ref}"
    else:
        api = f"{end_point}{domain}"
    try:
        response = requests.get(url=api, verify=False, timeout=30)
        # response.raise_for_status()  # 确保响应状态码是200
        res = response.json()
        data = res.get("data")
        if response.status_code == 200:
            if data:
                save_to_db(domain, json.dumps(data, ensure_ascii=False), level=ref)
                return "Success"
        else:
            error_msg = res.get("error")
            if error_msg == "whoisparser: domain is not found":
                save_to_db(domain, None, -1)
                return "Not_Register"
    except Exception as e:
        retry = retry - 1
        if retry < 0:
            return
        else:
            return fetch_data(domain, whois_end_point_en, ref, retry)


def look_in_db(domains):
    conn = connection_pool.getconn()
    # 先查询db，得到不在数据库中的域名
    try:
        with lock:
            cur = conn.cursor()
            query = "SELECT domain, data, level FROM whois_info WHERE domain IN %s"
            cur.execute(query, (tuple(domains),))
            existing_records = cur.fetchall()
            existing_domains = {record[0]:
                                    {"domain": record[0],
                                     "data": record[1],
                                     "level": record[2]}
                                for record in existing_records}
            return existing_domains
    except Exception as e:
        print(f"批量查询失败：{e}")
    finally:
        connection_pool.putconn(conn)


def process_domains_in_batches(domains):
    batch_size = 500
    print(f"全部数据{len(domains)}条")
    # existing_domains = look_in_db(domains)
    # print(f"数据库中有{len(existing_domains)}条")
    # dms = []
    # for domain in domains:
    #     if domain not in existing_domains:
    #         dms.append(domain)

    # with open("E:\\apprun\\domain_files\\bad_20241031_zh.csv", "w") as f:
    #     for dm in dms:
    #         f.write(f"{dm}\n")
    #     print(f"待检查数据写入文件")

    # domain_dict = get_domain_dict(dms)
    # # 按tld均匀排序
    # new_dms = []
    # while domain_dict:
    #     keys_to_remove = []
    #     for tld in list(domain_dict.keys()):
    #         new_dms.append(domain_dict[tld].popleft())
    #         if not domain_dict[tld]:
    #             keys_to_remove.append(tld)
    #     for tld in keys_to_remove:
    #         del domain_dict[tld]

    # 预处理数据
    new_dms = parallel_pre_process_domains(domains)

    dm_num = len(new_dms)
    print(f"待查询{dm_num}条")
    # 入库数
    roll_in_num = 0
    # 成功数
    success_num = 0
    # results = []
    processed_num = 0

    # 创建一个线程池
    with ThreadPoolExecutor(max_workers=tps) as executor:
        for i in range(0, len(new_dms), batch_size):
            futures = []
            start_time = time.time()

            batch = new_dms[i:i + batch_size]
            for domain in batch:
                # 创建一个任务来发送请求
                future = executor.submit(fetch_data, domain)
                futures.append(future)
                processed_num += 1

            # 等待所有任务完成
            for future in concurrent.futures.as_completed(futures):
                response = future.result()
                # 这里你可以添加你自己的处理代码
                if response:
                    roll_in_num += 1
                    if response == "Success":
                        # results.append(response)
                        success_num += 1
            print(f"whois successed/roll_in_num/processed/all {success_num}/{roll_in_num}/{processed_num}/{dm_num}")
            # 限制每秒的请求次数
            # time.sleep(max(0.0, start_time + 1 - time.time()))

    return success_num



# domain = "baidu.com"
# data = fetch_data(domain)
# print(data)
# save_to_db(domain, json.dumps(data, ensure_ascii=False))


if __name__ == "__main__":
    file_path = sys.argv[1]
    try:
        with open(file_path, "r") as json_file:
            data = json.load(json_file)
            domains = data.get('domain')
    except Exception as e:
        try:
            df = pd.read_csv(file_path, on_bad_lines='warn')
            if "top_domain" in df.columns:
                domains = df["top_domain"].tolist()
            else:
                raise ValueError("No 'top_domain' field present.")
        except Exception as e2:
            # If the CSV doesn't have the 'top_domain' column or if it has only one column
            df = pd.read_csv(file_path, header=None, quoting=csv.QUOTE_NONE, on_bad_lines='warn',
                             dtype=str)
            domains = df[0].tolist()  # Assuming the first column contains the domain data

    print(f'共{len(domains)}个域名')
    # r_domains = []
    # for dm in domains:
    #     r_dm = turn_to_register_domain(dm)
    #     if r_dm and r_dm not in r_domains:
    #         r_domains.append(r_dm)

    for i in range(turns):
        print(f"第{i}次循环：")
        process_domains_in_batches(domains)
