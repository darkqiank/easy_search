from datetime import datetime
import json
from engines import VT
from dotenv import load_dotenv
import os
import random
import psycopg2
from psycopg2 import pool
import logging
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures


logging.basicConfig(filename='task.log', level=logging.INFO, encoding="utf-8")

# 加载 .env 文件
load_dotenv()

# 从环境变量中读取数据库连接信息
dbname = os.getenv('DB_NAME')
user = os.getenv('DB_USER')
password = os.getenv('DB_PASSWORD')
host = os.getenv('DB_HOST')
port = os.getenv('DB_PORT')


# 创建连接池
connection_pool = psycopg2.pool.ThreadedConnectionPool(1, 50,
                                                       dbname=dbname,
                                                       user=user,
                                                       password=password,
                                                       host=host,
                                                       port=port)


def get_rand_vt_end_point():
    vt_end_points = ["https://www.virustotal.com/",
                     "https://vtfastlycdn.451964719.xyz/",
                     "https://vtcdn.darkqiank.work/",
                     ]
    weights = [0.0, 0.3, 0.3]
    vt_end_point = random.choices(vt_end_points, weights=weights, k=1)[0]
    return vt_end_point


with open("D:\\data\\nrd\\1115_50w.txt", "r", encoding='utf-8') as f:
    lines = f.readlines()
    src_ids = [line.strip() for line in lines]


def process_src_id(src_id):
    conn = connection_pool.getconn()
    success = False
    # print(src_id)
    try:
        cur = conn.cursor()
        # 检查是否已存在 src_id 数据
        cur.execute("SELECT 1 FROM vt_reports WHERE id = %s LIMIT 1", (src_id,))
        exists = cur.fetchone()

        if exists:
            pass
            # print(f"src_id {src_id} 已存在，跳过")
        else:
            with VT(proxies="socks5://127.0.0.1:10808", timeout=10, vt_end_point=get_rand_vt_end_point()) as vt:
                res = vt.api(input_str=src_id)
                cur.execute(
                    """
                    INSERT INTO vt_reports (id, data, create_time)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (src_id, json.dumps(res, ensure_ascii=False), datetime.now())
                )
            conn.commit()
            print("保存成功")
            success = True
    except Exception as e:
        print("保存失败", e)
    finally:
        connection_pool.putconn(conn)
        return success

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

success_num = 0

with ThreadPoolExecutor(max_workers=10) as executor:
    batch_size = 500
    for batch in chunks(src_ids, batch_size):
        futures = [executor.submit(process_src_id, src_id) for src_id in batch]

        for future in concurrent.futures.as_completed(futures):
            response = future.result()
            if response:
                success_num += 1
        print(f"成功处理数量：{success_num}")

