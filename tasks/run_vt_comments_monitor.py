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

proxy = os.getenv('FETCH_PROXY', "http://127.0.0.1:7890")

# PostgreSQL 连接配置
# conn = psycopg2.connect(
#     dbname=dbname,
#     user=user,
#     password=password,
#     host=host,
#     port=port
# )

# 创建连接池
connection_pool = psycopg2.pool.ThreadedConnectionPool(1, 20,
                                                       dbname=dbname,
                                                       user=user,
                                                       password=password,
                                                       host=host,
                                                       port=port)

# 创建线程锁
# lock = threading.Lock()


def get_rand_vt_end_point():
    vt_end_points = ["https://www.virustotal.com/",
                     "https://vtfastlycdn.451964719.xyz/",
                     "https://vtgcorecdn.451964719.xyz/"
                     ]
    weights = [0.5, 0.5, 0.0]
    vt_end_point = random.choices(vt_end_points, weights=weights, k=1)[0]
    return vt_end_point


src_ids = []

with open("tasks/vt_users.txt", "r") as f:
    lines = f.readlines()
    users = [line.strip() for line in lines]


conn = connection_pool.getconn()
try:
    # 创建游标对象
    cur = conn.cursor()
    res = []
    with VT(proxies=proxy, timeout=20, vt_end_point="https://www.virustotal.com/") as vt:
        res.extend(vt.api(input_str="comments"))

    for user in users:
        print(user)
        with VT(proxies=proxy, timeout=20, vt_end_point="https://www.virustotal.com/") as vt:
            res.extend(vt.api(input_str=user))

    for record in res:
        id_value = record.get('id')

        attributes = record.get("attributes", {})
        content = attributes.get("text")

        tags = "|".join(attributes.get("tags", []))

        votes = attributes.get("votes")

        src_data = record.get("relationships", {}).get("item", {}).get("data", {})
        src_id = src_data.get("id")
        src_type = src_data.get("type")
        src_content = src_data.get("context_attributes", {}).get("url")

        author_id = record.get("relationships", {}).get("author", {}).get("data", {}).get("id")

        data_value = json.dumps(record)
        create_time = datetime.now()
        comment_date = datetime.fromtimestamp(attributes.get("date")) if attributes.get("date") else create_time

        # 插入数据到 PostgreSQL

        cur.execute('''
            INSERT INTO vt_comments (id, content, tags, votes, src_id, src_type, src_content, author_id, comment_date, create_time)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING
        ''', (
            id_value,
            content,
            tags,
            json.dumps(votes),  # 将字典转换为 JSON 字符串
            src_id,
            src_type,
            src_content,
            author_id,
            comment_date,
            create_time
        ))
        src_ids.append(src_id)
        # 提交事务
        conn.commit()
except Exception as e:
    print(e)
finally:
    connection_pool.putconn(conn)

print("评论数据保存成功！")

logging.info('Task started at {} 保存成功{}条评论'.format(time.strftime('%Y-%m-%d %H:%M:%S'), len(src_ids)))

def process_src_id(src_id):
    conn = connection_pool.getconn()
    success = False
    print(src_id)
    try:
        cur = conn.cursor()
        # 检查是否已存在 src_id 数据
        cur.execute("SELECT 1 FROM vt_reports WHERE id = %s LIMIT 1", (src_id,))
        exists = cur.fetchone()

        if exists:
            print(f"src_id {src_id} 已存在，跳过")
        else:
            with VT(proxies=proxy, timeout=10, vt_end_point=get_rand_vt_end_point()) as vt:
                res = vt.api(input_str=src_id)
                cur.execute(
                    """
                    INSERT INTO vt_reports (id, data, create_time)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (src_id, json.dumps(res, ensure_ascii=False), create_time)
                )
            conn.commit()
            print("保存成功")
            success = True
    except Exception as e:
        print("保存失败", e)
    finally:
        connection_pool.putconn(conn)
        return success

success_num = 0

with ThreadPoolExecutor(max_workers=10) as executor:
    futures = []
    for src_id in src_ids:
        future = executor.submit(process_src_id, src_id)
        futures.append(future)

    for future in concurrent.futures.as_completed(futures):
        response = future.result()
        if response:
            success_num += 1

print("报告数据保存成功！")

logging.info('Task started at {} 保存成功{}条报告数据'.format(time.strftime('%Y-%m-%d %H:%M:%S'), success_num))


