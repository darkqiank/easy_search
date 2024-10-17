from datetime import datetime
import json
from engines import VT
import psycopg2
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

# PostgreSQL 连接配置
conn = psycopg2.connect(
    dbname=dbname,
    user=user,
    password=password,
    host=host,
    port=port
)

# 创建游标对象
cur = conn.cursor()

with open("tasks/vt_users.txt", "r") as f:
    lines = f.readlines()
    users = [line.strip() for line in lines]

for user in users:
    print(user)
    try:
        with VT(timeout=20, vt_end_point="https://www.virustotal.com/") as vt:
            res = vt.api(input_str=user)
            for record in res:
                id_value = record.get('id')
                data_value = json.dumps(record)
                create_time = datetime.now()

                # 插入数据到 PostgreSQL
                cur.execute(
                    """
                    INSERT INTO vt_user_comments (id, data, create_time)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (id_value, data_value, create_time)
                )
            # 提交事务
            conn.commit()
            print(user, "保存成功")
    except Exception as e:
        print(user, e)

# 关闭游标和连接
cur.close()
conn.close()

