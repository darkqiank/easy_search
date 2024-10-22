import psycopg2
from dotenv import load_dotenv
import os
import pandas as pd

# 加载 .env 文件
load_dotenv()

# 从环境变量中读取数据库连接信息
dbname = os.getenv('DB_NAME')
user = os.getenv('DB_USER')
password = os.getenv('DB_PASSWORD')
host = os.getenv('DB_HOST')
port = os.getenv('DB_PORT')


def drb_ra_parser(data):
    comment_id = data.get("id")
    # 定义要匹配的前缀，按长度从长到短排序
    prefixes = ["C2: HTTPS @", "C2: HTTP @", "C2 Server:", "C2:"]
    attributes = data.get("attributes")
    tags = "|".join(attributes.get("tags"))
    text = attributes.get("text")
    iocs = []
    if "c2" in tags:
        lines = text.split("\n")
        for line in lines:
            for prefix in prefixes:
                if line.startswith(prefix):
                    value = line[len(prefix):].strip()
                    iocs.append(value)
                    break
    src_data = data.get("relationships", {}).get("item", {}).get("data", {})
    src_id = src_data.get("id")
    src_type = src_data.get("type")
    src_content = src_data.get("context_attributes", {}).get("url")
    res_iocs = [
        {
            "comment_id": comment_id,
            "ioc": ioc,
            "tags": tags,
            "src_id": src_id,
            "src_type": src_type,
            "src_content": src_content
        } for ioc in iocs
    ]
    return res_iocs

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

# 从表中读取 jsonb 字段
cur.execute("SELECT data FROM vt_user_comments")
rows = cur.fetchall()

output = []
for row in rows:
    jsonb_data = row[0]  # 获取 jsonb 数据
    parsed_data = drb_ra_parser(jsonb_data)
    if parsed_data:
        print(parsed_data)
        output.extend(parsed_data)

df = pd.DataFrame(output)
df.to_excel("vt_user_iocs.xlsx", index=False)

# 关闭游标和连接
cur.close()
conn.close()
