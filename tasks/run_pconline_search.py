from engines import PCOnline
import os
from dotenv import load_dotenv
import psycopg2
import json

# 加载 .env 文件
load_dotenv()


# 从环境变量中读取数据库连接信息
dbname = os.getenv('DB_NAME')
user = os.getenv('DB_USER')
password = os.getenv('DB_PASSWORD')
host = os.getenv('DB_HOST')
port = os.getenv('DB_PORT')

conn = psycopg2.connect( dbname=dbname,
                                    user=user,
                                    password=password,
                                    host=host,
                                    port=port)

level4s =[]

with open("/Users/jiankaiwang/Documents/工作文档/06-设备识别优化/设备详情识别/phone_level4s") as f:
    lines = f.readlines()
    for line in lines:
        level4s.append(line.strip())

for i in range(len(level4s)):
    print(i)
    level4 = level4s[i]
    with PCOnline() as pc:
        datas = pc.search_dev(level4, small_type="手机", max_num=5)

        # 创建游标对象
        cur = conn.cursor()
        if datas:
            for data in datas:
                cur.execute('''
                                        INSERT INTO pconline_cellphone_info ( title, details, more_details, price, more_url)
                                        VALUES (%s, %s, %s, %s, %s)
                                        ON CONFLICT (title) DO NOTHING
                                    ''', (
                    data['title'],
                    data['details'],
                    json.dumps(data['more_details'], ensure_ascii=False),
                    data['price'],
                    data['more_url']
                ))
            # 提交事务
        conn.commit()
        cur.close()
        print(level4, '插入数据库成功')