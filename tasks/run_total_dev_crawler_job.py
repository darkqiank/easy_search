import json

from engines import ZOL
import os
from dotenv import load_dotenv
import psycopg2

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

for i in range(2,78):
    page_url = f'https://detail.zol.com.cn/cell_phone_index/subcate57_0_list_1_0_1_1_0_{i}.html'
    with ZOL() as zol:
        datas = zol.get_page_info(page_url)

        # 创建游标对象
        cur = conn.cursor()

        for data in datas:
            cur.execute('''
                        INSERT INTO zol_cellphone_info ( title, details, more_details, price, more_url)
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
    print(page_url, '插入数据库成功')

conn.close()
