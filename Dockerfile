# 使用官方Python运行时作为父镜像
FROM python:3.10

# 设置工作目录
WORKDIR /app

# 将当前目录内容复制到位于/app中的容器中
COPY . /app

# 安装requirements.txt中指定的所有依赖
RUN pip install --no-cache-dir -r requirements.txt

# 让端口80可用于世界外部
EXPOSE 5003

# 在容器启动时运行app.py
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5003"]
