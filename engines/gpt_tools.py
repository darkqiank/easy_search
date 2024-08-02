import openai
import os
from dotenv import load_dotenv
from tenacity import (
    retry,
    stop_after_attempt,
    wait_random_exponential,
)

# 获取项目根目录文件
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(root_dir)

# 读取 .env文件
load_dotenv(dotenv_path=os.path.join(root_dir, '.env'))

openai.api_base = os.getenv('OPENAI_API_BASE')
openai.api_key = os.getenv('OPENAI_API_KEY')


@retry(wait=wait_random_exponential(min=1, max=30), stop=stop_after_attempt(2))
def completion_with_backoff(**kwargs):
    return openai.ChatCompletion.create(**kwargs)


def ask_openai(text, temperature=0.2):
    response = openai.ChatCompletion.create(
        model="gemini-1.5-flash-oneapi",
        temperature = temperature,
        messages=[
            {"role": "system", "content": "你是一个内容分析工具"},
            {"role": "user", "content": text}
        ]
    )
    return response