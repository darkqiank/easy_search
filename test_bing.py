from curl_cffi import requests
# import requests

url = 'https://www.bing.com/search?q=52eva.top'
# url = 'https://icplishi.com/freelychat.cn/'
r = requests.get(url, impersonate="chrome110")
# r = requests.get(url)
print(r.text)