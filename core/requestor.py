import requests
import time
import random
from utils.logger import error

# 定义默认统一请求头
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (WebScanner)"  #伪装成浏览器
}
#复用TCP连接，稳定
session = requests.Session()

def get(url, headers=None, cookies=None, proxies=None, retries = 3,timeout=5,delay = (0.3,1.0)):
    # 合并请求头
    final_headers = DEFAULT_HEADERS.copy()  #用copy保证每次请求都是独立的
    #用户传入header，覆盖默认值
    if headers:
        final_headers.update(headers)
    for i in range(retries):
        try:
            #随机延迟
            time.sleep(random.uniform(*delay))
            #发起GET请求
            r = requests.get(
                url,
                headers=final_headers,
                cookies=cookies,
                proxies=proxies,
                timeout=timeout,
                verify=False,  #忽略HTTPS验证
                allow_redirects=True   #自动跟随301/302跳转
            )
            return r

        #超时
        except requests.exceptions.Timeout:
            error(f"请求超时: {url}")
            return None
        #异常
        except Exception as e:
            error(f"请求失败: {url} | {str(e)}")
            return None