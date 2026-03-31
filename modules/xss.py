import urllib.parse
import copy
import random
import string
import re

from core import requestor
from utils.logger import info, success


# =========================
# 工具函数
# =========================

def parse_url_params(url):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    return parsed, params


def build_url(parsed, params):
    query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, query, parsed.fragment
    ))


def inject_param(url, param, payload):
    parsed, params = parse_url_params(url)

    if param not in params:
        return None

    new_params = copy.deepcopy(params)
    new_params[param] = [params[param][0] + payload]

    return build_url(parsed, new_params)


def random_marker(length=6):
    return ''.join(random.choices(string.ascii_lowercase, k=length))


# =========================
# XSS 核心检测
# =========================

def check(url):
    parsed, params = parse_url_params(url)
    if not params:
        return None

    base = requestor.get(url)
    if not base:
        return None

    base_text = base.text

    results = []

    for param in params:
        info(f"[XSS] 测试参数: {param}")

        marker = random_marker()

        # =========================
        # payload设计（关键）
        # =========================
        payloads = [
            f"<script>{marker}</script>",
            f"'><script>{marker}</script>",
            f"\"<script>{marker}</script>",
            f"<img src=x onerror={marker}>",
            f"<svg/onload={marker}>",
        ]

        for payload in payloads:
            test_url = inject_param(url, param, payload)
            r = requestor.get(test_url)

            if not r:
                continue

            text = r.text

            # =========================
            # 核心检测逻辑（工程重点）
            # =========================

            # 1️⃣ marker是否出现
            if marker not in text:
                continue

            # 2️⃣ 是否被转义（关键降低误报）
            escaped_patterns = [
                f"&lt;script&gt;{marker}&lt;/script&gt;",
                f"&quot;&lt;script&gt;{marker}&lt;/script&gt;"
            ]

            if any(p in text for p in escaped_patterns):
                continue

            # 3️⃣ 上下文检测（关键）
            # 判断是否在HTML标签中执行
            dangerous_context = False

            # script标签
            if re.search(rf"<script[^>]*>{marker}</script>", text, re.I):
                dangerous_context = True

            # 事件属性
            if re.search(rf"onerror\s*=\s*{marker}", text, re.I):
                dangerous_context = True

            # svg执行
            if re.search(rf"<svg.*{marker}", text, re.I):
                dangerous_context = True

            # 4️⃣ 置信度判断
            confidence = "low"

            if dangerous_context:
                confidence = "high"
            elif marker in text:
                confidence = "medium"

            # =========================
            # 命中
            # =========================
            success(f"[XSS] 命中: {param} | {confidence}")

            results.append({
                "type": "xss",
                "method": "reflected",
                "param": param,
                "payload": payload,
                "confidence": confidence,
                "url": url
            })

            break  # 一个payload命中即可

    return results if results else None