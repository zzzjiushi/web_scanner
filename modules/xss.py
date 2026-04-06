import urllib.parse
import copy

from core import requestor
from utils.logger import info, success
from core.analyzer import (
    detect_xss_context,
    generate_xss_payload,
    xss_analysis
)

name = "XSS"

MARKER = "XSS123"


def inject_param(parsed, params, param, payload):
    new_params = copy.deepcopy(params)
    new_params[param] = [payload]

    query = urllib.parse.urlencode(new_params, doseq=True)
    return urllib.parse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, query, parsed.fragment
    ))


def check(context):
    results = []

    parsed = context.parsed
    params = context.params
    base_text = context.base_text

    for param in params:
        if param.lower() in ["csrf", "token", "submit"]:
            continue

        info(f"[XSS] 测试参数: {param}")

        # marker探测
        marker_url = inject_param(parsed, params, param, MARKER)
        resp = requestor.get(marker_url)

        if not resp:
            continue

        text = resp.text

        if MARKER not in text:
            continue

        # 调 analyser → 上下文识别
        context_type = detect_xss_context(text, MARKER)
        if not context_type:
            continue

        info(f"[XSS] 上下文: {context_type}")

        # 调 analyser → payload生成
        payloads = generate_xss_payload(context_type)

        for payload in payloads:
            test_url = inject_param(parsed, params, param, payload)
            test_r = requestor.get(test_url)

            if not test_r:
                continue

            test_text = test_r.text

            # 调 analyser → 判断
            if xss_analysis(base_text, test_text, payload):
                success(f"XSS(高危): {param}")

                results.append({
                    "type": "xss",
                    "param": param,
                    "payload": payload,
                    "context": context_type,
                    "confidence": "high"
                })

                break

    return results