import statistics

from Cython import returns
import re

from holoviews.operation import threshold

from utils.logger import info
def avg(lst):
    return sum(lst) / len(lst) if lst else 0

def boolean_based_analysis(base_text,true_texts,false_texts,similarity):
    sim_true_list = [similarity(base_text,t) for t in true_texts]
    sim_false_list = [similarity(base_text,f) for f in false_texts]

    sim_t = avg(sim_true_list)
    sim_f = avg(sim_false_list)

    sim_tf_list = [
        similarity(t,f) for t,f in zip(true_texts,false_texts)
    ]

    sim_tf = avg(sim_tf_list)
    delta = sim_t - sim_f

    len_t = avg([len(t) for t in true_texts])
    len_f = avg([len(f) for f in false_texts])
    len_diff = abs(len_t - len_f)

    score = 0
    if sim_t > sim_f:
        score += 40
    if delta > 0.002:
        score += 20
    if len_diff > 2:
        score += 20
    if sim_tf < 0.999:
        score += 20
    return score >= 60

def time_based_analysis(baseline_times,ts_sleep,ts_normal):
    if not ts_sleep or not ts_normal:
        return False

    avg_base = sum(baseline_times) / len(baseline_times) if baseline_times else 0
    avg_sleep = sum(ts_sleep) / len(ts_sleep) if ts_sleep else 0
    avg_normal = sum(ts_normal) / len(ts_normal) if ts_normal else 0

    diff_delay = avg_sleep - avg_normal
    #抗噪声（标准差）
    jitter = statistics.stdev(ts_sleep) if len(ts_sleep) > 1 else 0
    threshold1 = max(2,avg_base * 2)
    return (
        diff_delay > threshold1 and
        avg_sleep > avg_base + 3 and
        jitter < 1.5  #稳定性
    )
    #错误指纹库
ERROR_PATTERNS = [
    # mysql
    r"sql syntax.*mysql",
    r"warning.*mysql",
    r"mysql_fetch",
    r"mariadb server version",

    # mssql
    r"unclosed quotation mark",
    r"microsoft sql server",

    # postgresql
    r"pg_query",
    r"postgresql.*error",

    # oracle
    r"ora-\d+",

    # sqlite
    r"sqlite error",
    r"sqlite3.*error",

    # 通用
    r"syntax error",
    r"unexpected end",
    r"sql error",
    r"database error",
]
def error_based_analysis(base_text,test_text,similarity):
    text = test_text.lower()
    # 用正则re,来查询，精准匹配错误结构
    matched = any(re.search(p, text) for p in ERROR_PATTERNS)
    sim = similarity(base_text, text)

    info(f"matched={matched} sim={sim:.4f}")
    return (
        matched and sim < 0.95
    )
def union_based_analysis(base_text, union_texts, similarity, mark):
    if not union_texts:
        return False

    sims = []
    mark_hits = []

    for text in union_texts:
        sims.append(similarity(base_text, text))
        mark_hits.append(mark in text)

    avg_sim = sum(sims) / len(sims)
    hit_count = sum(mark_hits)

    # 命中率
    hit_ratio = hit_count / len(mark_hits)

    #打分机制（关键）
    score = 0

    if hit_ratio > 0.6:   # 多次命中
        score += 50

    if avg_sim < 0.98:    # 页面有变化
        score += 30

    if hit_count >= 2:    # 至少2次成功
        score += 20

    return score >= 60