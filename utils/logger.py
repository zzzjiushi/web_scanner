import datetime

def _get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def info(msg):
    print(f"[{_get_timestamp()}] [INFO] {msg}")

def warn(msg):
    print(f"[{_get_timestamp()}] [WARN] {msg}")

def error(msg):
    print(f"[{_get_timestamp()}] [ERROR] {msg}")

def success(msg):
    print(f"[{_get_timestamp()}] [SUCCESS] {msg}")

def debug(msg):
    # 可通过环境变量控制是否打印调试信息
    import os
    if os.getenv("SCANNER_DEBUG") == "1":
        print(f"[{_get_timestamp()}] [DEBUG] {msg}")