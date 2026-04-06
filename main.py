import argparse
from core.engine import Engine
from modules import sqli, rce, xss


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    args = parser.parse_args()

    engine = Engine()
    
    # 插件注册：想加什么漏洞就加什么
    engine.register(sqli)
    engine.register(xss)

    result = engine.run(args.url)

    print("\n===== 扫描结果 =====")
    for item in result:
        print(item)

if __name__ == "__main__":
    main()