from utils.logger import info,error

class Engine:
    def __init__(self):
        #定义列表，存储扫描模块
        #插件容器
        self.modules = []

    def register(self, module):
        # 动态扩展能力，插件化架构
        self.modules.append(module)

    def run(self, url):
        info(f"开始扫描 → {url}")
        results = []
        #逐个调用模块
        for module in self.modules:
            try:
                #接口规范:check
                res = module.check(url)
                if res:
                    if isinstance(res,list):
                        results.extend(res)
                    else:
                        results.append(res) #append加入
            except Exception as e:
                error(f"模块异常:{module.__name__} | {e}")

        info(f"扫描完成，发现 {len(results)} 个漏洞")
        return results