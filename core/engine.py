from utils.logger import info,error
from core.context import ScanContext


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

        #创建上下文
        context = ScanContext(url)
        #统一初始化
        from modules.sqli import parse_url_params  #临时
        from core import requestor
        context.parsed,context.params = parse_url_params(url)
        context.base_response = requestor.get(url)

        if not context.base_response:
            error("目标无法访问")
            return []

        context.base_text = context.base_response.text
        context.base_len = len(context.base_text)

        #逐个调用模块
        for module in self.modules:
            try:
                info(f"加载模块:{getattr(module,'name',module.__name__)}")
                #接口规范:check
                res = module.check(context)
                if res:
                    if isinstance(res,list):
                        context.results.extend(res)
                    else:
                        context.results.append(res) #append加入
            except Exception as e:
                error(f"模块异常:{module.__name__} | {e}")

        info(f"扫描完成，发现 {len(context.results)} 个漏洞")
        
        return context.results