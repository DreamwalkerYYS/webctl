"""webctl.commands —— 每个模块一个子命令，cli.py 自动发现。

加新功能的标准姿势（也是这个包存在的理由）：
    1. 新建 webctl/commands/<名字>.py
    2. 里面写 register(sub) 和 run(args)
    3. 完事。`webctl --help` 里就有了，不用改 cli.py / __init__.py
"""
