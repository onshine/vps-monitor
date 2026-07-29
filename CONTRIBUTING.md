# Contributing

1. 不得引入读取 `/proc/<pid>/environ`、文件内容、SSH 密钥或凭证的功能。
2. 新增命令必须设置超时和输出上限；新增存储必须有保留策略。
3. 高危权限必须是显式 opt-in，不能通过升级静默开启。
4. 提交前运行：`python3 -m py_compile vps_monitor.py && python3 vps_monitor.py check && python3 test_parser.py`。
5. Issue 和测试数据必须移除 Token、IP、用户名、路径及业务信息。
