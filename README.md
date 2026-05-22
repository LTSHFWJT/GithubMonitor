# GitHub Monitor

基于 `FastAPI + Jinja2 + SQLite` 的 GitHub 仓库泄露监控程序。

## 功能

- 管理员登录
- GitHub Token 管理和配额检测
- 任务配置：关键词、匹配模式、扫描页数、扫描间隔、存储策略
- 扫描队列：定时入队和后台执行
- GitHub Code Search 扫描
- 规则检测：GitHub Token、AWS Key、私钥块、高熵字符串等
- 扫描结果处置：待处理、误报、异常、已解决
- 扫描结果批量处置、仓库加白、文件加白和片段详情
- 白名单：owner、仓库、路径、文件名、片段值
- 通知配置：邮件、Webhook、Telegram、钉钉、飞书、企业微信
- 代理、通知模板、规则和账号设置

## 运行

```bash
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python -m githubmonitor --host 127.0.0.1 --port 8000 --reload
```

访问 `http://127.0.0.1:8000`。

首次启动时没有默认账号，需要在初始化页面注册管理员账号。

可用环境变量覆盖默认值：

```bash
GHMON_SECRET_KEY='change-me-too'
GHMON_DB_PATH='data/github_monitor.db'
```

## 使用流程

1. 登录后台。
2. 在 `Token` 页面添加 GitHub Personal Access Token，并点击测试。
3. 在 `任务配置` 页面添加关键词，例如 `company-name extension:env`。
4. 点击任务的 `扫描`，或在概况页执行队列。
5. 在 `扫描结果` 页面确认、误报、异常或标记已解决。

SQLite 数据库默认写入 `data/github_monitor.db`。
