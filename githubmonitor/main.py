import asyncio
import contextlib
import json
import math
import os
import traceback
from pathlib import Path
from urllib.parse import quote, urlencode

from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import db, github_client, notifications, scanner
from .forms import as_int, parse_form
from .security import hash_password, make_session, mask_secret, read_session, verify_password


APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))

STATUS_LABELS = {
    "unknown": "未知",
    "normal": "正常",
    "abnormal": "异常",
    "rate_limited": "限流",
    "disabled": "停用",
    "pending": "待处理",
    "false_positive": "误报",
    "solved": "已解决",
    "queued": "排队中",
    "running": "执行中",
    "success": "成功",
    "failed": "失败",
}

PER_PAGE_OPTIONS = (10, 20, 50, 100)

SEVERITY_LABELS = {
    "low": "低",
    "medium": "中",
    "high": "高",
    "critical": "严重",
}

RULE_LABELS = {
    "AWS Access Key ID": "AWS 访问密钥 ID",
    "GitHub Token": "GitHub 令牌",
    "Private Key Block": "私钥块",
    "Slack Token": "Slack 令牌",
    "Google API Key": "Google API 密钥",
    "Environment File": "环境配置文件",
    "SSH Private Key": "SSH 私钥",
    "AWS Credentials Path": "AWS 凭证路径",
    "High entropy string": "高熵疑似密钥",
    "Keyword match": "关键词命中",
}


def label_value(value: str | None, labels: dict[str, str]) -> str:
    if value is None:
        return "-"
    return labels.get(str(value), str(value))


templates.env.filters["status_label"] = lambda value: label_value(value, STATUS_LABELS)
templates.env.filters["severity_label"] = lambda value: label_value(value, SEVERITY_LABELS)
templates.env.filters["rule_label"] = lambda value: label_value(value, RULE_LABELS)

NOTIFICATION_LABELS = {
    "email": "邮件",
    "webhook": "Webhook",
    "telegram": "Telegram",
    "dingtalk": "钉钉",
    "feishu": "飞书",
    "work_wechat": "企业微信",
}

NOTIFICATION_DEFAULTS = {
    "email": {"encryption": "ssl", "port": "465"},
    "webhook": {},
    "telegram": {},
    "dingtalk": {},
    "feishu": {},
    "work_wechat": {},
}


templates.env.filters["notification_label"] = lambda value: label_value(value, NOTIFICATION_LABELS)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    scanner.requeue_orphaned_running_jobs()
    task = asyncio.create_task(background_scheduler())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="GitHub Monitor", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")


async def background_scheduler() -> None:
    while True:
        try:
            await asyncio.to_thread(scanner.requeue_stale_running_jobs)
            await asyncio.to_thread(scanner.enqueue_due_jobs)
            await asyncio.to_thread(scanner.run_pending_jobs, 2)
        except Exception:
            print(traceback.format_exc())
        await asyncio.sleep(60)


def redirect(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def safe_next_path(value: str | None, fallback: str = "/findings") -> str:
    if not value:
        return fallback
    value = value.strip()
    if not value.startswith("/") or value.startswith("//"):
        return fallback
    return value


def wants_json(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "")


def current_user(request: Request) -> str | None:
    username = read_session(request.cookies.get("ghmon_session"))
    if not username:
        return None
    if not db.query_one("select id from users where username = ?", (username,)):
        return None
    return username


def has_users() -> bool:
    return db.query_one("select id from users limit 1") is not None


def require_user(request: Request) -> str | RedirectResponse:
    if not has_users():
        return redirect("/register")
    user = current_user(request)
    return user if user else redirect("/login")


def render(request: Request, template: str, context: dict | None = None) -> HTMLResponse:
    data = {"request": request, "user": current_user(request), "active": ""}
    data.update(context or {})
    return templates.TemplateResponse(request, template, data)


def selected_ids(form: dict[str, str]) -> list[int]:
    raw = form.get("ids", "")
    ids: list[int] = []
    for item in raw.split(","):
        item = item.strip()
        if item.isdigit():
            ids.append(int(item))
    return ids


def url_with_query(request: Request, path: str | None = None, **updates) -> str:
    params = dict(request.query_params)
    for key, value in updates.items():
        if value is None or value == "":
            params.pop(key, None)
        else:
            params[key] = str(value)
    query = urlencode(params)
    target = path or request.url.path
    return f"{target}?{query}" if query else target


def pagination(request: Request, total: int, default_per_page: int = 10, path: str | None = None) -> dict:
    requested_per_page = as_int(request.query_params.get("per_page"), default_per_page)
    per_page = requested_per_page if requested_per_page in PER_PAGE_OPTIONS else default_per_page
    page = max(1, as_int(request.query_params.get("page"), 1))
    pages = max(1, math.ceil(total / per_page)) if total else 1
    page = min(page, pages)
    page_path = path or request.url.path
    link_defaults = {"message": None, "message_type": None}
    current_url = url_with_query(request, page=page, per_page=per_page, path=page_path, **link_defaults)
    query_string = current_url.partition("?")[2]
    return {
        "page": page,
        "pages": pages,
        "per_page": per_page,
        "per_page_options": PER_PAGE_OPTIONS,
        "size_links": [
            {"size": size, "url": url_with_query(request, page=1, per_page=size, path=page_path, **link_defaults)}
            for size in PER_PAGE_OPTIONS
        ],
        "offset": (page - 1) * per_page,
        "total": total,
        "prev": max(1, page - 1),
        "next": min(pages, page + 1),
        "current_url": current_url,
        "query_string": f"?{query_string}" if query_string else "",
        "prev_url": url_with_query(request, page=max(1, page - 1), per_page=per_page, path=page_path, **link_defaults),
        "next_url": url_with_query(request, page=min(pages, page + 1), per_page=per_page, path=page_path, **link_defaults),
    }


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if not has_users():
        return redirect("/register")
    if current_user(request):
        return redirect("/")
    return render(request, "login.html", {"error": ""})


@app.post("/login")
async def login(request: Request):
    if not has_users():
        return redirect("/register")
    form = await parse_form(request)
    username = form.get("username", "")
    password = form.get("password", "")
    user = db.query_one("select * from users where username = ?", (username,))
    if not user or not verify_password(password, user["password_hash"]):
        return render(request, "login.html", {"error": "用户名或密码错误"})

    response = redirect("/")
    response.set_cookie(
        "ghmon_session",
        make_session(username),
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 12,
    )
    return response


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    if has_users():
        return redirect("/login")
    return render(request, "register.html", {"error": ""})


@app.post("/register")
async def register(request: Request):
    if has_users():
        return redirect("/login")
    form = await parse_form(request)
    username = form.get("username", "").strip()
    password = form.get("password", "")
    confirm = form.get("confirm", "")
    if not username or not password:
        return render(request, "register.html", {"error": "用户名和密码不能为空"})
    if len(password) < 8:
        return render(request, "register.html", {"error": "密码长度至少 8 位"})
    if password != confirm:
        return render(request, "register.html", {"error": "两次输入的密码不一致"})
    db.execute(
        "insert into users(username, password_hash) values(?, ?)",
        (username, hash_password(password)),
    )
    response = redirect("/")
    response.set_cookie(
        "ghmon_session",
        make_session(username),
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 12,
    )
    return response


@app.get("/logout")
async def logout():
    response = redirect("/login")
    response.delete_cookie("ghmon_session")
    return response


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    user = require_user(request)
    if isinstance(user, RedirectResponse):
        return user

    metrics = {
        "findings": db.query_one("select count(*) as count from findings")["count"],
        "pending": db.query_one("select count(*) as count from findings where status = 'pending'")["count"],
        "solved": db.query_one("select count(*) as count from findings where status = 'solved'")["count"],
        "false_positive": db.query_one("select count(*) as count from findings where status = 'false_positive'")["count"],
        "abnormal": db.query_one("select count(*) as count from findings where status = 'abnormal'")["count"],
        "tasks": db.query_one("select count(*) as count from monitor_tasks")["count"],
        "queued": db.query_one("select count(*) as count from scan_jobs where status = 'queued'")["count"],
        "running": db.query_one("select count(*) as count from scan_jobs where status = 'running'")["count"],
        "tokens": db.query_one("select count(*) as count from tokens")["count"],
    }
    token_quota = db.query_one(
        "select coalesce(sum(api_limit), 0) as total, coalesce(sum(api_remaining), 0) as remaining from tokens where status in ('normal', 'unknown')"
    )
    recent = db.query_all(
        """
        select f.*, t.name as task_name
        from findings f
        left join monitor_tasks t on t.id = f.task_id
        order by f.id desc
        limit 8
        """
    )
    jobs = db.query_all(
        """
        select j.*, t.name as task_name
        from scan_jobs j
        left join monitor_tasks t on t.id = j.task_id
        order by j.id desc
        limit 8
        """
    )
    return render(
        request,
        "dashboard.html",
        {
            "active": "dashboard",
            "metrics": metrics,
            "token_quota": token_quota,
            "recent": recent,
            "jobs": jobs,
        },
    )


@app.post("/jobs/enqueue")
async def enqueue_jobs(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    scanner.enqueue_due_jobs()
    return redirect("/")


@app.post("/jobs/run")
async def run_jobs(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    await asyncio.to_thread(scanner.run_pending_jobs, 5)
    return redirect("/")


@app.get("/jobs", response_class=HTMLResponse)
async def jobs_page(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    total = db.query_one("select count(*) as count from scan_jobs")["count"]
    page = pagination(request, total, path="/jobs")
    rows = db.query_all(
        """
        select j.*, t.name as task_name
        from scan_jobs j
        left join monitor_tasks t on t.id = j.task_id
        order by j.id desc
        limit ? offset ?
        """,
        (page["per_page"], page["offset"]),
    )
    return render(request, "jobs.html", {"active": "jobs", "jobs": rows, "page": page})


@app.post("/jobs/{job_id}/retry")
async def retry_job(request: Request, job_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    db.execute(
        """
        update scan_jobs
        set status = 'queued', error = '', started_at = null, finished_at = null
        where id = ?
        """,
        (job_id,),
    )
    return redirect(url_with_query(request, "/jobs"))


@app.post("/jobs/{job_id}/delete")
async def delete_job(request: Request, job_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    db.execute("delete from scan_jobs where id = ?", (job_id,))
    return redirect(url_with_query(request, "/jobs"))


@app.post("/jobs/clear")
async def clear_jobs(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    db.execute("delete from scan_jobs where status in ('success', 'failed')")
    return redirect(url_with_query(request, "/jobs"))


@app.get("/tokens", response_class=HTMLResponse)
async def tokens_page(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    message = request.query_params.get("message", "")
    message_type = request.query_params.get("message_type", "info")
    total = db.query_one("select count(*) as count from tokens")["count"]
    page = pagination(request, total, path="/tokens")
    rows = [
        dict(row)
        for row in db.query_all(
            """
            select id, name, status, api_limit, api_remaining, api_reset_at, last_checked_at, created_at, updated_at
            from tokens
            order by id desc
            limit ? offset ?
            """,
            (page["per_page"], page["offset"]),
        )
    ]
    for row in rows:
        row["quota_percent"] = round(row["api_remaining"] / row["api_limit"] * 100, 1) if row["api_limit"] else 0
    return render(
        request,
        "tokens.html",
        {
            "active": "tokens",
            "tokens": rows,
            "page": page,
            "message": message,
            "message_type": message_type if message_type in {"success", "error", "info"} else "info",
        },
    )


@app.post("/tokens")
async def create_token(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    form = await parse_form(request)
    token = form.get("token", "").strip()
    if not token:
        return redirect(url_with_query(request, "/tokens", message_type="error", message="GitHub Token 不能为空"))
    token_id = db.execute(
        """
        insert or ignore into tokens(name, token, updated_at)
        values(?, ?, datetime('now', 'localtime'))
        """,
        (form.get("name", ""), token),
    )
    if not token_id:
        return redirect(url_with_query(request, "/tokens", message_type="info", message="Token 已存在"))
    return redirect(url_with_query(request, "/tokens", message_type="success", message="Token 已新增，请点击测试获取配额"))


@app.post("/tokens/{token_id}/test")
async def test_token(request: Request, token_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    ok, message = await asyncio.to_thread(github_client.test_token, token_id)
    message_type = "success" if ok else "error"
    return redirect(url_with_query(request, "/tokens", message_type=message_type, message=message))


@app.post("/tokens/{token_id}/delete")
async def delete_token(request: Request, token_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    db.execute("delete from tokens where id = ?", (token_id,))
    return redirect(url_with_query(request, "/tokens"))


@app.get("/tasks", response_class=HTMLResponse)
async def tasks_page(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    total = db.query_one("select count(*) as count from monitor_tasks")["count"]
    page = pagination(request, total, path="/tasks")
    tasks = db.query_all("select * from monitor_tasks order by id desc limit ? offset ?", (page["per_page"], page["offset"]))
    return render(request, "tasks.html", {"active": "tasks", "tasks": tasks, "edit": None, "page": page})


@app.get("/tasks/{task_id}/edit", response_class=HTMLResponse)
async def edit_task_page(request: Request, task_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    total = db.query_one("select count(*) as count from monitor_tasks")["count"]
    page = pagination(request, total, path="/tasks")
    tasks = db.query_all("select * from monitor_tasks order by id desc limit ? offset ?", (page["per_page"], page["offset"]))
    edit = db.query_one("select * from monitor_tasks where id = ?", (task_id,))
    return render(request, "tasks.html", {"active": "tasks", "tasks": tasks, "edit": edit, "page": page})


@app.post("/tasks")
async def save_task(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    form = await parse_form(request)
    params = (
        form.get("name", "").strip(),
        form.get("keywords", "").strip(),
        form.get("match_mode", "fuzzy"),
        as_int(form.get("scan_pages"), 3),
        as_int(form.get("scan_interval_min"), 60),
        form.get("store_type", "file_once"),
        form.get("ignore_owners", ""),
        form.get("ignore_repos", ""),
    )
    task_id = as_int(form.get("id"), 0)
    if task_id:
        db.execute(
            """
            update monitor_tasks
            set name = ?, keywords = ?, match_mode = ?, scan_pages = ?,
                scan_interval_min = ?, store_type = ?, ignore_owners = ?,
                ignore_repos = ?, updated_at = datetime('now', 'localtime')
            where id = ?
            """,
            (*params, task_id),
        )
    else:
        db.execute(
            """
            insert into monitor_tasks(
                name, keywords, match_mode, scan_pages, scan_interval_min,
                store_type, ignore_owners, ignore_repos, next_scan_at
            )
            values(?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
            """,
            params,
        )
    return redirect(url_with_query(request, "/tasks"))


@app.post("/tasks/{task_id}/toggle")
async def toggle_task(request: Request, task_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    db.execute(
        "update monitor_tasks set enabled = case enabled when 1 then 0 else 1 end, updated_at = datetime('now', 'localtime') where id = ?",
        (task_id,),
    )
    return redirect(url_with_query(request, "/tasks"))


@app.post("/tasks/{task_id}/run")
async def run_task(request: Request, task_id: int, background_tasks: BackgroundTasks):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    scanner.enqueue_task_now(task_id)
    background_tasks.add_task(scanner.run_task_jobs, task_id)
    return redirect(url_with_query(request, "/tasks"))


@app.post("/tasks/{task_id}/delete")
async def delete_task(request: Request, task_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    db.execute("delete from monitor_tasks where id = ?", (task_id,))
    return redirect(url_with_query(request, "/tasks"))


@app.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    status = request.query_params.get("status", "")
    search = request.query_params.get("search", "")
    where = []
    params: list[str] = []
    if status:
        where.append("f.status = ?")
        params.append(status)
    if search:
        where.append(
            "(f.repo_owner like ? or f.repo_name like ? or f.repo_description like ? or f.file_path like ? or f.keyword like ? or f.rule_name like ?)"
        )
        params.extend([f"%{search}%"] * 6)
    where_sql = "where " + " and ".join(where) if where else ""
    total = db.query_one(f"select count(*) as count from findings f {where_sql}", tuple(params))["count"]
    page = pagination(request, total, path="/findings")
    rows = db.query_all(
        f"""
        select f.*, t.name as task_name,
               (select content from finding_fragments ff where ff.finding_id = f.id order by ff.id desc limit 1) as fragment
        from findings f
        left join monitor_tasks t on t.id = f.task_id
        {where_sql}
        order by f.id desc
        limit ? offset ?
        """,
        (*params, page["per_page"], page["offset"]),
    )
    return render(
        request,
        "findings.html",
        {
            "active": "findings",
            "findings": rows,
            "status": status,
            "search": search,
            "page": page,
        },
    )


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail(request: Request, finding_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    finding = db.query_one(
        """
        select f.*, t.name as task_name
        from findings f
        left join monitor_tasks t on t.id = f.task_id
        where f.id = ?
        """,
        (finding_id,),
    )
    if not finding:
        return redirect("/findings")
    fragments = db.query_all(
        "select * from finding_fragments where finding_id = ? order by id asc",
        (finding_id,),
    )
    return render(
        request,
        "finding_detail.html",
        {"active": "findings", "finding": finding, "fragments": fragments},
    )


@app.post("/findings/{finding_id}/update")
async def update_finding(request: Request, finding_id: int):
    user = require_user(request)
    if isinstance(user, RedirectResponse):
        if wants_json(request):
            return JSONResponse({"success": False, "message": "请先登录"}, status_code=401)
        return redirect("/login")
    form = await parse_form(request)
    status = form.get("status", "pending")
    description = form.get("description", "")
    db.execute(
        """
        update findings
        set status = ?, description = ?, handler = ?, updated_at = datetime('now', 'localtime')
        where id = ?
        """,
        (status, description, user, finding_id),
    )
    if wants_json(request):
        return JSONResponse(
            {
                "success": True,
                "message": "已保存",
                "status": status,
                "status_label": label_value(status, STATUS_LABELS),
                "description": description,
                "handler": user,
            }
        )
    return redirect(safe_next_path(form.get("next"), url_with_query(request, "/findings")))


@app.post("/findings/batch")
async def batch_update_findings(request: Request):
    user = require_user(request)
    if isinstance(user, RedirectResponse):
        return redirect("/login")
    form = await parse_form(request)
    ids = selected_ids(form)
    if not ids:
        return redirect(url_with_query(request, "/findings"))
    action = form.get("action", "")
    placeholders = ",".join("?" for _ in ids)
    if action == "delete":
        db.execute(f"delete from findings where id in ({placeholders})", tuple(ids))
    elif action in {"pending", "false_positive", "abnormal", "solved"}:
        db.execute(
            f"""
            update findings
            set status = ?, handler = ?, updated_at = datetime('now', 'localtime')
            where id in ({placeholders})
            """,
            (action, user, *ids),
        )
    return redirect(url_with_query(request, "/findings"))


@app.post("/findings/{finding_id}/whitelist-repo")
async def whitelist_finding_repo(request: Request, finding_id: int):
    if isinstance(require_user(request), RedirectResponse):
        if wants_json(request):
            return JSONResponse({"success": False, "message": "请先登录"}, status_code=401)
        return redirect("/login")
    form = await parse_form(request)
    finding = db.query_one("select repo_owner, repo_name from findings where id = ?", (finding_id,))
    if finding:
        pattern = f"{finding['repo_owner']}/{finding['repo_name']}"
        db.execute(
            "insert or ignore into whitelists(type, pattern, reason) values('repo', ?, '从扫描结果加入')",
            (pattern,),
        )
        db.execute(
            """
            update findings
            set status = 'false_positive', description = '仓库已加入白名单', updated_at = datetime('now', 'localtime')
            where repo_owner = ? and repo_name = ? and status = 'pending'
            """,
            (finding["repo_owner"], finding["repo_name"]),
        )
    if wants_json(request):
        return JSONResponse({"success": True, "message": "仓库已加入白名单"})
    return redirect(safe_next_path(form.get("next"), url_with_query(request, "/findings")))


@app.post("/findings/{finding_id}/whitelist-file")
async def whitelist_finding_file(request: Request, finding_id: int):
    if isinstance(require_user(request), RedirectResponse):
        if wants_json(request):
            return JSONResponse({"success": False, "message": "请先登录"}, status_code=401)
        return redirect("/login")
    form = await parse_form(request)
    finding = db.query_one("select file_path from findings where id = ?", (finding_id,))
    if finding:
        filename = Path(finding["file_path"]).name
        db.execute(
            "insert or ignore into whitelists(type, pattern, reason) values('filename', ?, '从扫描结果加入')",
            (filename,),
        )
    if wants_json(request):
        return JSONResponse({"success": True, "message": "文件已加入白名单"})
    return redirect(safe_next_path(form.get("next"), url_with_query(request, "/findings")))


@app.post("/findings/{finding_id}/delete")
async def delete_finding(request: Request, finding_id: int):
    if isinstance(require_user(request), RedirectResponse):
        if wants_json(request):
            return JSONResponse({"success": False, "message": "请先登录"}, status_code=401)
        return redirect("/login")
    form = await parse_form(request)
    db.execute("delete from findings where id = ?", (finding_id,))
    return redirect(safe_next_path(form.get("next"), url_with_query(request, "/findings")))


@app.get("/whitelists", response_class=HTMLResponse)
async def whitelists_page(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    total = db.query_one("select count(*) as count from whitelists")["count"]
    page = pagination(request, total, path="/whitelists")
    rows = db.query_all("select * from whitelists order by id desc limit ? offset ?", (page["per_page"], page["offset"]))
    return render(request, "whitelists.html", {"active": "whitelists", "whitelists": rows, "page": page})


@app.post("/whitelists")
async def create_whitelist(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    form = await parse_form(request)
    db.execute(
        "insert or ignore into whitelists(type, pattern, reason) values(?, ?, ?)",
        (form.get("type", "repo"), form.get("pattern", "").strip(), form.get("reason", "")),
    )
    return redirect(url_with_query(request, "/whitelists"))


@app.post("/whitelists/{whitelist_id}/toggle")
async def toggle_whitelist(request: Request, whitelist_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    db.execute(
        "update whitelists set enabled = case enabled when 1 then 0 else 1 end where id = ?",
        (whitelist_id,),
    )
    return redirect(url_with_query(request, "/whitelists"))


@app.post("/whitelists/{whitelist_id}/delete")
async def delete_whitelist(request: Request, whitelist_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    db.execute("delete from whitelists where id = ?", (whitelist_id,))
    return redirect(url_with_query(request, "/whitelists"))


@app.get("/notifications", response_class=HTMLResponse)
async def notifications_page(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    message = request.query_params.get("message", "")
    message_type = request.query_params.get("message_type", "info")
    total = db.query_one("select count(*) as count from notification_configs")["count"]
    page = pagination(request, total, path="/notifications")
    rows = []
    for row in db.query_all(
        "select * from notification_configs order by id asc limit ? offset ?",
        (page["per_page"], page["offset"]),
    ):
        item = dict(row)
        try:
            config_values = json.loads(item["config_json"] or "{}")
        except json.JSONDecodeError:
            config_values = {}
        values = dict(NOTIFICATION_DEFAULTS.get(item["type"], {}))
        values.update(config_values)
        for secret_field in ["password", "token", "secret"]:
            values[f"has_{secret_field}"] = bool(values.get(secret_field))
            if secret_field in values:
                values[secret_field] = ""
        item["settings"] = values
        rows.append(item)
    return render(
        request,
        "notifications.html",
        {
            "active": "notifications",
            "configs": rows,
            "page": page,
            "message": message,
            "message_type": message_type if message_type in {"success", "error", "info"} else "info",
        },
    )


@app.post("/notifications/{config_id}")
async def save_notification(request: Request, config_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    form = await parse_form(request)
    config = db.query_one("select type, config_json from notification_configs where id = ?", (config_id,))
    if not config:
        return redirect(url_with_query(request, "/notifications", message_type="error", message="通知配置不存在"))
    try:
        old_values = json.loads(config["config_json"] or "{}")
    except json.JSONDecodeError:
        old_values = {}
    raw_json = json.dumps(notification_config_from_form(config["type"], form, old_values), ensure_ascii=False)
    db.execute(
        """
        update notification_configs
        set enabled = ?, interval_min = ?, start_time = ?, end_time = ?,
            config_json = ?, template_title = ?, template_body = ?,
            updated_at = datetime('now', 'localtime')
        where id = ?
        """,
        (
            1 if form.get("enabled") == "1" else 0,
            as_int(form.get("interval_min"), 30),
            form.get("start_time", "00:00:00"),
            form.get("end_time", "23:59:59"),
            raw_json,
            form.get("template_title", "GitHub 监控告警"),
            form.get("template_body", "本时段共有 {{count}} 条待处理风险。"),
            config_id,
        ),
    )
    return redirect(url_with_query(request, "/notifications", message_type="success", message="通知配置已保存"))


@app.post("/notifications/{config_id}/test")
async def test_notification(request: Request, config_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    wants_json = "application/json" in request.headers.get("accept", "")
    config = db.query_one("select * from notification_configs where id = ?", (config_id,))
    if config:
        form = await parse_form(request)
        try:
            old_values = json.loads(config["config_json"] or "{}")
        except json.JSONDecodeError:
            old_values = {}
        test_values = notification_config_from_form(config["type"], form, old_values)
        try:
            notifications.send(
                config["type"],
                "GitHub Monitor 测试通知",
                "这是一条测试通知。",
                test_values,
            )
        except Exception as exc:
            if wants_json:
                return JSONResponse({"success": False, "message": str(exc)})
            return redirect(url_with_query(request, "/notifications", message_type="error", message=str(exc)))
    if wants_json:
        return JSONResponse({"success": True, "message": "测试通知已发送"})
    return redirect(url_with_query(request, "/notifications", message_type="success", message="测试通知已发送"))


def notification_config_from_form(channel: str, form: dict[str, str], old_values: dict | None = None) -> dict[str, str]:
    fields = {
        "email": ["encryption", "host", "port", "username", "password", "from", "to"],
        "webhook": ["webhook", "headers", "params"],
        "telegram": ["token", "chat_id"],
        "dingtalk": ["webhook", "secret"],
        "feishu": ["webhook", "secret"],
        "work_wechat": ["webhook"],
    }.get(channel, [])
    data = {}
    old_values = old_values or {}
    secret_fields = {"password", "token", "secret"}
    for field in fields:
        value = form.get(field, "")
        if field in {"host", "username", "from", "webhook", "secret", "token", "chat_id", "port", "encryption"}:
            value = value.strip()
        if field == "webhook" and not value and old_values.get("url"):
            value = old_values["url"]
        if field in secret_fields and not value and old_values.get(field):
            value = old_values[field]
        data[field] = value
    return data


@app.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    total = db.query_one("select count(*) as count from rule_signatures")["count"]
    page = pagination(request, total, path="/rules")
    rows = db.query_all("select * from rule_signatures order by id desc limit ? offset ?", (page["per_page"], page["offset"]))
    return render(request, "rules.html", {"active": "rules", "rules": rows, "edit": None, "page": page})


@app.get("/rules/{rule_id}/edit", response_class=HTMLResponse)
async def edit_rule_page(request: Request, rule_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    total = db.query_one("select count(*) as count from rule_signatures")["count"]
    page = pagination(request, total, path="/rules")
    rows = db.query_all("select * from rule_signatures order by id desc limit ? offset ?", (page["per_page"], page["offset"]))
    edit = db.query_one("select * from rule_signatures where id = ?", (rule_id,))
    return render(request, "rules.html", {"active": "rules", "rules": rows, "edit": edit, "page": page})


@app.post("/rules")
async def save_rule(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    form = await parse_form(request)
    params = (
        form.get("name", "").strip(),
        form.get("part", "contents"),
        form.get("match", "").strip(),
        form.get("regex", "").strip(),
        form.get("severity", "medium"),
    )
    rule_id = as_int(form.get("id"), 0)
    if rule_id:
        db.execute(
            """
            update rule_signatures
            set name = ?, part = ?, match = ?, regex = ?, severity = ?
            where id = ?
            """,
            (*params, rule_id),
        )
    else:
        db.execute(
            """
            insert or ignore into rule_signatures(name, part, match, regex, severity)
            values(?, ?, ?, ?, ?)
            """,
            params,
        )
    return redirect(url_with_query(request, "/rules"))


@app.post("/rules/{rule_id}/toggle")
async def toggle_rule(request: Request, rule_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    db.execute(
        "update rule_signatures set enabled = case enabled when 1 then 0 else 1 end where id = ?",
        (rule_id,),
    )
    return redirect(url_with_query(request, "/rules"))


@app.post("/rules/{rule_id}/delete")
async def delete_rule(request: Request, rule_id: int):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    db.execute("delete from rule_signatures where id = ?", (rule_id,))
    return redirect(url_with_query(request, "/rules"))


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    user = require_user(request)
    if isinstance(user, RedirectResponse):
        return redirect("/login")
    settings = {row["key"]: row["value"] for row in db.query_all("select * from settings")}
    return render(
        request,
        "settings.html",
        {
            "active": "settings",
            "settings": settings,
            "message": request.query_params.get("message", ""),
            "message_type": request.query_params.get("message_type", "info"),
        },
    )


@app.post("/settings")
async def save_settings(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    form = await parse_form(request)
    for key in ["proxy_url", "save_fragments", "notify_template_title", "notify_template_body"]:
        db.set_setting(key, form.get(key, ""))
    return redirect("/settings")


@app.post("/settings/test-proxy")
async def test_proxy(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    form = await parse_form(request)
    proxy_url = form.get("proxy_url", "").strip()
    ok, message = await asyncio.to_thread(github_client.test_proxy, proxy_url)
    if ok:
        db.set_setting("proxy_url", proxy_url)
    message_type = "success" if ok else "error"
    return redirect(f"/settings?message_type={message_type}&message={quote(message)}")


@app.get("/mobile", response_class=HTMLResponse)
async def mobile_page(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return redirect("/login")
    status = request.query_params.get("status", "")
    search = request.query_params.get("search", "")
    where = []
    params: list[str] = []
    if status:
        where.append("f.status = ?")
        params.append(status)
    if search:
        where.append(
            "(f.repo_owner like ? or f.repo_name like ? or f.repo_description like ? or f.file_path like ? or f.keyword like ? or f.rule_name like ?)"
        )
        params.extend([f"%{search}%"] * 6)
    where_sql = "where " + " and ".join(where) if where else ""
    total = db.query_one(f"select count(*) as count from findings f {where_sql}", tuple(params))["count"]
    page = pagination(request, total, path="/mobile")
    items = db.query_all(
        f"""
        select f.*, t.name as task_name,
               (select content from finding_fragments ff where ff.finding_id = f.id order by ff.id desc limit 1) as fragment
        from findings f
        left join monitor_tasks t on t.id = f.task_id
        {where_sql}
        order by f.id desc
        limit ? offset ?
        """,
        (*params, page["per_page"], page["offset"]),
    )
    return render(
        request,
        "mobile.html",
        {
            "active": "findings",
            "findings": items,
            "status": status,
            "search": search,
            "page": page,
        },
    )


@app.get("/api/home/metric")
async def api_metric(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return {"success": False}
    return {
        "success": True,
        "data": {
            "codeLeakCount": db.query_one("select count(*) as count from findings")["count"],
            "codeLeakPending": db.query_one("select count(*) as count from findings where status = 'pending'")["count"],
            "codeLeakSolved": db.query_one("select count(*) as count from findings where status = 'solved'")["count"],
            "queueJobCount": db.query_one("select count(*) as count from scan_jobs where status = 'queued'")["count"],
        },
    }


@app.get("/api/home/disk")
async def api_disk(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return {"success": False}
    stat = os.statvfs(str(db.DATA_DIR))
    total = stat.f_blocks * stat.f_frsize
    free = stat.f_bavail * stat.f_frsize
    used = total - free
    return {"success": True, "data": {"used": used, "total": total, "percent": used / total * 100 if total else 0}}


@app.get("/api/home/tokenQuota")
async def api_token_quota(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return {"success": False}
    quota = db.query_one(
        "select coalesce(sum(api_limit), 0) as total, coalesce(sum(api_remaining), 0) as remaining from tokens where status in ('normal', 'unknown')"
    )
    total = quota["total"]
    remaining = quota["remaining"]
    used = total - remaining
    return {
        "success": True,
        "data": [
            {"name": "可用", "value": remaining, "percent": remaining / total if total else 0},
            {"name": "已用", "value": used, "percent": used / total if total else 0},
        ],
    }


@app.get("/api/home/jobCount")
async def api_job_count(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return {"success": False}
    return {"success": True, "data": db.query_one("select count(*) as count from monitor_tasks")["count"]}


@app.get("/api/home/tokenCount")
async def api_token_count(request: Request):
    if isinstance(require_user(request), RedirectResponse):
        return {"success": False}
    return {"success": True, "data": db.query_one("select count(*) as count from tokens")["count"]}


@app.post("/profile")
async def update_profile(request: Request):
    user = require_user(request)
    if isinstance(user, RedirectResponse):
        return redirect("/login")
    form = await parse_form(request)
    new_username = form.get("username", "").strip()
    password = form.get("password", "")
    if new_username and new_username != user:
        db.execute("update users set username = ? where username = ?", (new_username, user))
        user = new_username
    if password:
        db.execute("update users set password_hash = ? where username = ?", (hash_password(password), user))
    response = redirect("/settings")
    response.set_cookie(
        "ghmon_session",
        make_session(user),
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 12,
    )
    return response
