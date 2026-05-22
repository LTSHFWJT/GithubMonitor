import fnmatch
import hashlib
import traceback
from datetime import datetime

from . import db, github_client, notifications, rules
from .forms import lines


SEARCH_PER_PAGE = 30


def enqueue_due_jobs() -> int:
    tasks = db.query_all(
        """
        select *
        from monitor_tasks
        where enabled = 1
          and (next_scan_at is null or next_scan_at <= datetime('now', 'localtime'))
        """
    )
    created = 0
    for task in tasks:
        for keyword in lines(task["keywords"]):
            created += enqueue_job(task["id"], keyword)
        db.execute(
            """
            update monitor_tasks
            set next_scan_at = datetime('now', 'localtime', '+' || scan_interval_min || ' minutes'),
                updated_at = datetime('now', 'localtime')
            where id = ?
            """,
            (task["id"],),
        )
    return created


def enqueue_task_now(task_id: int) -> int:
    task = db.query_one("select * from monitor_tasks where id = ?", (task_id,))
    if not task:
        return 0
    created = 0
    for keyword in lines(task["keywords"]):
        created += enqueue_job(task_id, keyword)
    return created


def enqueue_job(task_id: int, keyword: str) -> int:
    return db.execute_rowcount(
        """
        insert into scan_jobs(task_id, keyword)
        select ?, ?
        where not exists (
            select 1 from scan_jobs
            where task_id = ?
              and keyword = ?
              and status in ('queued', 'running')
        )
        """,
        (task_id, keyword, task_id, keyword),
    )


def run_pending_jobs(limit: int = 3) -> int:
    done = 0
    for job in take_queued_jobs(limit):
        if run_job(job["id"]):
            done += 1
    if done:
        notifications.notify_pending_summary()
    return done


def run_task_jobs(task_id: int, limit: int | None = None) -> int:
    task = db.query_one("select * from monitor_tasks where id = ?", (task_id,))
    if not task:
        return 0
    limit = limit or max(1, len(lines(task["keywords"])))
    done = 0
    for job in take_queued_jobs(limit, task_id=task_id):
        if run_job(job["id"]):
            done += 1
    if done:
        notifications.notify_pending_summary()
    return done


def take_queued_jobs(limit: int, task_id: int | None = None) -> list:
    where = "where status = 'queued'"
    params: list[int] = []
    if task_id is not None:
        where += " and task_id = ?"
        params.append(task_id)
    params.append(limit)
    jobs = db.query_all(
        f"select * from scan_jobs {where} order by id asc limit ?",
        tuple(params),
    )
    claimed = []
    for job in jobs:
        changed = db.execute_rowcount(
            """
            update scan_jobs
            set status = 'running',
                started_at = datetime('now', 'localtime'),
                error = ''
            where id = ? and status = 'queued'
            """,
            (job["id"],),
        )
        if changed:
            claimed.append(job)
    return claimed


def run_job(job_id: int) -> bool:
    job = db.query_one("select * from scan_jobs where id = ?", (job_id,))
    if not job:
        return False
    task = db.query_one("select * from monitor_tasks where id = ?", (job["task_id"],))
    if not task:
        db.execute("delete from scan_jobs where id = ?", (job_id,))
        return True
    if job["status"] != "running":
        changed = db.execute_rowcount(
            """
            update scan_jobs
            set status = 'running',
                started_at = datetime('now', 'localtime'),
                error = ''
            where id = ? and status = 'queued'
            """,
            (job_id,),
        )
        if not changed:
            return False
    try:
        scan_keyword(task, job["keyword"])
        db.execute(
            """
            update scan_jobs
            set status = 'success', finished_at = datetime('now', 'localtime')
            where id = ?
            """,
            (job_id,),
        )
        db.execute(
            "update monitor_tasks set last_scan_at = datetime('now', 'localtime'), updated_at = datetime('now', 'localtime') where id = ?",
            (task["id"],),
        )
    except Exception as exc:
        db.execute(
            """
            update scan_jobs
            set status = 'failed',
                error = ?,
                finished_at = datetime('now', 'localtime')
            where id = ?
            """,
            (f"{exc}\n{traceback.format_exc(limit=3)}", job_id),
        )
    return True


def scan_keyword(task, keyword: str) -> None:
    token = github_client.available_token()
    if not token:
        raise RuntimeError("没有可用 GitHub Token")

    for page in range(1, max(1, int(task["scan_pages"])) + 1):
        data, token = search_code_with_rotation(keyword, page, token)
        items = data.get("items") or []
        if not items:
            break
        for item in items:
            store_item(task, keyword, item)
        if len(items) < SEARCH_PER_PAGE:
            break


def search_code_with_rotation(keyword: str, page: int, token):
    tried_ids: set[int] = set()
    while token:
        try:
            return github_client.search_code(token, keyword, page=page, per_page=SEARCH_PER_PAGE), token
        except github_client.RateLimitError:
            tried_ids.add(token["id"])
            token = github_client.available_token(exclude_ids=tried_ids)
            continue
        except github_client.TokenUnavailableError:
            tried_ids.add(token["id"])
            token = github_client.available_token(exclude_ids=tried_ids)
            continue
    raise RuntimeError("没有可用 GitHub Token")


def store_item(task, keyword: str, item: dict) -> None:
    repo = item.get("repository") or {}
    owner = (repo.get("owner") or {}).get("login", "")
    repo_name = repo.get("name", "")
    repo_description = repo.get("description") or ""
    repo_url = repo.get("html_url", "")
    path = item.get("path", "")
    sha = item.get("sha", "")
    html_url = item.get("html_url", "")
    fragments = " ".join(match.get("fragment", "") for match in item.get("text_matches", []))

    if is_ignored(task, owner, repo_name, path, fragments):
        return
    if not rules.match_mode_passes(task["match_mode"], keyword, fragments):
        return

    rule_name, severity, value_hash = rules.detect(path, fragments)
    uuid = finding_uuid(task["store_type"], owner, repo_name, sha, path)

    finding_id = db.execute(
        """
        insert or ignore into findings(
            uuid, task_id, keyword, rule_name, severity, repo_owner, repo_name,
            repo_description, repo_url, file_path, blob_sha, html_url, matched_value_hash
        )
        values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            uuid,
            task["id"],
            keyword,
            rule_name,
            severity,
            owner,
            repo_name,
            repo_description,
            repo_url,
            path,
            sha,
            html_url,
            value_hash,
        ),
    )
    if finding_id and db.get_setting("save_fragments", "1") == "1":
        db.execute(
            "insert into finding_fragments(finding_id, content) values(?, ?)",
            (finding_id, rules.sanitize_fragment(fragments)),
        )


def requeue_stale_running_jobs(max_running_minutes: int = 60) -> int:
    cutoff = datetime.now().timestamp() - max_running_minutes * 60
    cutoff_sql = datetime.fromtimestamp(cutoff).strftime("%Y-%m-%d %H:%M:%S")
    return db.execute_rowcount(
        """
        update scan_jobs
        set status = 'queued',
            error = '任务执行超时，已重新入队',
            started_at = null
        where status = 'running'
          and started_at is not null
          and started_at < ?
        """,
        (cutoff_sql,),
    )


def requeue_orphaned_running_jobs() -> int:
    return db.execute_rowcount(
        """
        update scan_jobs
        set status = 'queued',
            error = '服务重启后重新入队',
            started_at = null,
            finished_at = null
        where status = 'running'
        """
    )


def finding_uuid(store_type: str, owner: str, repo_name: str, sha: str, path: str) -> str:
    if store_type == "repo_once":
        raw = f"{owner}/{repo_name}"
    elif store_type == "file_once":
        raw = f"{owner}/{repo_name}/{path}"
    else:
        raw = f"{owner}/{repo_name}/{sha}/{path}"
    return hashlib.md5(raw.encode()).hexdigest()


def is_ignored(task, owner: str, repo_name: str, path: str, fragment: str) -> bool:
    repo_full = f"{owner}/{repo_name}"
    for value in lines(task["ignore_owners"]):
        if owner == value:
            return True
    for value in lines(task["ignore_repos"]):
        if value and (value in repo_name or fnmatch.fnmatch(repo_full, value)):
            return True

    whitelists = db.query_all("select * from whitelists where enabled = 1")
    for item in whitelists:
        pattern = item["pattern"]
        if item["type"] == "owner" and fnmatch.fnmatch(owner, pattern):
            return True
        if item["type"] == "repo" and fnmatch.fnmatch(repo_full, pattern):
            return True
        if item["type"] == "path" and fnmatch.fnmatch(path, pattern):
            return True
        if item["type"] == "filename" and fnmatch.fnmatch(rules.filename(path), pattern):
            return True
        if item["type"] == "value" and pattern in fragment:
            return True
    return False
