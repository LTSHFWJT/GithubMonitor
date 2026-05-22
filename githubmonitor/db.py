import os
import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = Path(os.environ.get("GHMON_DB_PATH", DATA_DIR / "github_monitor.db"))


def now_sql() -> str:
    return sqlite3.connect(":memory:").execute("select datetime('now', 'localtime')").fetchone()[0]


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("pragma foreign_keys = on")
    conn.execute("pragma journal_mode = wal")
    return conn


def query_all(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(sql, params).fetchall()


def query_one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute(sql, params).fetchone()


def execute(sql: str, params: tuple = ()) -> int:
    with connect() as conn:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid


def execute_rowcount(sql: str, params: tuple = ()) -> int:
    with connect() as conn:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.rowcount


def execute_many(sql: str, values: list[tuple]) -> None:
    with connect() as conn:
        conn.executemany(sql, values)
        conn.commit()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            create table if not exists users (
                id integer primary key autoincrement,
                username text not null unique,
                password_hash text not null,
                created_at text not null default (datetime('now', 'localtime'))
            );

            create table if not exists tokens (
                id integer primary key autoincrement,
                name text not null default '',
                token text not null unique,
                status text not null default 'unknown',
                api_limit integer not null default 0,
                api_remaining integer not null default 0,
                api_reset_at text,
                last_checked_at text,
                created_at text not null default (datetime('now', 'localtime')),
                updated_at text not null default (datetime('now', 'localtime'))
            );

            create table if not exists monitor_tasks (
                id integer primary key autoincrement,
                name text not null,
                keywords text not null,
                match_mode text not null default 'fuzzy',
                scan_pages integer not null default 3,
                scan_interval_min integer not null default 60,
                store_type text not null default 'file_once',
                ignore_owners text not null default '',
                ignore_repos text not null default '',
                enabled integer not null default 1,
                last_scan_at text,
                next_scan_at text,
                created_at text not null default (datetime('now', 'localtime')),
                updated_at text not null default (datetime('now', 'localtime'))
            );

            create table if not exists scan_jobs (
                id integer primary key autoincrement,
                task_id integer not null references monitor_tasks(id) on delete cascade,
                keyword text not null,
                status text not null default 'queued',
                error text not null default '',
                started_at text,
                finished_at text,
                created_at text not null default (datetime('now', 'localtime'))
            );

            create table if not exists findings (
                id integer primary key autoincrement,
                uuid text not null unique,
                task_id integer references monitor_tasks(id) on delete set null,
                keyword text not null default '',
                rule_name text not null default '',
                severity text not null default 'medium',
                status text not null default 'pending',
                repo_owner text not null default '',
                repo_name text not null default '',
                repo_description text not null default '',
                repo_url text not null default '',
                file_path text not null default '',
                blob_sha text not null default '',
                html_url text not null default '',
                matched_value_hash text not null default '',
                description text not null default '',
                handler text not null default '',
                created_at text not null default (datetime('now', 'localtime')),
                updated_at text not null default (datetime('now', 'localtime'))
            );

            create index if not exists idx_findings_status on findings(status);
            create index if not exists idx_findings_repo on findings(repo_owner, repo_name);
            create index if not exists idx_findings_task on findings(task_id);

            create table if not exists finding_fragments (
                id integer primary key autoincrement,
                finding_id integer not null references findings(id) on delete cascade,
                content text not null,
                created_at text not null default (datetime('now', 'localtime'))
            );

            create table if not exists whitelists (
                id integer primary key autoincrement,
                type text not null,
                pattern text not null,
                reason text not null default '',
                enabled integer not null default 1,
                created_at text not null default (datetime('now', 'localtime')),
                unique(type, pattern)
            );

            create table if not exists notification_configs (
                id integer primary key autoincrement,
                type text not null unique,
                enabled integer not null default 0,
                interval_min integer not null default 30,
                start_time text not null default '00:00:00',
                end_time text not null default '23:59:59',
                config_json text not null default '{}',
                template_title text not null default 'GitHub 监控告警',
                template_body text not null default '本时段共有 {{count}} 条待处理风险。',
                last_sent_at text,
                created_at text not null default (datetime('now', 'localtime')),
                updated_at text not null default (datetime('now', 'localtime'))
            );

            create table if not exists rule_signatures (
                id integer primary key autoincrement,
                name text not null,
                part text not null,
                match text not null default '',
                regex text not null default '',
                severity text not null default 'medium',
                enabled integer not null default 1,
                unique(name, part, match, regex)
            );

            create table if not exists settings (
                key text primary key,
                value text not null default '',
                updated_at text not null default (datetime('now', 'localtime'))
            );
            """
        )
        conn.commit()

    migrate_scan_jobs()
    migrate_findings_repo_description()
    seed_rules()
    seed_notification_configs()
    seed_settings()


def migrate_scan_jobs() -> None:
    row = query_one(
        "select sql from sqlite_master where type = 'table' and name = 'scan_jobs'"
    )
    if not row or "unique(task_id, keyword, status)" not in (row["sql"] or "").lower():
        return
    with connect() as conn:
        conn.executescript(
            """
            create table if not exists scan_jobs_new (
                id integer primary key autoincrement,
                task_id integer not null references monitor_tasks(id) on delete cascade,
                keyword text not null,
                status text not null default 'queued',
                error text not null default '',
                started_at text,
                finished_at text,
                created_at text not null default (datetime('now', 'localtime'))
            );
            insert into scan_jobs_new(id, task_id, keyword, status, error, started_at, finished_at, created_at)
            select id, task_id, keyword, status, error, started_at, finished_at, created_at
            from scan_jobs;
            drop table scan_jobs;
            alter table scan_jobs_new rename to scan_jobs;
            """
        )
        conn.commit()


def migrate_findings_repo_description() -> None:
    columns = [row["name"] for row in query_all("pragma table_info(findings)")]
    if "repo_description" in columns:
        return
    with connect() as conn:
        conn.execute("alter table findings add column repo_description text not null default ''")
        conn.commit()


def seed_rules() -> None:
    rules = [
        ("AWS Access Key ID", "contents", "", r"AKIA[0-9A-Z]{16}", "high"),
        ("GitHub Token", "contents", "", r"gh[pousr]_[A-Za-z0-9_]{36,255}", "critical"),
        ("Private Key Block", "contents", "", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "critical"),
        ("Slack Token", "contents", "", r"xox[baprs]-[A-Za-z0-9-]{10,}", "high"),
        ("Google API Key", "contents", "", r"AIza[0-9A-Za-z\\-_]{35}", "high"),
        ("Environment File", "filename", ".env", "", "medium"),
        ("SSH Private Key", "filename", "id_rsa", "", "critical"),
        ("AWS Credentials Path", "path", "", r"(^|/)\\.aws/credentials$", "high"),
    ]
    execute_many(
        """
        insert or ignore into rule_signatures(name, part, match, regex, severity)
        values(?, ?, ?, ?, ?)
        """,
        rules,
    )


def seed_notification_configs() -> None:
    channels = [
        ("email",),
        ("webhook",),
        ("telegram",),
        ("dingtalk",),
        ("feishu",),
        ("work_wechat",),
    ]
    execute_many(
        "insert or ignore into notification_configs(type) values(?)",
        channels,
    )


def seed_settings() -> None:
    defaults = [
        ("proxy_url", ""),
        ("save_fragments", "1"),
        ("notify_template_title", "GitHub 监控告警"),
        ("notify_template_body", "本时段共有 {{count}} 条待处理风险。"),
    ]
    execute_many(
        "insert or ignore into settings(key, value) values(?, ?)",
        defaults,
    )


def get_setting(key: str, default: str = "") -> str:
    row = query_one("select value from settings where key = ?", (key,))
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    execute(
        """
        insert into settings(key, value, updated_at)
        values(?, ?, datetime('now', 'localtime'))
        on conflict(key) do update set
            value = excluded.value,
            updated_at = excluded.updated_at
        """,
        (key, value),
    )
