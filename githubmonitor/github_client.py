import json
import socket
import time
from datetime import datetime, timedelta
from email.utils import formatdate, parsedate_to_datetime
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request

from . import db
from .http_utils import open_external


API_BASE = "https://api.github.com"
USER_AGENT = "GithubMonitor-FastAPI"
GITHUB_API_VERSION = "2022-11-28"
HTTP_MAX_RETRIES = 5
HTTP_RETRY_DELAY_SECONDS = 2
HTTP_MAX_RETRY_SLEEP_SECONDS = 10
HTTP_TIMEOUT_TEST = 5


class GitHubError(RuntimeError):
    pass


class RateLimitError(GitHubError):
    pass


class TokenUnavailableError(GitHubError):
    pass


def reset_to_sql(reset: str | None) -> str | None:
    if not reset:
        return None
    try:
        return datetime.fromtimestamp(int(reset)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def retry_after_to_sql(value: str | None) -> str | None:
    if not value:
        return None
    if value.isdigit():
        return (datetime.now() + timedelta(seconds=int(value))).strftime("%Y-%m-%d %H:%M:%S")
    try:
        return parsedate_to_datetime(value).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def auth_headers(token: str, accept: str = "application/vnd.github+json") -> dict[str, str]:
    return {
        "Accept": accept,
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }


def request_json(
    token_row,
    path: str,
    params: dict | None = None,
    accept: str = "application/vnd.github+json",
    timeout: int = 30,
    max_retries: int = HTTP_MAX_RETRIES,
) -> dict:
    url = f"{API_BASE}{path}"
    if params:
        url = f"{url}?{urlencode(params)}"

    attempts = max(1, int(max_retries))
    proxy = db.get_setting("proxy_url", "")
    for attempt in range(attempts):
        request = Request(url, headers=auth_headers(token_row["token"], accept=accept))
        try:
            response_context = open_external(request, timeout=timeout, proxy=proxy)
            with response_context as response:
                body = response.read().decode()
                update_rate_from_headers(token_row["id"], response.headers)
                return json.loads(body) if body else {}
        except HTTPError as exc:
            payload = exc.read().decode(errors="replace")
            message = payload
            try:
                message = json.loads(payload).get("message", payload)
            except json.JSONDecodeError:
                pass

            if exc.code == 401:
                mark_token(token_row["id"], "abnormal")
                raise TokenUnavailableError(f"GitHub API {exc.code}: {message}") from exc
            if is_rate_limited_response(exc.code, exc.headers, message):
                update_rate_from_headers(token_row["id"], exc.headers, status="rate_limited")
                raise RateLimitError(f"GitHub API {exc.code}: {message}") from exc
            if is_retryable_http_status(exc.code) and attempt < attempts - 1:
                update_rate_from_headers(token_row["id"], exc.headers)
                sleep_before_retry(attempt, exc.headers)
                continue

            update_rate_from_headers(token_row["id"], exc.headers)
            if exc.code == 403:
                mark_token(token_row["id"], "abnormal")
            raise GitHubError(f"GitHub API {exc.code}: {message}") from exc
        except (TimeoutError, socket.timeout) as exc:
            if attempt < attempts - 1:
                sleep_before_retry(attempt)
                continue
            raise GitHubError("GitHub network error: request timed out") from exc
        except URLError as exc:
            if attempt < attempts - 1:
                sleep_before_retry(attempt)
                continue
            raise GitHubError(f"GitHub network error: {exc.reason}") from exc

    raise GitHubError("GitHub network error: retry exhausted")


def is_rate_limited_response(code: int, headers, message: str) -> bool:
    if code == 429:
        return True
    if headers.get("Retry-After") or headers.get("X-RateLimit-Remaining") == "0":
        return True
    message_lower = message.lower()
    return code == 403 and ("rate limit" in message_lower or "abuse" in message_lower)


def is_retryable_http_status(code: int) -> bool:
    return code in {408, 500, 502, 503, 504}


def retry_after_seconds(value: str | None) -> int | None:
    if not value:
        return None
    if value.isdigit():
        return max(0, int(value))
    try:
        delta = parsedate_to_datetime(value).astimezone() - datetime.now().astimezone()
        return max(0, int(delta.total_seconds()))
    except (TypeError, ValueError):
        return None


def sleep_before_retry(attempt: int, headers=None) -> None:
    retry_after = retry_after_seconds(headers.get("Retry-After") if headers else None)
    delay = retry_after if retry_after is not None else HTTP_RETRY_DELAY_SECONDS * (2**attempt)
    time.sleep(min(delay, HTTP_MAX_RETRY_SLEEP_SECONDS))


def update_rate_from_headers(token_id: int, headers, status: str | None = None) -> None:
    limit = headers.get("X-RateLimit-Limit")
    remaining = headers.get("X-RateLimit-Remaining")
    reset_at = retry_after_to_sql(headers.get("Retry-After")) or reset_to_sql(headers.get("X-RateLimit-Reset"))
    if not status:
        status = "normal"
    if remaining == "0":
        status = "rate_limited"
    if status == "rate_limited" and not reset_at:
        reset_at = (datetime.now() + timedelta(seconds=60)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        """
        update tokens
        set status = ?,
            api_limit = coalesce(?, api_limit),
            api_remaining = coalesce(?, api_remaining),
            api_reset_at = coalesce(?, api_reset_at),
            last_checked_at = datetime('now', 'localtime'),
            updated_at = datetime('now', 'localtime')
        where id = ?
        """,
        (
            status,
            int(limit) if limit else None,
            int(remaining) if remaining else None,
            reset_at,
            token_id,
        ),
    )


def mark_token(token_id: int, status: str) -> None:
    db.execute(
        "update tokens set status = ?, updated_at = datetime('now', 'localtime') where id = ?",
        (status, token_id),
    )


def test_token(token_id: int) -> tuple[bool, str]:
    token = db.query_one("select * from tokens where id = ?", (token_id,))
    if not token:
        return False, "Token 不存在"
    try:
        data = request_json(token, "/rate_limit", timeout=10, max_retries=2)
    except GitHubError as exc:
        db.execute(
            """
            update tokens
            set last_checked_at = datetime('now', 'localtime'),
                updated_at = datetime('now', 'localtime')
            where id = ?
            """,
            (token_id,),
        )
        return False, str(exc)

    search = data.get("resources", {}).get("code_search") or data.get("resources", {}).get("search", {})
    db.execute(
        """
        update tokens
        set status = 'normal',
            api_limit = ?,
            api_remaining = ?,
            api_reset_at = ?,
            last_checked_at = datetime('now', 'localtime'),
            updated_at = datetime('now', 'localtime')
        where id = ?
        """,
        (
            search.get("limit", 0),
            search.get("remaining", 0),
            reset_to_sql(str(search.get("reset"))) if search.get("reset") else None,
            token_id,
        ),
    )
    return True, "Token 可用"


def available_token(exclude_ids: set[int] | None = None):
    exclude_ids = exclude_ids or set()
    excluded_sql = ""
    params: list[int] = []
    if exclude_ids:
        placeholders = ",".join("?" for _ in exclude_ids)
        excluded_sql = f"and id not in ({placeholders})"
        params.extend(sorted(exclude_ids))
    rows = db.query_all(
        f"""
        select *
        from tokens
        where (
            status in ('unknown', 'normal')
           or (status = 'rate_limited' and (api_reset_at is null or api_reset_at <= datetime('now', 'localtime')))
        )
          {excluded_sql}
        order by api_remaining desc, id asc
        """,
        tuple(params),
    )
    if rows:
        return rows[0]
    return None


def search_code(token_row, keyword: str, page: int, per_page: int = 50) -> dict:
    per_page = max(1, min(int(per_page), 100))
    return request_json(
        token_row,
        "/search/code",
        {
            "q": keyword,
            "per_page": per_page,
            "page": page,
        },
        accept="application/vnd.github.text-match+json",
    )


def http_date(ts: int) -> str:
    return formatdate(ts, usegmt=True)


def test_proxy(proxy_url: str) -> tuple[bool, str]:
    proxy_url = (proxy_url or "").strip()
    if not proxy_url:
        return False, "代理地址不能为空"

    request = Request(
        f"{API_BASE}/repos/4x99/code6/releases/latest",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        },
    )
    try:
        with open_external(request, timeout=HTTP_TIMEOUT_TEST, proxy=proxy_url) as response:
            response.read()
        return True, "代理可用"
    except HTTPError as exc:
        return False, f"代理测试失败：GitHub API {exc.code}"
    except (TimeoutError, socket.timeout) as exc:
        return False, f"代理测试失败：请求超时（{exc}）"
    except URLError as exc:
        return False, f"代理测试失败：{exc.reason}"
