import json
import smtplib
import base64
import hashlib
import hmac
import time
from email.message import EmailMessage
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request

from . import db
from .http_utils import insecure_ssl_context, open_external


def render_template(text: str, context: dict[str, object]) -> str:
    for key, value in context.items():
        text = text.replace("{{" + key + "}}", str(value))
    return text


def notify_pending_summary() -> list[str]:
    count = db.query_one("select count(*) as count from findings where status = 'pending'")["count"]
    if count == 0:
        return []
    messages: list[str] = []
    configs = db.query_all(
        """
        select *
        from notification_configs
        where enabled = 1
          and time('now', 'localtime') between start_time and end_time
          and (
            last_sent_at is null
            or strftime('%s', 'now', 'localtime') - strftime('%s', last_sent_at) >= interval_min * 60
          )
        """
    )
    context = {"count": count}
    default_title = db.get_setting("notify_template_title", "GitHub 监控告警")
    default_body = db.get_setting("notify_template_body", "本时段共有 {{count}} 条待处理风险。")
    for config in configs:
        title = render_template(config["template_title"] or default_title, context)
        body = render_template(config["template_body"] or default_body, context)
        try:
            send(config["type"], title, body, json.loads(config["config_json"] or "{}"))
            db.execute(
                "update notification_configs set last_sent_at = datetime('now', 'localtime'), updated_at = datetime('now', 'localtime') where id = ?",
                (config["id"],),
            )
            messages.append(f"{config['type']} 发送成功")
        except Exception as exc:
            messages.append(f"{config['type']} 发送失败：{exc}")
    return messages


def send(channel: str, title: str, body: str, config: dict) -> None:
    if channel == "email":
        send_email(title, body, config)
        return
    if channel == "telegram":
        send_telegram(title, body, config)
        return
    if channel in {"webhook", "dingtalk", "feishu", "work_wechat"}:
        send_webhook(channel, title, body, config)
        return
    raise ValueError(f"不支持的通知类型：{channel}")


def send_email(title: str, body: str, config: dict) -> None:
    host = config.get("host")
    to_addr = config.get("to")
    from_addr = config.get("from") or config.get("username")
    if not host or not to_addr or not from_addr:
        raise ValueError("邮件配置缺少 host/from/to")

    message = EmailMessage()
    message["Subject"] = title
    message["From"] = from_addr
    recipients = [item.strip() for item in to_addr.replace(",", "\n").splitlines() if item.strip()]
    message["To"] = ", ".join(recipients)
    message.set_content(body)

    port = int(config.get("port") or 25)
    username = config.get("username")
    password = config.get("password")
    encryption = str(config.get("encryption", "")).lower()
    use_ssl = encryption == "ssl" or str(config.get("ssl", "")).lower() in {"1", "true", "yes"}
    smtp_cls = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    smtp_kwargs = {"timeout": 10}
    if use_ssl:
        smtp_kwargs["context"] = insecure_ssl_context()
    with smtp_cls(host, port, **smtp_kwargs) as smtp:
        if encryption == "tls" or str(config.get("tls", "")).lower() in {"1", "true", "yes"}:
            smtp.starttls(context=insecure_ssl_context())
        if username:
            smtp.login(username, password or "")
        smtp.send_message(message, to_addrs=recipients)


def send_webhook(channel: str, title: str, body: str, config: dict) -> None:
    url = config.get("url") or config.get("webhook")
    if not url:
        raise ValueError("Webhook 配置缺少 url")

    if channel == "feishu":
        payload = {"msg_type": "text", "content": {"text": f"{title}\n{body}"}}
        secret = config.get("secret")
        if secret:
            timestamp = str(int(time.time()))
            payload["timestamp"] = timestamp
            payload["sign"] = feishu_sign(timestamp, secret)
    elif channel in {"dingtalk", "work_wechat"}:
        payload = {"msgtype": "text", "text": {"content": f"{title}\n{body}"}}
        if channel == "dingtalk":
            url = dingtalk_signed_url(url, config.get("secret"))
    else:
        payload = {"title": title, "content": body}
        headers = parse_lines(config.get("headers", ""))
        params = parse_lines(config.get("params", ""))
        payload = replace_template_values(params, title, body) if params else payload
        send_json(url, payload, headers=headers)
        return

    response = send_json(url, payload)
    if channel == "dingtalk" and int(response.get("errcode", 0)) != 0:
        raise ValueError(response.get("errmsg", "钉钉发送失败"))
    if channel == "work_wechat" and int(response.get("errcode", 0)) != 0:
        raise ValueError(response.get("errmsg", "企业微信发送失败"))
    if channel == "feishu" and int(response.get("code", 0)) != 0:
        raise ValueError(response.get("msg", "飞书发送失败"))


def send_telegram(title: str, body: str, config: dict) -> None:
    token = config.get("token")
    chat_id = config.get("chat_id")
    if not token or not chat_id:
        raise ValueError("Telegram 配置缺少 token/chat_id")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": f"{title}\n{body}"}
    response = send_json(url, payload)
    if not response.get("ok", False):
        raise ValueError(response.get("description", "Telegram 发送失败"))


def send_json(url: str, payload: dict, headers: dict | None = None) -> dict:
    request_headers = {"Content-Type": "application/json"}
    request_headers.update(headers or {})
    data = json.dumps(payload).encode()
    request = Request(url, data=data, headers=request_headers)
    with open_external(request, timeout=10) as response:
        body = response.read().decode()
    if not body:
        return {}
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"raw": body}


def dingtalk_signed_url(url: str, secret: str | None) -> str:
    if not secret:
        return url
    timestamp = str(int(time.time() * 1000))
    string_to_sign = f"{timestamp}\n{secret}".encode()
    sign = base64.b64encode(hmac.new(secret.encode(), string_to_sign, hashlib.sha256).digest()).decode()
    parts = urlsplit(url)
    query = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key not in {"timestamp", "sign"}
    ]
    query.extend([("timestamp", timestamp), ("sign", sign)])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def feishu_sign(timestamp: str, secret: str) -> str:
    string_to_sign = f"{timestamp}\n{secret}".encode()
    return base64.b64encode(hmac.new(string_to_sign, b"", hashlib.sha256).digest()).decode()


def parse_lines(value: str) -> dict[str, str]:
    items: dict[str, str] = {}
    for line in (value or "").splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        if key:
            items[key] = val.strip()
    return items


def replace_template_values(values: dict[str, str], title: str, body: str) -> dict:
    payload: dict = {}
    for key, value in values.items():
        target = payload
        parts = [part for part in key.split(".") if part]
        if not parts:
            continue
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = value.replace("{{title}}", title).replace("{{content}}", body)
    return payload
