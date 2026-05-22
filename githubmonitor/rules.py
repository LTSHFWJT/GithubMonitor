import math
import re
import shlex
from pathlib import PurePosixPath

from . import db
from .security import hash_value


def entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {char: value.count(char) / len(value) for char in set(value)}
    return -sum(prob * math.log2(prob) for prob in freq.values())


def filename(path: str) -> str:
    return PurePosixPath(path).name


def extension(path: str) -> str:
    return PurePosixPath(path).suffix.lower()


def search_terms(query: str) -> list[str]:
    try:
        parts = shlex.split(query)
    except ValueError:
        parts = query.split()

    terms: list[str] = []
    for part in parts:
        upper = part.upper()
        if upper in {"AND", "OR", "NOT"}:
            continue
        if ":" in part:
            key = part.split(":", 1)[0].lower()
            if key in {"repo", "org", "user", "language", "path", "filename", "extension", "size", "fork", "in"}:
                continue
        terms.append(part.lstrip("-"))
    return [term for term in terms if term]


def match_mode_passes(mode: str, keyword: str, haystack: str) -> bool:
    if mode == "fuzzy":
        return True
    terms = search_terms(keyword)
    if not terms:
        return True
    if mode == "exact":
        return any(term in haystack for term in terms)
    if mode == "word":
        return any(re.search(rf"\b{re.escape(term)}\b", haystack) is not None for term in terms)
    return True


def detect(path: str, content: str) -> tuple[str, str, str]:
    rules = db.query_all(
        "select * from rule_signatures where enabled = 1 order by case severity when 'critical' then 1 when 'high' then 2 when 'medium' then 3 else 4 end"
    )
    targets = {
        "path": path,
        "filename": filename(path),
        "extension": extension(path),
        "contents": content,
    }
    for rule in rules:
        target = targets.get(rule["part"], "")
        matched_value = ""
        if rule["match"] and rule["match"] == target:
            matched_value = target
        elif rule["regex"]:
            found = re.search(rule["regex"], target, flags=re.IGNORECASE | re.MULTILINE)
            if found:
                matched_value = found.group(0)
        if matched_value:
            return rule["name"], rule["severity"], hash_value(matched_value)

    for line in content.splitlines():
        clean = line.strip()
        if 12 <= len(clean) <= 120 and entropy(clean) >= 4.5:
            return "High entropy string", "medium", hash_value(clean)

    return "Keyword match", "medium", ""


def sanitize_fragment(value: str) -> str:
    value = value or ""
    value = re.sub(r"(gh[pousr]_[A-Za-z0-9_]{8})[A-Za-z0-9_]+", r"\1...", value)
    value = re.sub(r"(AKIA[0-9A-Z]{8})[0-9A-Z]{8}", r"\1...", value)
    value = re.sub(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----).*?(-----END [A-Z ]*PRIVATE KEY-----)", r"\1\n...\n\2", value, flags=re.S)
    return value[:4000]
