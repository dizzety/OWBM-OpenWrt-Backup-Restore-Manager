"""TOML subset reader/writer.

Python 3.11+ has ``tomllib`` in the stdlib. For 3.9/3.10 OWBM needs its own
reader, and in both cases it needs a *writer* for the settings menu (``tomllib``
is read-only). This module supports exactly what OWBM writes and what users
realistically type: comments, tables, dotted keys, strings, integers, floats,
booleans and flat arrays of strings/numbers. Anything else raises ``TomlError``
instead of being silently misread.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "b": "\b", "f": "\f"}


class TomlError(ValueError):
    def __init__(self, message: str, line: int) -> None:
        super().__init__(f"строка {line}: {message}")
        self.line = line


def _strip_comment(line: str) -> str:
    out = []
    quote = ""
    escaped = False
    for char in line:
        if quote:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\" and quote == '"':
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            out.append(char)
        elif char == "#":
            break
        else:
            out.append(char)
    return "".join(out).rstrip()


def _split_key(text: str, lineno: int) -> List[str]:
    parts: List[str] = []
    buf = ""
    quote = ""
    for char in text:
        if quote:
            if char == quote:
                quote = ""
            elif char == "\\" and quote == '"':
                buf += char
                continue
            else:
                buf += char
                continue
        if char in "\"'":
            quote = char
            continue
        if char == ".":
            parts.append(buf.strip())
            buf = ""
            continue
        buf += char
    parts.append(buf.strip())
    for part in parts:
        if not part:
            raise TomlError("пустой ключ", lineno)
    return parts


def _parse_value(raw: str, lineno: int) -> Any:
    text = raw.strip()
    if not text:
        raise TomlError("отсутствует значение", lineno)
    if text[0] == '"':
        if len(text) < 2 or text[-1] != '"':
            raise TomlError("незакрытая строка", lineno)
        body = text[1:-1]
        result = []
        index = 0
        while index < len(body):
            char = body[index]
            if char == "\\":
                index += 1
                if index >= len(body):
                    raise TomlError("оборванная escape-последовательность", lineno)
                code = body[index]
                result.append(_ESCAPES.get(code, code))
            else:
                result.append(char)
            index += 1
        return "".join(result)
    if text[0] == "'":
        if len(text) < 2 or text[-1] != "'":
            raise TomlError("незакрытая строка", lineno)
        return text[1:-1]
    if text in ("true", "false"):
        return text == "true"
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        items: List[Any] = []
        buf = ""
        quote = ""
        for char in inner:
            if quote:
                buf += char
                if char == quote:
                    quote = ""
                continue
            if char in "\"'":
                quote = char
                buf += char
                continue
            if char == ",":
                items.append(_parse_value(buf, lineno))
                buf = ""
                continue
            buf += char
        if buf.strip():
            items.append(_parse_value(buf, lineno))
        return items
    if re.fullmatch(r"[+-]?\d+", text):
        return int(text)
    if re.fullmatch(r"[+-]?(\d+\.\d*|\.\d+)([eE][+-]?\d+)?", text):
        return float(text)
    raise TomlError(f"неподдерживаемое значение {text!r}", lineno)


def loads(text: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    table: Dict[str, Any] = data
    lineno = 0
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw_line)
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("[["):
            raise TomlError("массивы таблиц не поддерживаются", lineno)
        if stripped.startswith("["):
            if not stripped.endswith("]"):
                raise TomlError("незакрытая таблица", lineno)
            path = _split_key(stripped[1:-1], lineno)
            table = data
            for part in path:
                node = table.get(part)
                if node is None:
                    node = {}
                    table[part] = node
                if not isinstance(node, dict):
                    raise TomlError(f"ключ {part!r} уже занят значением", lineno)
                table = node
            continue
        if "=" not in stripped:
            raise TomlError("ожидалось key = value", lineno)
        key_text, value_text = stripped.split("=", 1)
        path = _split_key(key_text, lineno)
        value = _parse_value(value_text, lineno)
        node = table
        for part in path[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise TomlError(f"ключ {part!r} уже занят значением", lineno)
        node[path[-1]] = value
    return data


def dumps(data: Dict[str, Any]) -> str:
    lines: List[str] = []

    def fmt(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, list):
            return "[" + ", ".join(fmt(item) for item in value) + "]"
        text = str(value)
        escaped = (
            text.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\t", "\\t")
            .replace("\r", "\\r")
        )
        return f'"{escaped}"'

    def emit(table: Dict[str, Any], prefix: List[str]) -> None:
        scalars = {k: v for k, v in table.items() if not isinstance(v, dict)}
        tables = {k: v for k, v in table.items() if isinstance(v, dict)}
        for key, value in scalars.items():
            lines.append(f"{key} = {fmt(value)}")
        for key, value in tables.items():
            path = prefix + [key]
            header = ".".join(path)
            if lines:
                lines.append("")
            lines.append(f"[{header}]")
            emit(value, path)

    emit(data, [])
    return "\n".join(lines).rstrip() + "\n"


def load(path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return loads(handle.read())
