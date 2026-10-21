"""Markdown for the show-one tools (`response_format='markdown'` of fmc_get_file_policy & co.).

Core's object_result renders an object as `- **key**: value` lines, and its cells collapse a list of
dicts to the items' names and a dict without a name to compact JSON: a file policy's rules, an intrusion
policy's overrides or each device's version vanish from the default answer. `object_reply` keeps the
JSON answer as it is and renders the markdown with `object_markdown`: scalars and short lists as
bullets, nested objects as indented bullets, and every list of records (dicts that are more than an
{id, name, type} reference) as its own table under a heading, with all of its fields.
TODO(core): drop this once core's kv_markdown renders nested rows (CORE-REQUESTS.md, 2026-10-20).
"""

import re
from typing import Any

from fastmcp.tools import ToolResult

from fmc_mcp._core import ResponseFormat, object_result
from fmc_mcp._core.formatting import compact, mask_secrets, max_chars, text_result

# The keys of a bare FMC reference: shown by its name, like core does.
REF_KEYS = frozenset({"id", "name", "type", "uuid", "label", "display"})
INLINE_MAX = 120  # longer lists and objects get a line per item
ROW_CAPS = (
    200,
    100,
    50,
    20,
    10,
)  # rows kept per table, tried in turn while the answer is over the size limit
MORE = "use response_format='json' or narrow the query"


def is_ref(v: Any) -> bool:
    return isinstance(v, dict) and bool(v) and set(v) <= REF_KEYS


def is_rows(v: Any) -> bool:
    """A list holding records (dicts that are more than references): rendered as a table."""
    return isinstance(v, list) and any(isinstance(x, dict) and not is_ref(x) for x in v)


def _ref_label(v: dict[str, Any]) -> str:
    return str(v.get("name") or v.get("label") or v.get("display") or v.get("id") or v.get("uuid"))


def inline(v: Any, *, nested: bool = False) -> str:
    """A value on one line: references by name, objects as `k: v` pairs, lists joined."""
    if isinstance(v, dict):
        if is_ref(v):
            return _ref_label(v)
        text = ", ".join(f"{k}: {inline(x, nested=True)}" for k, x in v.items())
        return "{" + text + "}" if nested else text
    if isinstance(v, list):
        sep = "; " if any(isinstance(x, dict | list) and not is_ref(x) for x in v) else ", "
        return sep.join(inline(x, nested=True) for x in v)
    return str(v)


def _line(v: Any) -> str:
    return inline(v).replace("\r\n", " ").replace("\r", " ").replace("\n", " ")


def _cell(v: Any) -> str:
    return _line(v).replace("|", "\\|")


def table(rows: list[Any], cap: int | None = None) -> str:
    """A markdown table of records; the columns are every key any row has, in first-seen order. With
    `cap`, only the first `cap` rows, and a line saying so."""
    recs = [r if isinstance(r, dict) else {"value": r} for r in rows]
    cols: list[str] = []
    for r in recs:
        cols += [k for k in r if k not in cols]
    shown = recs if cap is None else recs[:cap]
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join(_cell(r[c]) if c in r else "" for c in cols) + " |" for r in shown]
    if len(shown) < len(recs):
        lines.append(f"\n_Showing {len(shown)} of {len(recs)} rows; {MORE}._")
    return "\n".join(lines)


def fenced(text: str, cap: int | None = None) -> str:
    """A code block whose fence is longer than any backtick run in the text; with `cap`, its first
    `cap` lines."""
    lines = text.splitlines()
    body = "\n".join(lines if cap is None else lines[:cap])
    runs = [len(m) for m in re.findall(r"`+", body)]
    fence = "`" * max(3, max(runs, default=0) + 1)
    out = f"{fence}\n{body}\n{fence}"
    if cap is not None and len(lines) > cap:
        out += f"\n\n_Showing {cap} of {len(lines)} lines; {MORE}._"
    return out


def _flat(v: dict[str, Any]) -> bool:
    """An object short and shallow enough for one bullet."""
    shallow = all(is_ref(x) or not isinstance(x, dict) and not is_rows(x) for x in v.values())
    return shallow and len(inline(v)) <= INLINE_MAX


def _one_per_line(v: list[Any]) -> bool:
    """Long lists, and lists of sentences (notes) whose items have commas of their own."""
    return len(inline(v)) > INLINE_MAX or any(isinstance(x, str) and ("," in x or ";" in x) for x in v)


def _walk(
    obj: dict[str, Any], path: str, depth: int, lines: list[str], sections: list[str], cap: int | None
) -> None:
    pad = "  " * depth
    for k, v in obj.items():
        key = f"{path}{k}"
        if is_rows(v):
            sections.append(f"### {key} ({len(v)})\n\n{table(v, cap)}")
        elif isinstance(v, str) and ("\n" in v.strip() or "\r" in v.strip()):
            sections.append(f"### {key}\n\n{fenced(v.strip(), cap)}")
        elif isinstance(v, dict) and v and not is_ref(v) and not _flat(v):
            lines.append(f"{pad}- **{k}**:")
            _walk(v, f"{key}.", depth + 1, lines, sections, cap)
        elif isinstance(v, list) and _one_per_line(v):
            lines.append(f"{pad}- **{k}**:")
            lines += [f"{pad}  - {_line(x)}" for x in v]
        else:
            lines.append(f"{pad}- **{k}**: {_line(v)}")


def object_markdown(obj: dict[str, Any], cap: int | None = None) -> str:
    """One object as markdown: bullets first, then a table per list of records (and fenced blocks for
    multi-line text such as a PEM or a CSV), each under a heading naming its key path. `cap` limits
    each table's rows (and each block's lines)."""
    lines: list[str] = []
    sections: list[str] = []
    _walk(obj, "", 0, lines, sections, cap)
    parts = (["\n".join(lines)] if lines else []) + sections
    return "\n\n".join(parts) or "_Empty._"


def fitted_markdown(obj: dict[str, Any]) -> str:
    """object_markdown within the response size limit: when the whole answer is too long, every table
    keeps fewer rows (200, 100, ... 10) so that the sections after a long table still show."""
    text = object_markdown(obj)
    for cap in ROW_CAPS:
        if len(text) <= max_chars():
            break
        text = object_markdown(obj, cap)
    return text


def object_reply(obj: Any, *, fmt: ResponseFormat = "json", shape: bool = True) -> ToolResult:
    """Core's object_result, with markdown that keeps nested rows (object_markdown)."""
    if fmt != "markdown" or not isinstance(obj, dict):
        return object_result(obj, fmt=fmt, shape=shape)
    data = compact(obj) if shape else mask_secrets(obj)  # markdown never shows a secret
    if not isinstance(data, dict):
        return object_result(obj, fmt=fmt, shape=shape)
    return text_result(fitted_markdown(data))
