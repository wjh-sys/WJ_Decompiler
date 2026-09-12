from __future__ import annotations

import ast
import json
import re

from .schema import (PROBLEM_KINDS, VULN_TYPES, DangerPoint, ExploitPlan,
                     FailureAnalysis, Problem, VulnDetails, VulnReport)

def parse_report(raw: str) -> VulnReport:
    obj = _try_load(raw)
    if obj is None:
        return VulnReport(raw=raw, summary=raw[:500] or "(空响应)")
    return _normalize(obj, raw)

def _try_load(raw: str):
    candidates = []
    m = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
    if m:
        candidates.append(m.group(1))
    candidates.append(raw)
    for c in candidates:
        for loader in (json.loads, _py_literal_load):
            try:
                obj = loader(c)
                if isinstance(obj, dict):
                    return obj
            except Exception:
                continue
    return None

def _py_literal_load(text: str):
    # 宽松解析:兼容模型把 payload_layout 写成 ["A"*112, p32(...)] 等
    # 非严格 JSON 的 Python 风格字面量(先剥离行注释与尾部逗号)。
    lines = []
    for ln in text.splitlines():
        lines.append(re.sub(r"\s*//.*$", "", ln))
    cleaned = "\n".join(lines)
    return ast.literal_eval(cleaned)

def _normalize(obj: dict, raw: str) -> VulnReport:
    r = VulnReport(raw=raw)
    r.entry_function = _as_str(obj.get("entry_function"))
    r.involved_functions = _as_str_list(obj.get("involved_functions"))
    r.vulnerable_function = _as_str(obj.get("vulnerable_function"))
    r.call_chain = _as_str_list(obj.get("call_chain"))
    r.vulnerability_type = _as_type(obj.get("vulnerability_type"))
    r.confidence = _as_float(obj.get("confidence"))
    r.summary = _as_str(obj.get("summary"))
    r.exploitation = _as_str(obj.get("exploitation"))
    r.false_positive_reason = _as_str(obj.get("false_positive_reason"))
    for dp in obj.get("danger_points") or []:
        if isinstance(dp, dict):
            r.danger_points.append(DangerPoint(
                addr=_as_str(dp.get("addr")),
                call=_as_str(dp.get("call")),
                args=_as_str(dp.get("args")),
                note=_as_str(dp.get("note")),
            ))
    det = obj.get("details")
    if isinstance(det, dict):
        r.details = VulnDetails(
            buffer_size=_as_int(det.get("buffer_size")),
            overflow_length=_as_str(det.get("overflow_length")),
            overwritten_target=_as_str(det.get("overwritten_target")),
            protection=_as_str_list(det.get("protection")),
        )
    ep = obj.get("exploit_plan")
    if isinstance(ep, dict):
        r.exploit_plan = ExploitPlan(
            offset=_as_str(ep.get("offset")),
            payload_layout=_as_str_list(ep.get("payload_layout")),
            exp_code=_as_str(ep.get("exp_code")),
            verification=_as_str(ep.get("verification")),
        )
    return r

def _as_str(v) -> str:
    return str(v) if v is not None else ""

def _as_str_list(v) -> list:
    if isinstance(v, list):
        return [str(x) for x in v if x is not None]
    return []

def _as_float(v) -> float:
    try:
        return max(0.0, min(1.0, float(v)))
    except (TypeError, ValueError):
        return 0.0

def _as_int(v):
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None

def _as_type(v) -> str:
    s = _as_str(v).strip().lower()
    return s if s in VULN_TYPES else "none"

def _as_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "1", "yes", "y")

def parse_analysis(raw: str) -> FailureAnalysis:
    obj = _try_load(raw)
    if obj is None:
        return FailureAnalysis(reasoning=raw[:500] or "(空响应)")
    a = FailureAnalysis()
    a.score = _as_float(obj.get("score"))
    a.actually_passed = _as_bool(obj.get("actually_passed"))
    for p in obj.get("problems") or []:
        if isinstance(p, dict):
            a.problems.append(Problem(
                kind=_as_str(p.get("kind")).strip(),
                detail=_as_str(p.get("detail")),
                target=_as_str(p.get("target")),
            ))
    a.locked = _as_str_list(obj.get("locked"))
    a.reasoning = _as_str(obj.get("reasoning"))
    return a
