#!/usr/bin/env python3
"""Algorithm 1 编排器: Taint 引导的迭代 EXP 精炼闭环

对应 algorithm/Algorithm_1.py。需在 WSL/Linux 运行(RunVerify 依赖 pwntools)。

用法:
    python3 refine.py <binary> [addr] [--rounds N] [--theta 0.95] [--json-out f]
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ui

from analyze import LargeStaticError, round_zero
from analysis.resolver import format_materials, resolve
from llm.client import LLMClient, LLMError
from llm.config import LLMConfigError, load_config
from llm.parser import parse_analysis, parse_report
from llm.prompt import (build_analyze_messages, build_explain_messages,
                        build_regenerate_messages, format_feedback)
from verify_exp import run_verify

def _dump(report) -> dict:
    if dataclasses.is_dataclass(report):
        return dataclasses.asdict(report)
    return report

def _get_path(obj, path: str):
    cur = obj
    for part in path.split("."):
        if cur is None:
            return None
        cur = cur.get(part) if isinstance(cur, dict) else getattr(cur, part, None)
    return cur

def _set_path(obj, path: str, val) -> None:
    parts = path.split(".")
    cur = obj
    for part in parts[:-1]:
        cur = cur.get(part) if isinstance(cur, dict) else getattr(cur, part, None)
        if cur is None:
            return
    last = parts[-1]
    if isinstance(cur, dict):
        cur[last] = val
    else:
        setattr(cur, last, val)

def enforce_locked(new_report, locked, prev_report):
    applied = []
    for path in locked or []:
        val = _get_path(prev_report, path)
        if val not in (None, "", [], {}):
            _set_path(new_report, path, val)
            applied.append(path)
    return new_report, applied

def llm_analyze(client, report, taint, feedback):
    messages = build_analyze_messages(report, taint, format_feedback(feedback))
    try:
        raw = client.chat(messages)
    except LLMError:
        return None
    return parse_analysis(raw)

def llm_regenerate(client, report, taint, analysis):
    messages = build_regenerate_messages(report, taint, analysis)
    try:
        raw = client.chat(messages)
    except LLMError:
        return None
    return parse_report(raw)

GAP_HINTS = {
    "addr_missing": "需补齐目标地址(plt/后门/gadget 目标)",
    "gadget_missing": "需补齐 ROP gadget(可换 ret2text/ret2libc)",
    "need_leak": "需先泄露(libc 基址或 PIE 基址)",
    "string_missing": "需确认 /bin/sh 等字符串地址",
    "offset_wrong": "需用静态实测偏移替换估算值",
    "payload_fix": "需修正 payload 拼装/打包逻辑",
    "stage_runtime": "需修正交互时序(recv/send/分隔符)",
    "misread": "需纠正对证据的误读",
    "libc_mismatch": "需提供与目标匹配的 libc(LD_PRELOAD)",
    "libc_missing": "需提供 libc 才能计算 system 地址",
}
_BLOCKER_KINDS = {"addr_missing", "gadget_missing", "need_leak",
                  "string_missing", "offset_wrong", "libc_mismatch", "libc_missing"}
_STAGE_SCORE = {"marker_ok": 1.0, "no_marker": 0.55, "segv": 0.5, "eof": 0.4,
                "timeout": 0.35, "payload_eval": 0.2, "spawn_fail": 0.1,
                "no_exp_code": 0.05}

def build_deliverable(J, I, F, A, status, history) -> dict:
    """构建可交付 EXP: 完度评分 + 缺口清单 + 最优 exp_code."""
    stage = getattr(F, "stage", "?") or "?"
    verified = bool(getattr(F, "ok", False))
    stage_s = _STAGE_SCORE.get(stage, 0.1)
    a_score = float(getattr(A, "score", 0.0) or 0.0) if A else 0.0
    score = round(stage_s if A is None else 0.5 * stage_s + 0.5 * a_score, 3)

    gaps: list = []
    seen: set = set()

    def add(kind, detail):
        if not kind or kind in seen:
            return
        seen.add(kind)
        gaps.append({
            "kind": kind,
            "severity": "blocker" if kind in _BLOCKER_KINDS else "warn",
            "detail": (detail or "").strip(),
            "hint": GAP_HINTS.get(kind, ""),
        })

    for p in (getattr(A, "problems", None) or []):
        add(str(getattr(p, "kind", "") or ""), getattr(p, "detail", ""))

    diag = getattr(F, "diagnosis", "") or ""
    if "未页对齐" in diag or "不一致" in diag:
        add("libc_mismatch",
            "运行时 libc 与题目目录 libc.so 不一致, 偏移不可套用: " + diag.splitlines()[-1])

    targets = getattr(I, "targets", []) or []
    names = {t.name for t in targets}
    libc = getattr(I, "libc", {}) or {}
    if "system" not in names and not libc and not verified:
        add("libc_missing", "二进制无 system@plt 且未找到同目录 libc, 无法计算 system 地址")

    # 归并: libc_mismatch 已覆盖 need_leak(泄漏成功但版本不符)
    _kinds = {g["kind"] for g in gaps}
    if "libc_mismatch" in _kinds and "need_leak" in _kinds:
        gaps = [g for g in gaps if g["kind"] != "need_leak"]
    # 过滤: detail 明示已修复的问题(描述上一轮失败、本轮已解决)
    _resolved = ("已改", "已修", "已成功", "已解决", "本轮已")
    gaps = [g for g in gaps
            if not (g["severity"] == "warn" and any(k in g["detail"] for k in _resolved))]

    exp = getattr(J, "exploit_plan", None)
    return {
        "score": score,
        "ready_to_use": verified,
        "status": status,
        "stage": stage,
        "confidence": float(getattr(J, "confidence", 0.0) or 0.0),
        "vulnerability_type": getattr(J, "vulnerability_type", "") or "",
        "vulnerable_function": getattr(J, "vulnerable_function", "") or "",
        "offset": getattr(exp, "offset", "") or "",
        "payload_layout": list(getattr(exp, "payload_layout", []) or []),
        "exp_code": getattr(exp, "exp_code", "") or "",
        "gaps": gaps,
        "rounds_used": len(history),
    }

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="refine",
        description="Algorithm 1: Taint 引导的迭代 EXP 精炼闭环",
    )
    ap.add_argument("binary")
    ap.add_argument("addr", nargs="?", default=None)
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--max-nodes", type=int, default=20)
    ap.add_argument("--rounds", type=int, default=3, help="N, 最大优化轮数")
    ap.add_argument("--theta", type=float, default=0.95, help="完成度收敛阈值")
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--flag", default=None)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--no-color", action="store_true", help="关闭彩色输出")
    args = ap.parse_args(argv)
    ui.init_color(args.no_color)

    try:
        config = load_config()
    except LLMConfigError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1

    try:
        J, I, nodes, prog, graph, root = round_zero(
            args.binary, args.addr, args.depth, args.max_nodes, config)
    except LargeStaticError as exc:
        print(f"[跳过] {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[错误] RoundZero 失败: {exc}", file=sys.stderr)
        return 1

    ui.render_banner(args.binary, args.rounds, args.theta)
    ui.render_round_zero(J, I, nodes, root)
    T = [I.to_prompt_text()]
    F = run_verify(args.binary, J, flag=args.flag, timeout=args.timeout)
    client = LLMClient(config)
    H: list = []
    history: list = []
    Pprev = None
    status = "MAX_ROUNDS"
    A = None

    def _finish(st, k, A=None, hit=0, total=0, locked=None):
        history.append(ui.record(k, F, A, hit, total, locked))
        return st

    for k in range(1, args.rounds + 1):
        ui.render_round(k, args.rounds, args.theta)
        ui.render_feedback(F)
        ui.render_diagnosis(J, I)
        if F.ok:
            status = _finish("PASS", k)
            break
        ui.step("LLMAnalyze", "把验证证据翻译为结构化问题清单")
        A = llm_analyze(client, J, T, F)
        if A is None:
            status = _finish("LLM_FAILED", k)
            break
        ui.render_analysis(A, args.theta)
        if A.actually_passed:
            status = _finish("PASS_SUSPECT", k, A, 0, 0, A.locked)
            break
        if A.score >= args.theta:
            status = _finish("CONVERGED", k, A, 0, 0, A.locked)
            break
        if not A.problems:
            status = _finish("NO_PROBLEM", k, A, 0, 0, A.locked)
            break
        if Pprev is not None and A.problems == Pprev:
            status = _finish("STALLED", k, A, 0, 0, A.locked)
            break
        Pprev = A.problems
        ui.step("Resolve", "按问题 kind 反查静态语料 (只读)")
        R = resolve(A.problems, I, prog, feedback=F)
        M = [m for m in R if m.material]
        ui.render_materials(R, M)
        if not M:
            status = _finish("UNRESOLVABLE", k, A, 0, len(R), A.locked)
            break
        T = T + [format_materials(M)]
        ui.step("LLMRegenerate", f"注入 {len(M)} 项反查材料, 重出 EXP")
        Jnew = llm_regenerate(client, J, T, A)
        if Jnew is None:
            status = _finish("LLM_FAILED", k, A, len(M), len(R), A.locked)
            break
        J, applied = enforce_locked(Jnew, A.locked, J)
        ui.render_solving(A, J, applied)
        history.append(ui.record(k, F, A, len(M), len(R), applied))
        H.append(F.fingerprint)
        F = run_verify(args.binary, J, flag=args.flag, timeout=args.timeout)

    ui.render_final(status, J, F, H, args.rounds, history)
    deliverable = build_deliverable(J, I, F, A, status, history)
    try:
        raw = client.chat(build_explain_messages(deliverable, I.to_prompt_text()))
        obj = json.loads(raw)
        deliverable["rationale"] = obj.get("rationale", "")
        deliverable["manual_steps"] = [str(s) for s in (obj.get("manual_steps") or [])]
        deliverable["env_note"] = obj.get("env_note", "")
    except Exception:
        pass
    ui.render_deliverable(deliverable)

    if args.json_out:
        out_path = args.json_out
        if os.path.dirname(out_path) == "":
            base = os.path.dirname(os.path.abspath(__file__))
            out_dir = os.path.join(base, "reports")
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, out_path)
        with open(out_path, "w", encoding="utf-8") as f:
            data = _dump(J)
            data["_deliverable"] = deliverable
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[+] 最终报告+可交付EXP 已写入 {out_path}")

    return 0 if status in ("PASS", "PASS_SUSPECT") else 1

if __name__ == "__main__":
    sys.exit(main())