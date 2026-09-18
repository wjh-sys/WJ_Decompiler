#!/usr/bin/env python3
"""WJ 反编译器 - LLM 辅助漏洞分析与 EXP 精炼统一入口

本文件是项目唯一入口, 内含三段职责(以分节注释分隔):
  1. 基础设施    : round_zero / 反编译 + 调用图 + Taint 静态分析
  2. Algorithm 2 : EXP 完成度评分与收敛策略 (score_exp)
  3. Algorithm 1 : Taint 引导的迭代 EXP 精炼闭环 (refine)

用法:
    python analyze.py <binary> [addr] [--depth N] [--max-nodes N] [--json-out f]
        -> 单轮 LLM 漏洞分析(默认; Windows 亦可运行)

    python analyze.py <binary> --refine [--rounds N] [--theta t] [--flag f]
                      [--timeout s] [--json-out f]
        -> 迭代 EXP 精炼闭环(需在 WSL/Linux 运行, RunVerify 依赖 pwntools)
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ui

from analysis import CallGraph, analyze as taint_analyze, is_large_static
from analysis.listtable import ListTable
from analysis.resolver import format_materials, resolve
from analysis.techniques import (eval_routes, infer_route, rank_routes,
                                 scoring_routes)
from disasm import Disassembler
from llm.client import LLMClient, LLMError
from llm.config import LLMConfigError, load_config
from llm.parser import parse_analysis, parse_report
from llm.prompt import (build_analyze_messages, build_explain_messages,
                        build_graph_text, build_messages, build_prog_info,
                        build_regenerate_messages, format_feedback)
from loader import guess_loader

# verify_exp 在函数内按需 import pwntools(仅 RunVerify 时), 故此处顶部导入
# 不影响 Windows 下的单轮分析
from verify_exp import run_verify

def _find_root(prog, dis, addr: str | None) -> int:
    if addr is not None:
        return int(addr, 0)
    for s in prog.symbols:
        if s.name == "main" and s.addr:
            return s.addr
    # strip 二进制: 从 _start 反汇编找 mov rdi, imm(传给 __libc_start_main)
    try:
        entry = prog.entry
        cs = prog.find_section(entry)
        if cs is not None:
            code = cs.data[entry - cs.addr: entry - cs.addr + 0x100]
            for ins in dis.decode(code, entry):
                m, ops = ins.mnemonic, ins.op_str
                if m == "mov" and ops.startswith("rdi,"):
                    try:
                        return int(ops[4:].strip(), 0)
                    except ValueError:
                        pass
                if m == "call":
                    break
    except Exception:
        pass
    return prog.entry

def _print_report(report) -> None:
    line = "=" * 60
    print("\n" + line)
    print("漏洞分析报告")
    print(line)
    print(f"漏洞类型   : {report.vulnerability_type}")
    print(f"确信度     : {report.confidence:.2f}")
    print(f"入口函数   : {report.entry_function or 'N/A'}")
    print(f"涉及函数   : {', '.join(report.involved_functions) if report.involved_functions else 'N/A'}")
    print(f"漏洞函数   : {report.vulnerable_function or 'N/A'}")
    print(f"调用链     : {' -> '.join(report.call_chain) if report.call_chain else 'N/A'}")
    print(f"概述       : {report.summary}")
    for i, dp in enumerate(report.danger_points, 1):
        loc = f"{dp.addr or '?'}  {dp.call}({dp.args})"
        print(f"危险点{i}    : {loc}  {dp.note}")
    det = report.details
    if det.buffer_size is not None or det.overflow_length or det.overwritten_target or det.protection:
        print("细节       :")
        if det.buffer_size is not None:
            print(f"            缓冲区大小: {det.buffer_size}")
        if det.overflow_length:
            print(f"            溢出长度  : {det.overflow_length}")
        if det.overwritten_target:
            print(f"            覆盖目标  : {det.overwritten_target}")
        if det.protection:
            print(f"            防护      : {', '.join(det.protection)}")
    print(f"利用思路   : {report.exploitation or 'N/A'}")
    print(f"误报说明   : {report.false_positive_reason or 'N/A'}")
    ep = report.exploit_plan
    if ep.offset or ep.exp_code:
        print("\nEXP 方案:")
        if ep.offset:
            print(f"  溢出偏移  : {ep.offset}")
        if ep.payload_layout:
            print(f"  payload   : {ep.payload_layout}")
        if ep.exp_code:
            print("  exp_code  :")
            print(ep.exp_code)
        if ep.verification:
            print(f"  验证方式  : {ep.verification}")
    print(line)

class LargeStaticError(RuntimeError):
    pass

def round_zero(binary: str, addr: str | None, depth: int, max_nodes: int, config):
    """Algorithm 1 第 1 行: RoundZero(B) -> (J0, I). 单次完整流水线."""
    if not os.path.isfile(binary):
        raise FileNotFoundError(
            f"目标二进制不存在: {binary}\n"
            f"请检查路径(项目内题目多为多层嵌套目录, 例如 "
            f"test/user-mode/stackoverflow/ret2text/bamboofox-ret2text/ret2text)")
    prog = guess_loader(binary).load()
    dis = Disassembler(prog)
    if is_large_static(prog, binary):
        raise LargeStaticError(
            "该文件为全静态大体积二进制,当前工具链不支持"
            "(函数发现误报多、无 PLT 符号可识别 source),请换动态链接题目")
    graph = CallGraph(prog, dis)
    graph.build()
    root = _find_root(prog, dis, addr)
    nodes = graph.expand(root, max_depth=depth, max_nodes=max_nodes)
    if not nodes:
        raise RuntimeError(f"根函数 0x{root:x} 展开结果为空，无法分析")
    print(f"[*] 根函数 0x{root:x}，展开 {len(nodes)} 个函数"
          f"（深度≤{depth}，节点≤{max_nodes}），正在请求模型分析...")
    ev = taint_analyze(prog, graph, binary)
    messages = build_messages(
        build_prog_info(prog),
        build_graph_text(graph, nodes),
        nodes,
        evidence_text=ev.to_prompt_text(),
    )
    client = LLMClient(config)
    raw = client.chat(messages)
    report = parse_report(raw)
    return report, ev, nodes, prog, graph, root

# =============================================================================
# Algorithm 2: EXP 完成度评分与收敛策略
#
# 信度分层(高 -> 低):
#   run    运行时证据  STAGE_SCORE[F.stage]              真机可复现, 信度最高
#   static 静态结构化  offset 命中 + 路线成立 + 无阻塞项
#   llm    语义评分    A.score 经置信度折扣 + EMA 平滑
#   cov    工具覆盖    A.problems 经 ListTable 反查命中率
#
# 四条不变量:
#   1) PASS 短路    : F.ok 直接满分, 不参与加权折中(真打通不被主观分拉低)
#   2) 非 PASS 不越阈: 权重设计使 F.ok=False 时 raw <= 0.82 < THETA_PASS
#   3) 单调包络     : Score_k = max(Score_{k-1}, raw_k), 跨轮只升不降, 保证可比
#   4) 双阈值滞回   : 收敛需连续 HOLD_ROUNDS 轮 raw >= THETA_HOLD, 抑制抖动
# =============================================================================
STAGE_SCORE = {
    "marker_ok": 1.0, "no_marker": 0.55, "segv": 0.5, "eof": 0.4,
    "timeout": 0.35, "payload_eval": 0.2, "spawn_fail": 0.1, "no_exp_code": 0.05,
}

WEIGHTS = {"run": 0.40, "static": 0.30, "llm": 0.15, "cov": 0.15}
STATIC_W = {"offset": 0.5, "route": 0.3, "blocker": 0.2}

BLOCKER_KINDS = {"addr_missing", "gadget_missing", "need_leak", "string_missing",
                 "offset_wrong", "libc_mismatch", "libc_missing"}

THETA_PASS = 0.95
THETA_HOLD = 0.85
EPS = 0.02
HOLD_ROUNDS = 2

VERDICT_PASS = "PASS"
VERDICT_CONVERGED = "CONVERGED"
VERDICT_REGRESSION = "REGRESSION"
VERDICT_STALLED = "STALLED"
VERDICT_CONTINUE = "CONTINUE"

@dataclass
class ScoreRecord:
    score: float = 0.0
    raw: float = 0.0
    delta: float = 0.0
    verdict: str = VERDICT_CONTINUE
    breakdown: dict = field(default_factory=dict)
    route_ok: bool = False
    route_used: list = field(default_factory=list)
    routes_available: list = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        return {"score": self.score, "raw": self.raw, "delta": self.delta,
                "verdict": self.verdict, "breakdown": self.breakdown,
                "route_ok": self.route_ok, "route_used": self.route_used,
                "routes_available": self.routes_available, "note": self.note}

def _int0(v):
    try:
        return int(str(v), 0)
    except (TypeError, ValueError):
        return None

def _clamp(x, lo, hi):
    return max(lo, min(hi, float(x)))

def _weighted(parts) -> float:
    """按权重归一化: parts = [(w, v), ...], 空则 0.

    用于子维度裁剪后的重新归一化, 使"不适用"的维度不被当作 0 分参与平均.
    """
    tot = sum(w for w, _ in parts)
    if tot <= 0:
        return 0.0
    return sum(w * v for w, v in parts) / tot

def _plan(J):
    return getattr(J, "exploit_plan", None)

def _exp_code(J) -> str:
    """取 EXP 代码文本; 空串表示本轮未产出有效产物."""
    return (getattr(_plan(J), "exp_code", "") or "").strip()

def _cited(v) -> bool:
    """判断是否为有据可依的引用: 非空且长度足够, 排除无/占位类回复."""
    s = str(v or "").strip()
    if len(s) < 6:
        return False
    return s.lower() not in ("none", "null", "n/a", "no evidence", "无证据", "无")

def _cited_problems(A) -> list:
    """只保留引用了证据的问题: 未被证据支撑的主张不加权(正负双向对称)."""
    return [p for p in (getattr(A, "problems", None) or [])
            if _cited(getattr(p, "evidence", ""))]

def _blob(J):
    p = _plan(J)
    return ((getattr(p, "exp_code", "") or "") + " " +
            " ".join(getattr(p, "payload_layout", []) or []))

def _measured_offset(I, case):
    if case and case.get("offset") is not None:
        return _int0(case["offset"])
    for o in getattr(I, "overflow", []) or []:
        return o.offset_to_ret
    return None

def _s_offset(J, I, case):
    """偏移子分: 静态证据无法测出偏移时返回 None(不适用), 而非 0(误罚).

    返回 None 表示该维度不可判定, 调用方应将其移出加权而非计 0 分:
    否则工具的识别盲区会被记到 EXP 的账上.
    """
    want = _measured_offset(I, case)
    if want is None:
        return None
    got = _int0(getattr(_plan(J), "offset", ""))
    if got is None:
        return 0.0
    return 1.0 if got == want else 0.0

def _s_blocker(A):
    problems = _cited_problems(A)
    if not problems:
        return 1.0
    kinds = [str(getattr(p, "kind", "") or "") for p in problems]
    blockers = sum(1 for k in kinds if k in BLOCKER_KINDS)
    return 1.0 - blockers / len(kinds)

def _s_llm(A, J, prev_llm):
    # 证据门控: 未引用任何证据的主观评分不计分(抗无据给分).
    if not _cited(getattr(A, "evidence", "")):
        return 0.0
    conf = _clamp(getattr(J, "confidence", 0.0) or 0.0, 0.3, 1.0)
    now = _clamp(getattr(A, "score", 0.0) or 0.0, 0.0, 1.0) * conf
    if prev_llm <= 0.0:
        return now
    return 0.5 * now + 0.5 * prev_llm

def _s_cov(A, table):
    problems = _cited_problems(A)
    if not problems:
        return 1.0
    total = 0.0
    for p in problems:
        total += table.lookup(str(getattr(p, "kind", "") or ""),
                              str(getattr(p, "target", "") or "")).score
    return total / len(problems)

def _recent(vals, n):
    return vals[-n:] if len(vals) >= n else vals

def _envelope(rec, history, theta_pass=THETA_PASS, theta_hold=THETA_HOLD):
    prev = history[-1] if history else None
    rec.delta = round(rec.raw - (prev.raw if prev else rec.raw), 4)
    rec.score = round(max((prev.score if prev else 0.0), rec.raw), 4)
    if rec.verdict == VERDICT_PASS:
        return rec
    raws = [r.raw for r in history] + [rec.raw]
    if rec.score >= theta_pass and len(raws) >= HOLD_ROUNDS \
            and all(v >= theta_hold for v in _recent(raws, HOLD_ROUNDS)):
        rec.verdict = VERDICT_CONVERGED
        rec.note = (f"包络 {rec.score:.3f} 达阈值, 且连续 {HOLD_ROUNDS} 轮 "
                    f"当轮值 >= {theta_hold}(抗抖动)")
        return rec
    deltas = [r.delta for r in history[1:]] + [rec.delta]
    if len(deltas) >= HOLD_ROUNDS and all(abs(d) < EPS for d in _recent(deltas, HOLD_ROUNDS)):
        rec.verdict = VERDICT_STALLED
        rec.note = f"连续 {HOLD_ROUNDS} 轮增量 < {EPS}, 已停滞, 继续空转无益"
    elif rec.delta < -EPS:
        rec.verdict = VERDICT_REGRESSION
        rec.note = f"当轮值较上轮下降 {rec.delta:.3f}(单调包络已兜住, 仅诊断)"
    return rec

def score_exp(J, I, F, A, table=None, case=None, history=None,
              llm_fresh=True, cfg=None) -> ScoreRecord:
    """计算 EXP 完成度.

    J/I/F/A: 漏洞报告(EXP)/静态证据/运行验证反馈/LLM 归因结果.
    llm_fresh=False 表示 A 与当前 J 不同源(如 regenerate 之后), llm 维度不计分.
    """
    history = list(history or [])
    weights = {**WEIGHTS, **((cfg or {}).get("weights") or {})}
    theta_pass = (cfg or {}).get("theta_pass", THETA_PASS)
    theta_hold = (cfg or {}).get("theta_hold", THETA_HOLD)

    # 路线信息在 PASS 短路前先算出: 终局满分不应丢失"实际走了哪条路线"这一交付信息
    table = table or ListTable.from_evidence(I)
    routes = eval_routes(table)
    scored = rank_routes(scoring_routes(routes))
    avail_r = [r for r in scored if r.status == "AVAILABLE"]
    avail = [r.name for r in avail_r]
    partial = [r.name for r in scored if r.status == "PARTIAL"]
    preferred = avail[0] if avail else ""
    used = infer_route(_blob(J), routes)
    route_ok = bool(used and (set(used) & set(avail)))

    if bool(getattr(F, "ok", False)):
        rec = ScoreRecord(
            1.0, 1.0, 0.0, VERDICT_PASS,
            {"run": 1.0, "static": 1.0, "llm": 1.0, "cov": 1.0,
             "stage": getattr(F, "stage", "?"),
             "excluded": [], "preferred": preferred,
             "sub": {"offset": 1.0, "route": 1.0, "blocker": 1.0}},
            route_ok=route_ok, route_used=used, routes_available=avail,
            note="已验证打通, 终局满分(优先级 0, 短路一切加权维度)")
        return _envelope(rec, history, theta_pass, theta_hold)

    fresh = bool(llm_fresh and A is not None)

    stage = getattr(F, "stage", "?") or "?"
    s_run = STAGE_SCORE.get(stage, 0.1)
    s_off = _s_offset(J, I, case)
    s_route = 1.0 if route_ok else (0.5 if avail else 0.3)
    s_blocker = _s_blocker(A) if fresh else 0.0

    # 可测性门控: 只对可判定的子维度计分, 其余移出并在剩余维度内重新归一化.
    # offset 不可测(如手工循环读导致溢出点识别不到)时, 路线可行性同不可判定
    # (13 条路线中 12 条 requires 含 offset:*), 故一并移出, 避免双重惩罚.
    parts, excluded = [], []
    if s_off is None:
        excluded += ["offset", "route"]
    else:
        parts += [(STATIC_W["offset"], s_off), (STATIC_W["route"], s_route)]
    if fresh:
        parts.append((STATIC_W["blocker"], s_blocker))
    else:
        excluded.append("blocker")
    s_static = _weighted(parts)
    prev_llm = history[-1].breakdown.get("llm", 0.0) if history else 0.0
    s_llm = _s_llm(A, J, prev_llm) if fresh else 0.0
    s_cov = _s_cov(A, table) if fresh else 0.0

    raw = (weights["run"] * s_run + weights["static"] * s_static
           + weights["llm"] * s_llm + weights["cov"] * s_cov)
    rec = ScoreRecord(
        0.0, round(raw, 4), 0.0, VERDICT_CONTINUE,
        {"run": round(s_run, 3), "static": round(s_static, 3),
         "llm": round(s_llm, 3), "cov": round(s_cov, 3), "stage": stage,
         "excluded": excluded, "preferred": preferred,
         "sub": {"offset": None if s_off is None else round(s_off, 3),
                 "route": round(s_route, 3),
                 "blocker": round(s_blocker, 3)}},
        route_ok=route_ok, route_used=used, routes_available=avail)
    if partial:
        rec.note = f"部分可用(缺前置, 不计入可用方向): {', '.join(partial)}"
    rec = _envelope(rec, history, theta_pass, theta_hold)
    if not fresh:
        rec.note = "本轮无与当前 J 同源的 LLM 归因, llm/cov 维度不计分"
    return rec

# =============================================================================
# Algorithm 1: Taint 引导的迭代 EXP 精炼闭环
#
# 流程: RoundZero(J0,I) -> RunVerify -> LLMAnalyze 归因 -> Resolve 反查静态语料
#       补全 T -> LLMRegenerate 重出报告 -> 下一轮
# 终止: PASS / PASS_SUSPECT / CONVERGED / NO_PROBLEM / STALLED /
#        UNRESOLVABLE / LLM_FAILED / MAX_ROUNDS
# =============================================================================
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

def build_deliverable(J, I, F, A, status, history, score_hist=None,
                      llm_fresh=True) -> dict:
    """构建可交付 EXP: Algorithm 2 完成度 + 缺口清单 + 最优 exp_code."""
    stage = getattr(F, "stage", "?") or "?"
    verified = bool(getattr(F, "ok", False))
    rec = score_exp(J, I, F, A, history=score_hist, llm_fresh=llm_fresh)
    score = rec.score
    used = rec.route_used
    avail = rec.routes_available
    route_ok = rec.route_ok

    gaps: list = []
    seen: set = set()

    def add(kind, detail):
        if not kind or kind in seen:
            return
        seen.add(kind)
        gaps.append({
            "kind": kind,
            "severity": "blocker" if kind in BLOCKER_KINDS else "warn",
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
        "route_used": used,
        "routes_available": avail,
        "route_ok": route_ok,
        "score_raw": rec.raw,
        "score_delta": rec.delta,
        "verdict": rec.verdict,
        "score_breakdown": rec.breakdown,
        "score_note": rec.note,
    }

def refine(binary: str, addr: str | None, depth: int, max_nodes: int, config,
           rounds: int, theta: float, flag: str | None, timeout: float,
           json_out: str | None) -> int:
    """执行 Algorithm 1 迭代精炼闭环, 返回进程退出码(0 = 已打通)."""
    try:
        J, I, nodes, prog, graph, root = round_zero(
            binary, addr, depth, max_nodes, config)
    except LargeStaticError as exc:
        print(f"[跳过] {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[错误] RoundZero 失败: {exc}", file=sys.stderr)
        return 1

    ui.render_banner(binary, rounds, theta)
    ui.render_round_zero(J, I, nodes, root)
    # 注入真实二进制路径: 否则模型习惯性使用占位名 './pwn', 每个 EXP 都需人工替换
    T = [I.to_prompt_text(),
         f"[目标二进制] 生成 EXP 时 process() 必须使用 {binary!r} "
         f"(或相对名 {os.path.basename(binary)!r}); "
         f"禁止使用 './pwn' 等占位名"]
    F = run_verify(binary, J, flag=flag, timeout=timeout)
    client = LLMClient(config)
    H: list = []
    history: list = []
    score_hist: list = []
    Pprev = None
    status = "MAX_ROUNDS"
    A = None
    A_fresh = False
    # 交付物单调性: J 每轮会被 regenerate 覆盖, 而分数有单调包络保护 —— 二者不对称
    # 会导致"分数记住峰值、交付的却是更差的 EXP"(甚至空 EXP). 故按验证阶段
    # 保留历史最优产物, 末尾以它构建 deliverable.
    best = {"rank": STAGE_SCORE.get(getattr(F, "stage", "?") or "?", 0.1),
            "J": J, "F": F, "k": 0}

    def _finish(st, k, rec, hit=0, total=0, locked=None):
        history.append(ui.record(k, F, A, hit, total, locked,
                                 score=rec.score if rec else 0.0))
        return st

    for k in range(1, rounds + 1):
        ui.render_round(k, rounds, theta)
        ui.render_feedback(F)
        ui.render_diagnosis(J, I)
        if F.ok:
            rec = score_exp(J, I, F, A, history=score_hist, llm_fresh=False)
            score_hist.append(rec)
            status = _finish("PASS", k, rec)
            break
        ui.step("LLMAnalyze", "把验证证据翻译为结构化问题清单")
        A = llm_analyze(client, J, T, F)
        A_fresh = A is not None
        if A is None:
            rec = score_exp(J, I, F, None, history=score_hist, llm_fresh=False)
            score_hist.append(rec)
            status = _finish("LLM_FAILED", k, rec)
            break
        rec = score_exp(J, I, F, A, history=score_hist, llm_fresh=True)
        score_hist.append(rec)
        ui.render_analysis(A, theta, score=rec.score)
        if A.actually_passed:
            status = _finish("PASS_SUSPECT", k, rec, 0, 0, A.locked)
            break
        if rec.verdict == VERDICT_CONVERGED:
            status = _finish("CONVERGED", k, rec, 0, 0, A.locked)
            break
        if not A.problems:
            status = _finish("NO_PROBLEM", k, rec, 0, 0, A.locked)
            break
        if rec.verdict == VERDICT_STALLED or (Pprev is not None and A.problems == Pprev):
            status = _finish("STALLED", k, rec, 0, 0, A.locked)
            break
        Pprev = A.problems
        ui.step("Resolve", "按问题 kind 反查静态语料 (只读)")
        R = resolve(A.problems, I, prog, feedback=F)
        M = [m for m in R if m.material]
        ui.render_materials(R, M)
        if not M:
            status = _finish("UNRESOLVABLE", k, rec, 0, len(R), A.locked)
            break
        T = T + [format_materials(M)]
        ui.step("LLMRegenerate", f"注入 {len(M)} 项反查材料, 重出 EXP")
        Jnew = llm_regenerate(client, J, T, A)
        if Jnew is None:
            status = _finish("LLM_FAILED", k, rec, len(M), len(R), A.locked)
            break
        if not _exp_code(Jnew):
            # 空 EXP 属无效产物: 不得用它覆盖已有 J, 保留历史最优并终止
            print("[!] 本轮重出结果不含 exp_code, 保留历史最优产物并终止",
                  file=sys.stderr)
            status = _finish("LLM_FAILED", k, rec, len(M), len(R), A.locked)
            break
        J, applied = enforce_locked(Jnew, A.locked, J)
        A_fresh = False
        ui.render_solving(A, J, applied)
        history.append(ui.record(k, F, A, len(M), len(R), applied,
                                 score=rec.score))
        H.append(F.fingerprint)
        F = run_verify(binary, J, flag=flag, timeout=timeout)
        rank = STAGE_SCORE.get(getattr(F, "stage", "?") or "?", 0.1)
        if rank >= best["rank"]:
            best = {"rank": rank, "J": J, "F": F, "k": k}

    use_best = best["F"] is not F
    if use_best:
        print(f"[*] 交付第 {best['k']} 轮最优产物"
              f"(阶段 {getattr(best['F'], 'stage', '?')}), 而非最终轮",
              file=sys.stderr)
    dJ, dF = (best["J"], best["F"]) if use_best else (J, F)
    ui.render_final(status, dJ, dF, H, rounds, history)
    deliverable = build_deliverable(dJ, I, dF, A, status, history,
                                    score_hist=score_hist,
                                    llm_fresh=(A_fresh and not use_best))
    try:
        raw = client.chat(build_explain_messages(deliverable, I.to_prompt_text()))
        obj = json.loads(raw)
        deliverable["rationale"] = obj.get("rationale", "")
        deliverable["manual_steps"] = [str(s) for s in (obj.get("manual_steps") or [])]
        deliverable["env_note"] = obj.get("env_note", "")
    except Exception:
        pass
    ui.render_deliverable(deliverable)

    _write_report(dJ, deliverable, json_out)
    return 0 if status in ("PASS", "PASS_SUSPECT") else 1

def _write_report(J, deliverable, json_out) -> None:
    """导出报告(含 Algorithm 2 可交付结果); 未指定目录时落到 reports/."""
    if not json_out:
        return
    out_path = json_out
    if os.path.dirname(out_path) == "":
        out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, out_path)
    with open(out_path, "w", encoding="utf-8") as f:
        data = _dump(J)
        data["_deliverable"] = deliverable
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[+] 最终报告+可交付EXP 已写入 {out_path}")

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="analyze",
        description="WJ 统一入口: 单轮 LLM 漏洞分析(默认) / "
                    "Algorithm 1 迭代 EXP 精炼(--refine)",
    )
    parser.add_argument("binary", help="目标二进制文件路径")
    parser.add_argument("addr", nargs="?", default=None,
                        help="根函数地址(十六进制)；缺省使用 main 符号或程序入口")
    parser.add_argument("--refine", action="store_true",
                        help="启用 Algorithm 1 迭代精炼闭环"
                             "(需 WSL/Linux; RunVerify 依赖 pwntools)")
    parser.add_argument("--depth", type=int, default=3, metavar="N",
                        help="调用图最大展开深度(默认 3)")
    parser.add_argument("--max-nodes", type=int, default=20, metavar="N",
                        help="调用图最多纳入函数数(默认 20)")
    parser.add_argument("--rounds", type=int, default=3, metavar="N",
                        help="[--refine] 最大优化轮数(默认 3)")
    parser.add_argument("--theta", type=float, default=THETA_PASS,
                        help="[--refine] 完成度收敛阈值(默认 %(default)s)")
    parser.add_argument("--flag", default=None,
                        help="[--refine] flag 文件路径(用于探活判定)")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="[--refine] 单次 RunVerify 超时秒数(默认 3.0)")
    parser.add_argument("--no-color", action="store_true",
                        help="[--refine] 关闭彩色输出")
    parser.add_argument("--json-out", default=None, metavar="FILE",
                        help="将结构化报告(含 exploit_plan)写入 JSON 文件,供 verify_exp.py 读取;"
                             "未指定目录时默认存入项目根 reports/ 下")
    args = parser.parse_args(argv)

    try:
        config = load_config()
    except LLMConfigError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1

    if args.refine:
        ui.init_color(args.no_color)
        return refine(args.binary, args.addr, args.depth, args.max_nodes,
                      config, args.rounds, args.theta, args.flag,
                      args.timeout, args.json_out)

    # ---- 单轮分析(默认): 不依赖 pwntools, Windows 亦可运行 ----
    try:
        report, ev, nodes, prog, graph, root = round_zero(
            args.binary, args.addr, args.depth, args.max_nodes, config)
    except LargeStaticError as exc:
        print(f"[跳过] {exc}", file=sys.stderr)
        return 2
    except LLMError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[错误] 无法加载/分析二进制 {args.binary}: {exc}", file=sys.stderr)
        return 1
    _print_report(report)
    if args.json_out:
        try:
            out_path = args.json_out
            if os.path.dirname(out_path) == "":
                out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "reports")
                os.makedirs(out_dir, exist_ok=True)
                out_path = os.path.join(out_dir, out_path)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(_dump(report), f, ensure_ascii=False, indent=2)
            print(f"[+] 报告已写入 {out_path}")
        except Exception as exc:
            print(f"[错误] 写入 JSON 失败: {exc}", file=sys.stderr)
            return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())