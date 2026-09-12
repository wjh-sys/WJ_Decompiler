"""CLI 可视化层: 规范展示 Algorithm 1 迭代过程的反馈/归因/缺口/解题。"""
from __future__ import annotations

import os
import re
import shutil
import sys
import unicodedata

_COLOR = False
_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "gray": "\033[90m",
}

def init_color(off: bool = False) -> None:
    global _COLOR
    if off or os.environ.get("NO_COLOR"):
        _COLOR = False
        return
    try:
        _COLOR = sys.stdout.isatty()
    except Exception:
        _COLOR = False
    if _COLOR and os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass

def _c(text, *styles) -> str:
    if not _COLOR:
        return text
    return "".join(_C.get(s, "") for s in styles) + text + _C["reset"]

def _dw(s) -> int:
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in str(s))

def _w() -> int:
    try:
        return max(64, min(shutil.get_terminal_size((92, 24)).columns, 112))
    except Exception:
        return 92

def _wrap(s, width) -> list:
    s = str(s)
    if _dw(s) <= width:
        return [s]
    out, cur = [], ""
    for ch in s:
        if _dw(cur) + _dw(ch) > width:
            out.append(cur)
            cur = ch
        else:
            cur += ch
    out.append(cur)
    return out

def rule(title: str = "", color: str = "blue") -> str:
    w = _w()
    if not title:
        return _c("─" * w, color)
    pad = max(0, w - _dw(title) - 4)
    return _c("─" * (pad // 2) + " " + title + " " + "─" * (pad - pad // 2), color)

def box(title: str, lines: list, color: str = "cyan") -> str:
    w = _w()
    inner = w - 2
    head = "┌─ " + title + " " + "─" * max(0, inner - _dw(title) - 3) + "┐"
    out = [_c(head, color)]
    for ln in lines:
        for seg in _wrap(ln, inner - 2):
            out.append(_c("│", color) + " " + seg
                       + " " * max(0, inner - 2 - _dw(seg)) + " " + _c("│", color))
    out.append(_c("└" + "─" * inner + "┘", color))
    return "\n".join(out)

def step(name: str, desc: str = "") -> None:
    tail = " " + _c(desc, "gray") if desc else ""
    print(_c(f"\n▸ [{name}]", "magenta", "bold") + tail)

def _get(obj, key):
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)

def _to_int(s):
    if s is None:
        return None
    m = re.search(r"0x[0-9a-fA-F]+|\d+", str(s))
    if not m:
        return None
    try:
        return int(m.group(0), 0)
    except Exception:
        return None

def _bar(score, width: int = 30) -> str:
    s = max(0.0, min(1.0, float(score or 0)))
    fill = int(round(s * width))
    col = "green" if s >= 0.85 else ("yellow" if s >= 0.5 else "red")
    return _c("█" * fill, col) + _c("░" * (width - fill), "gray") + f"  {s * 100:5.1f}%"

STAGE_INFO = {
    "no_exp_code": ("无 EXP 代码", "red"),
    "payload_eval": ("payload 求值失败", "red"),
    "spawn_fail": ("目标进程启动失败", "red"),
    "segv": ("崩溃(段错误)", "yellow"),
    "timeout": ("探活超时", "yellow"),
    "eof": ("进程提前退出, 未见回显", "yellow"),
    "no_marker": ("未命中标记", "yellow"),
    "marker_ok": ("已打通(拿到 shell)", "green"),
}
KIND_INFO = {
    "addr_missing": ("地址缺失", "缺 system@plt / 后门 / 跳转目标地址", "可反查"),
    "gadget_missing": ("gadget 缺失/不足", "缺可用 ROP gadget", "可反查"),
    "need_leak": ("需先泄漏", "PIE/ASLR 需泄漏基址或 libc", "可反查"),
    "string_missing": ("字符串缺失", "缺 /bin/sh 等字符串或地址", "可反查"),
    "offset_wrong": ("偏移错误", "栈偏移须用静态实测值", "可反查"),
    "payload_fix": ("payload 构造错误", "payload 拼装/打包有误", "运行期证据"),
    "stage_runtime": ("运行期问题", "交互/时序/环境等运行期卡点", "运行期证据"),
    "misread": ("误读", "对客观证据理解有误", "运行期证据"),
}
GADGET_CATS = [
    ("reg-set", "寄存器设置", "green"),
    ("stack-pivot", "栈迁移", "green"),
    ("syscall", "系统调用", "green"),
    ("call", "调用跳转", "cyan"),
    ("move", "数据搬运", "gray"),
    ("arith", "算术逻辑", "gray"),
    ("other", "其他", "gray"),
]
STATUS_INFO = {
    "PASS": ("EXP 已打通", "green"),
    "PASS_SUSPECT": ("模型判定已打通(建议人工复核)", "green"),
    "CONVERGED": ("完成度达阈值, 收敛", "cyan"),
    "MAX_ROUNDS": ("到达最大轮数上限", "yellow"),
    "NO_PROBLEM": ("无待解问题", "yellow"),
    "STALLED": ("问题清单不再变化, 停摆", "yellow"),
    "UNRESOLVABLE": ("问题无静态材料可反查", "yellow"),
    "LLM_FAILED": ("大模型调用失败", "red"),
}

def render_banner(binary: str, rounds: int, theta: float) -> None:
    print(rule(" WJ · Algorithm 1 · Taint 引导的迭代 EXP 精炼 ", "blue"))
    print(box("运行配置", [f"目标     : {binary}",
                           f"轮数上限 : {rounds}    收敛阈值: {theta}"], "blue"))

def render_round_zero(J, I, nodes, root) -> None:
    lines = [
        f"根函数   : {_c(hex(root), 'yellow')}    展开函数: {len(nodes)}",
        f"漏洞类型 : {_c(_get(J, 'vulnerability_type') or '-', 'cyan')}"
        f"    置信度: {(_get(J, 'confidence') or 0.0):.2f}",
        f"漏洞函数 : {_get(J, 'vulnerable_function') or '-'}",
        f"调用链   : {' -> '.join(_get(J, 'call_chain') or []) or '-'}",
    ]
    ov = _get(I, "overflow") or []
    if ov:
        lines.append(_c("静态实测溢出点:", "cyan"))
        for o in ov:
            lines.append(f"  {o.func} @ 0x{o.faddr:x}: {o.call}(...) 偏移 {o.offset_to_ret}")
    print(box("RoundZero 初始报告 (J0)", lines, "blue"))

def render_round(k: int, total: int, theta: float) -> None:
    print("\n" + rule(f" ROUND {k}/{total} ", "blue"))

def render_feedback(F) -> None:
    stage = _get(F, "stage") or "?"
    text, col = STAGE_INFO.get(stage, (stage, "white"))
    ok = bool(_get(F, "ok"))
    lines = [
        f"stage   : {_c(stage, col, 'bold')}  {_c(text, col)}",
        f"结果    : {_c('PASS' if ok else 'FAIL', 'green' if ok else 'red', 'bold')}",
        f"指纹    : {_c(_get(F, 'fingerprint') or '-', 'gray')}",
    ]
    tb = _get(F, "exp_traceback") or ""
    if tb:
        lines += ["", _c("● EXP traceback:", "red")] + tb.strip().splitlines()[-8:]
    diag = _get(F, "diagnosis") or ""
    if diag:
        dl = diag.strip().splitlines()
        lines += ["", _c(dl[0], "cyan")] + dl[1:]
    out = _get(F, "stdout_tail") or ""
    if out:
        lines += ["", _c("● 进程回显尾部:", "gray")] + out.strip().splitlines()[-8:]
    print(box("RunVerify 验证反馈", lines, "green" if ok else "yellow"))

def render_diagnosis(J, I) -> None:
    lines = [_c("● 偏移核对 (LLM 报告 vs 静态实测):", "cyan")]
    ov = _get(I, "overflow") or []
    ep = _get(J, "exploit_plan")
    llm_off = _to_int(_get(ep, "offset"))
    if ov:
        for o in ov:
            real = o.offset_to_ret
            if llm_off is None:
                lines.append(f"  {o.func}: LLM 未给出偏移   "
                             f"{_c('静态实测=' + str(real), 'yellow')}")
            elif llm_off == real:
                lines.append(f"  {o.func}: {_c('✔ 一致', 'green')}  "
                             f"LLM={llm_off}  静态实测={real}")
            else:
                lines.append(f"  {o.func}: {_c('✘ 不一致', 'red', 'bold')}  "
                             f"LLM={llm_off}  静态实测={real}(0x{real:x})")
    else:
        lines.append(_c("  静态语料未发现溢出入点(非栈溢出或需人工判读)", "yellow"))

    lines += ["", _c("● ROP gadget 储备:", "cyan")]
    gs = _get(I, "gadgets") or []
    if gs:
        cats: dict = {}
        for g in gs:
            cats.setdefault(g.get("cat", "other"), []).append(g)
        lines.append(f"  共 {len(gs)} 个")
        for cat, label, col in GADGET_CATS:
            if cat in cats:
                names = ", ".join(sorted({g["asm"] for g in cats[cat]})[:6])
                lines.append(_c(f"    {label:<10}: {len(cats[cat]):>3} 个  {names}", col))
        if "reg-set" not in cats:
            lines.append(_c("    警告: 无 pop 系寄存器设置 gadget, 需考虑 ret2text/ret2libc",
                            "red"))
    else:
        lines.append(_c("  0 个 (无可用 gadget, 需考虑 ret2text / ret2libc / shellcode)",
                        "red"))
    print(box("缺口诊断 (静态核对)", lines, "yellow"))

def render_analysis(A, theta: float) -> None:
    lines = [f"完成度  : {_bar(_get(A, 'score') or 0.0)}   (阈值 {theta})"]
    if _get(A, "actually_passed"):
        lines.append(_c("● 模型判断: 其实已打通(探活可能误判)", "green", "bold"))
    lines += ["", _c("● 大模型归因(思考):", "cyan")]
    for seg in _wrap(_get(A, "reasoning") or "(无)", _w() - 6):
        lines.append("  " + seg)
    problems = _get(A, "problems") or []
    lines += ["", _c(f"● 问题清单 ({len(problems)}):", "cyan")]
    if not problems:
        lines.append("  (无)")
    for i, p in enumerate(problems, 1):
        kind = _get(p, "kind") or ""
        detail = _get(p, "detail") or ""
        target = _get(p, "target") or ""
        name, desc, tagtxt = KIND_INFO.get(kind, (kind, "", "?"))
        tagcol = {"可反查": "green", "运行期证据": "cyan"}.get(tagtxt, "gray")
        tag = _c(tagtxt, tagcol)
        lines.append(f"  {i}. {_c(name, 'yellow', 'bold')} [{_c(kind, 'gray')}] {tag}")
        lines.append(f"     {desc}" + (f"  target={target}" if target else ""))
        for seg in (_wrap(detail, _w() - 8) if detail else []):
            lines.append("     " + seg)
    locked = _get(A, "locked") or []
    if locked:
        lines += ["", _c("● 锁定字段(下轮禁止改动): ", "cyan") + ", ".join(locked)]
    print(box("LLMAnalyze 归因结果 (分析过程)", lines, "magenta"))

def render_materials(R, M) -> None:
    lines = []
    for m in R:
        if m.material:
            lines.append(_c(f"✔ {m.kind}  {m.title}", "green", "bold"))
            for seg in m.material.splitlines()[1:11]:
                for s in _wrap(seg, _w() - 6):
                    lines.append("  " + s)
        else:
            lines.append(_c(f"✘ {m.kind}  查无静态材料", "red")
                         + _c("  -> 可能触发 UNRESOLVABLE", "gray"))
    print(box(f"Resolve 反查结果 (命中 {len(M)}/{len(R)})", lines,
              "green" if M else "red"))

def render_solving(A, J, applied) -> None:
    ep = _get(J, "exploit_plan")
    lines = [
        f"漏洞类型 : {_c(_get(J, 'vulnerability_type') or '-', 'cyan')}"
        f"    置信度: {(_get(J, 'confidence') or 0.0):.2f}",
        f"溢出偏移 : {_c(_get(ep, 'offset') or '-', 'yellow')}",
    ]
    layout = _get(ep, "payload_layout")
    if layout:
        lines.append("payload  :")
        for it in layout[:8]:
            lines.append(f"  - {it}")
    code = (_get(ep, "exp_code") or "").strip()
    if code:
        rows = code.splitlines()
        lines.append(_c("exp_code 预览:", "cyan"))
        for seg in rows[:20]:
            lines.append("  " + seg)
        if len(rows) > 20:
            lines.append(_c(f"  ...(余 {len(rows) - 20} 行见 JSON)", "gray"))
    fixed = [str(_get(p, "kind")) for p in (_get(A, "problems") or [])]
    if fixed:
        lines.append(_c("本轮修复目标: ", "cyan") + ", ".join(fixed))
    if applied:
        lines.append(_c("锁定回填 : ", "cyan") + ", ".join(applied))
    print(box("LLMRegenerate 新 EXP (解题过程)", lines, "cyan"))

def record(k, F, A, hit, total, locked) -> dict:
    kinds = [str(_get(p, "kind")) for p in ((_get(A, "problems") or []) if A else [])]
    return {"round": k, "stage": _get(F, "stage") or "?",
            "score": float(_get(A, "score") or 0.0) if A else 0.0,
            "kinds": [x for x in kinds if x], "hit": hit, "total": total,
            "locked": list(locked or [])}

def render_final(status, J, F, H, rounds, history) -> None:
    text, col = STATUS_INFO.get(status, (status, "white"))
    stage = _get(F, "stage") or "?"
    s_text, s_col = STAGE_INFO.get(stage, (stage, "white"))
    ok = bool(_get(F, "ok"))
    print("\n" + rule(" 算法终止 ", "blue"))
    lines = [
        f"终止状态 : {_c(status, col, 'bold')}  {_c(text, col)}",
        f"实际轮数 : {len(history)}/{rounds}",
        f"最终阶段 : {_c(stage, s_col, 'bold')}  {_c(s_text, s_col)}",
        f"最终结果 : {_c('PASS' if ok else 'FAIL', 'green' if ok else 'red', 'bold')}",
        f"漏洞类型 : {_get(J, 'vulnerability_type') or '-'}"
        f"    置信度: {(_get(J, 'confidence') or 0.0):.2f}",
    ]
    if H:
        lines.append(f"证据指纹链: {' -> '.join(H)}")
    if history:
        lines += ["", _c("● 迭代时间线:", "cyan")]
        for r in history:
            kinds = ",".join(r["kinds"]) or "-"
            score = "  --.--%" if not r.get("kinds") and r["score"] == 0.0 \
                else f"{r['score'] * 100:5.1f}%"
            lines.append(f"  R{r['round']}: {r['stage']:<11} 完成度 {score}"
                         f"  问题[{kinds}]  材料 {r['hit']}/{r['total']}"
                         f"  锁定 {len(r['locked'])}")
    print(box("Algorithm 1 运行总结", lines, "cyan"))
    print("\n")

def render_deliverable(D) -> None:
    ok = bool(D.get("ready_to_use"))
    lines = [
        f"完成度   : {_bar(D.get('score', 0.0))}"
        f"   {'✔ 可直接使用' if ok else '✘ 需人工补齐'}",
        f"验证     : {'PASS' if ok else 'FAIL'}"
        f"   终止状态: {D.get('status', '-')}   阶段: {D.get('stage', '-')}",
        f"漏洞类型 : {D.get('vulnerability_type') or '-'}"
        f"   置信度: {D.get('confidence', 0.0):.2f}   轮数: {D.get('rounds_used', 0)}",
        f"溢出偏移 : {D.get('offset') or '-'}",
    ]
    layout = D.get("payload_layout") or []
    if layout:
        lines.append("payload  :")
        for it in layout[:10]:
            lines.append(f"  - {it}")
    gaps = D.get("gaps") or []
    lines += ["", _c(f"● 缺口清单 ({len(gaps)}):", "cyan")]
    if not gaps:
        lines.append(_c("  (无, EXP 已可直接使用)", "green"))
    for i, g in enumerate(gaps, 1):
        blocker = g.get("severity") == "blocker"
        tag = _c("阻塞", "red", "bold") if blocker else _c("待改", "yellow")
        lines.append(f"  {i}. {tag} [{_c(g.get('kind', '?'), 'gray')}]")
        for seg in _wrap(g.get("detail", "") or "(无描述)", _w() - 8):
            lines.append("     " + seg)
        hint = g.get("hint") or ""
        if hint:
            for seg in _wrap("→ " + hint, _w() - 8):
                lines.append(_c("     " + seg, "cyan"))
    code = (D.get("exp_code") or "").strip()
    if code:
        rows = code.splitlines()
        lines += ["", _c(f"● 完整 EXP ({len(rows)} 行):", "cyan")]
        for seg in rows[:120]:
            lines.append("  " + seg)
        if len(rows) > 120:
            lines.append(_c(f"  ...(余 {len(rows) - 120} 行见 JSON)", "gray"))
    steps = D.get("manual_steps") or []
    if steps:
        lines += ["", _c(f"● 需你自行补充 ({len(steps)}):", "yellow")]
        for i, s in enumerate(steps, 1):
            for seg in _wrap(f"  {i}. {s}", _w() - 4):
                lines.append(seg)
    note = D.get("env_note") or ""
    if note:
        lines += ["", _c("● 环境差异说明:", "cyan")]
        for seg in _wrap(note, _w() - 4):
            lines.append("  " + seg)
    rat = D.get("rationale") or ""
    if rat:
        lines += ["", _c("● 构造原理讲解:", "cyan")]
        for seg in _wrap(rat, _w() - 4):
            lines.append("  " + seg)
    print(box("可交付 EXP (Deliverable)", lines, "green" if ok else "yellow"))