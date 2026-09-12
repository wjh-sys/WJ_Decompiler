from __future__ import annotations

from dataclasses import dataclass, field

@dataclass
class Material:
    kind: str = ""
    title: str = ""
    lines: list = field(default_factory=list)
    material: str = ""

def _kind_of(problem) -> str:
    if isinstance(problem, dict):
        return str(problem.get("kind", ""))
    return str(getattr(problem, "kind", ""))

def _mk(kind: str, title: str, lines: list) -> Material:
    body = "\n".join(lines)
    mat = f"[反查材料 kind={kind}] {title}\n{body}" if lines else ""
    return Material(kind=kind, title=title, lines=lines, material=mat)

def _resolve_one(kind: str, ev, prog, feedback=None) -> Material:
    if kind == "addr_missing":
        lines = [f"  {t.kind:<9} {t.name}  {t.detail}" for t in getattr(ev, "targets", [])]
        return _mk(kind, "可利用目标地址(plt/后门)", lines)
    if kind == "gadget_missing":
        lines = [f"  0x{g['addr']:x}: {g['asm']}" for g in getattr(ev, "gadgets", [])]
        return _mk(kind, "ROP gadget", lines)
    if kind == "need_leak":
        p = getattr(ev, "protections", {}) or {}
        lines = [f"  保护: NX={p.get('NX','?')} Canary={p.get('Canary','?')} "
                 f"PIE={p.get('PIE','?')} RELRO={p.get('RELRO','?')}"]
        for t in getattr(ev, "targets", []):
            if t.name in ("puts", "printf", "write", "putchar"):
                lines.append(f"  {t.kind:<9} {t.name}  {t.detail}")
        lc = getattr(ev, "libc", {}) or {}
        if lc:
            lines.append(f"  同目录 libc: {lc.get('path', '?')}")
            for k in ("system", "__libc_start_main", "puts", "read", "write"):
                if k in lc:
                    lines.append(f"    {k} 偏移 = 0x{lc[k]:x}")
            if "str_bin_sh" in lc:
                lines.append(f"    '/bin/sh' 偏移 = 0x{lc['str_bin_sh']:x}")
            lines.append("  用法: 先溢出泄露 got 表函数真实地址 -> libc_base = 泄露值 - 该函数偏移")
            lines.append("        -> system/str_bin_sh = libc_base + 偏移 (两阶段 ret2libc)")
        if p.get("PIE") == "on":
            lines.append("  提示: PIE 开启,硬编码内部地址无效,需先泄漏基址")
        return _mk(kind, "泄漏所需信息", lines)
    if kind == "string_missing":
        lines = [f"  0x{s['addr']:x}: {s['text']!r}" for s in getattr(ev, "strings", [])]
        if prog is not None:
            for addr, text in sorted(getattr(prog, "strings", {}).items())[:100]:
                if len(text) <= 64:
                    lines.append(f"  0x{addr:x}: {text!r}")
        return _mk(kind, "字符串语料", lines)
    if kind == "offset_wrong":
        lines = []
        for o in getattr(ev, "overflow", []):
            lines.append(f"  {o.func} @ 0x{o.faddr:x}: {o.call}(...) 距 saved-eip "
                         f"{o.offset_to_ret}(0x{o.offset_to_ret:x}) 字节")
            r = getattr(o, "reentry_offset", None)
            if r:
                lines.append(f"    注: 若 ret 二次返回本函数再溢出, 偏移可能为 {r}(栈对齐平移)")
        return _mk(kind, "实测溢出偏移(勿估算)", lines)
    if kind in ("payload_fix", "stage_runtime", "misread"):
        lines = []
        st = getattr(feedback, "stage", "") if feedback is not None else ""
        tb = getattr(feedback, "exp_traceback", "") if feedback is not None else ""
        out = getattr(feedback, "stdout_tail", "") if feedback is not None else ""
        if st:
            lines.append(f"  卡点阶段: {st}")
        diag = getattr(feedback, "diagnosis", "") if feedback is not None else ""
        if diag:
            lines.append("  " + diag.replace("\n", "\n  "))
        if tb:
            lines.append("  上一轮 EXP traceback:")
            lines += tb.strip().splitlines()[-12:]
        if out:
            lines.append("  进程回显尾部:")
            lines += out.strip().splitlines()[-8:]
        if lines:
            return _mk(kind, "运行期证据(上一轮 traceback/回显)", lines)
        return Material(kind=kind, title="无运行期材料", lines=[], material="")
    return Material(kind=kind, title="无静态材料", lines=[], material="")

def resolve(problems, evidence, prog=None, feedback=None) -> list:
    return [_resolve_one(_kind_of(p), evidence, prog, feedback)
            for p in (problems or [])]

def format_materials(materials) -> str:
    return "\n\n".join(m.material for m in materials if m.material)