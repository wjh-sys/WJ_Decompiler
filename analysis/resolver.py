from __future__ import annotations

from dataclasses import dataclass, field

from .listtable import STATUS_SCORE, ListTable

@dataclass
class Material:
    kind: str = ""
    title: str = ""
    lines: list = field(default_factory=list)
    material: str = ""
    status: str = ""
    score: float = 0.0

def _kind_of(problem) -> str:
    if isinstance(problem, dict):
        return str(problem.get("kind", ""))
    return str(getattr(problem, "kind", ""))

def _target_of(problem) -> str:
    if isinstance(problem, dict):
        return str(problem.get("target", "") or "")
    return str(getattr(problem, "target", "") or "")

def _mk(kind: str, title: str, lines: list, status: str = "HIT") -> Material:
    body = "\n".join(lines)
    mat = f"[反查材料 kind={kind} status={status}] {title}\n{body}" if lines else ""
    return Material(kind=kind, title=title, lines=lines, material=mat,
                    status=status, score=STATUS_SCORE.get(status, 0.0))

def _entry_lines(res) -> list:
    out = []
    for e in res.entries[:60]:
        a = f"0x{e.addr:x}" if isinstance(e.addr, int) else "-"
        out.append(f"  {e.category:<8} {a:>10}  {e.name}  {e.detail}")
    if res.hint:
        out.append(f"  [{res.status}] {res.hint}")
    return out

RUNTIME_KINDS = ("payload_fix", "stage_runtime", "misread")

# 证据分级标记: 区分可复现的实测事实与未验证的条件性推断,
# 避免 LLM 把"若 ... 则 ..."类假设当成已确认的阻塞项.
FACT = "[实测]"
HYPO = "[假设]"
EVIDENCE_RULE = (
    "[证据分级规则] "
    "[实测]=静态反汇编实测值/可复现事实, 优先级最高, 不得推翻; "
    "[假设]=未经验证的条件性推断, 默认不成立. "
    "若 [假设] 与 [实测] 冲突, 一律以 [实测] 为准; "
    "严禁仅凭 [假设] 修改已与 [实测] 一致的字段(如 offset)."
)

def _resolve_one(problem, ev, prog, feedback=None, table=None) -> Material:
    kind = _kind_of(problem)
    target = _target_of(problem)
    if kind in RUNTIME_KINDS:
        return _runtime_material(kind, feedback)
    if table is None:
        table = ListTable.from_evidence(ev, prog)
    res = table.lookup(kind, target)
    if kind == "addr_missing":
        return _mk(kind, "可利用目标地址(List Table: sym/backdoor)",
                   _entry_lines(res), res.status)
    if kind == "gadget_missing":
        return _mk(kind, "ROP gadget(List Table: gadget)",
                   _entry_lines(res), res.status)
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
        return _mk(kind, f"泄漏所需信息[ListTable {res.status}]", lines, res.status)
    if kind == "string_missing":
        lines = _entry_lines(res)
        if prog is not None:
            for addr, text in sorted(getattr(prog, "strings", {}).items())[:60]:
                if len(text) <= 64:
                    lines.append(f"  0x{addr:x}: {text!r}")
        return _mk(kind, "字符串语料", lines, res.status)
    if kind == "offset_wrong":
        lines = []
        measured, hypo = [], []
        for o in getattr(ev, "overflow", []):
            measured.append(f"  {FACT} {o.func} @ 0x{o.faddr:x}: {o.call}(...) 距 saved-eip "
                            f"{o.offset_to_ret}(0x{o.offset_to_ret:x}) 字节")
            r = getattr(o, "reentry_offset", None)
            if r:
                hypo.append(f"  {HYPO} 仅当 {o.func} 被二次调用(经 ret 重新进入)时, 偏移才因"
                            f"栈对齐平移为 {r}(0x{r:x}); 此为推断, 非实测")
        lines += measured
        if hypo:
            lines.append("  ── 以下为条件性假设, 默认不成立 ──")
            lines += hypo
            lines.append(f"  {FACT} 若上方实测偏移已与报告一致, 禁止改动 offset; "
                         "仅当运行证据(crash 地址与偏移的对应关系)明确指向二次返回时, "
                         "才可采纳假设值")
        return _mk(kind, "实测溢出偏移(勿估算)", lines, res.status)
    return Material(kind=kind, title="无静态材料", lines=[], material="", status=res.status)

def _runtime_material(kind, feedback) -> Material:
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
    if not lines:
        return Material(kind=kind, title="无运行期材料", lines=[], material="")
    return _mk(kind, "运行期证据(上一轮 traceback/回显)", lines, "HIT")

def resolve(problems, evidence, prog=None, feedback=None) -> list:
    table = ListTable.from_evidence(evidence, prog)
    return [_resolve_one(p, evidence, prog, feedback, table)
            for p in (problems or [])]

def table_of(evidence, prog=None) -> ListTable:
    """供 Algorithm 2 计算 List Table 覆盖度使用."""
    return ListTable.from_evidence(evidence, prog)

def format_materials(materials) -> str:
    body = "\n\n".join(m.material for m in materials if m.material)
    if not body:
        return ""
    return f"{EVIDENCE_RULE}\n\n{body}"