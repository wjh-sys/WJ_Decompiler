
# d:\CODE\WJ_Decompiler\analysis\taint.py
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from ir import BinOp, Const, Expr, Mem, Var
from ir.lifter import Lifter, _split_top_level

SOURCES = {
    "gets", "read", "fgets", "fread", "scanf", "fscanf",
    "__isoc99_scanf", "__isoc99_fscanf", "recv", "getline",
}
SOURCE_BUF_ARG = {
    "gets": (0, None), "read": (1, 2), "fgets": (0, 2), "fread": (0, 2),
    "scanf": (1, None), "__isoc99_scanf": (1, None),
    "fscanf": (1, None), "__isoc99_fscanf": (1, None),
    "recv": (1, 2), "getline": (0, 2),
}
EXEC_FUNCS = {"system", "execve", "execl", "execlp", "execvp", "popen"}
SUSPECT_STR = re.compile(r"/bin/sh|/system|shell|flag|cat /|> /|/bin/cat|sh\"|sh'|/bin/bash", re.I)
SUSPECT_NAME = re.compile(r"win|backdoor|shell|system|flag|secret|hack|pwn|secure|vuln", re.I)
REGS32 = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
REGS64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
ARG_REGS64 = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
ALIAS64 = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
           "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
           "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
           "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15"}

@dataclass
class OverflowSite:
    func: str
    faddr: int
    site: int
    call: str
    args: list
    base: str
    disp: int
    offset_to_ret: int
    why: str
    reachable: bool = False
    reentry_offset: int | None = None

@dataclass
class Backdoor:
    name: str
    addr: int
    note: str

@dataclass
class Target:
    kind: str
    name: str
    detail: str

@dataclass
class Evidence:
    arch: str = ""
    bits: int = 0
    protections: dict = field(default_factory=dict)
    overflow: list = field(default_factory=list)
    backdoors: list = field(default_factory=list)
    targets: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    funcs: list = field(default_factory=list)
    sinks: list = field(default_factory=list)
    gadgets: list = field(default_factory=list)
    unreachable: list = field(default_factory=list)
    unsupported: bool = False
    note: str = ""
    libc: dict = field(default_factory=dict)

    def to_prompt_text(self) -> str:
        L = []
        if self.unsupported:
            L.append("[静态污点证据]")
            L.append(f"架构 {self.arch} 暂不支持污点路径分析: {self.note}")
            return "\n".join(L)
        p = self.protections
        L.append("[静态污点证据]")
        L.append(f"架构: {self.arch} {self.bits}位  保护: "
                 f"NX={p.get('NX','?')}  Canary={p.get('Canary','?')}  "
                 f"PIE={p.get('PIE','?')}  RELRO={p.get('RELRO','?')}")
        if p.get("NX") == "off":
            L.append("提示: NX 关闭,可考虑栈上执行 shellcode")
        if p.get("PIE") == "on":
            L.append("提示: PIE 开启,直接硬编码内部地址无效,需先泄漏")
        if self.overflow:
            L.append("")
            L.append("[可能溢出的输入点](source -> 栈缓冲;偏移为实测,勿自行估算)")
            for o in self.overflow:
                mark = "可达" if o.reachable else "不可达main"
                L.append(f"  {o.func} @ 0x{o.faddr:x} [{mark}]: {o.call}"
                         f"({', '.join(o.args)})  ->  {o.why}")
        if self.sinks:
            L.append("")
            L.append("[其他输入/危险调用点]")
            for s in self.sinks:
                mark = "可达" if s["reachable"] else "不可达"
                L.append(f"  {s['func']} @ 0x{s['faddr']:x} [{mark}]: "
                         f"{s['call']}({', '.join(s['args'])})  {s['note']}")
        if self.unreachable:
            L.append("")
            L.append("注意: 下列函数未被调用图展开覆盖,可能为隐藏后门")
            for u in self.unreachable:
                L.append(f"  {u['name']} @ 0x{u['addr']:x}")
        L.append("")
        L.append("[可利用目标]")
        for t in self.targets:
            L.append(f"  {t.kind:<9} {t.name}  {t.detail}")
        if self.libc:
            lc = self.libc
            L.append("")
            L.append("[同目录 libc 符号偏移](泄露基址后 真实地址 = libc_base + 偏移)")
            L.append(f"  libc: {lc.get('path', '?')}")
            for k in ("system", "__libc_start_main", "puts", "read", "write"):
                if k in lc:
                    L.append(f"  {k} = 0x{lc[k]:x}")
            if "str_bin_sh" in lc:
                L.append(f"  str_bin_sh(\"/bin/sh\") = 0x{lc['str_bin_sh']:x}")
            if not any(t.name in ("system", "execve") for t in self.targets):
                L.append("  提示: 目标无 system@plt, 但同目录 libc 含 system; "
                         "疑需先泄漏 libc 基址(ret2libc 两阶段), 再 system('/bin/sh')")
        if self.strings:
            L.append("[可疑字符串]")
            for s in self.strings:
                L.append(f"  0x{s['addr']:x}: {s['text']!r}")
        if self.gadgets:
            L.append("[ROP gadget]")
            for g in self.gadgets:
                L.append(f"  0x{g['addr']:x}: {g['asm']}")
        L.append("")
        L.append("[用户函数总览]")
        seen = set()
        for f in sorted(self.funcs, key=lambda x: (not x["reachable"], x["addr"])):
            if f["addr"] in seen:
                continue
            seen.add(f["addr"])
            mark = "" if f["reachable"] else "(不可达)"
            L.append(f"  {f['name']} @ 0x{f['addr']:x} {mark}".rstrip())
        return "\n".join(L)

@dataclass
class _CallEv:
    site: int
    target: int | None
    args: list
    esp_off: int = 0
    ebp_off: int | None = None

class TaintAnalyzer:
    def __init__(self, prog, graph, binary_path: str | None = None):
        self.prog = prog
        self.graph = graph
        self.dis = graph.dis
        self.binary_path = binary_path
        self.bits = prog.bits
        self.ws = prog.bits // 8
        self.is_x86 = prog.arch in ("x86", "x86_64")
        self.lf = Lifter(self.dis)
        self.resolve = graph.resolve_name
        self._root = self._find_root()

    def _find_root(self) -> int:
        for s in self.prog.symbols:
            if s.name == "main" and s.addr:
                return s.addr
        # strip 二进制无 main 符号: 从 _start 反汇编找 mov rdi, imm(传给
        # __libc_start_main 的用户 main 地址)
        try:
            entry = self.prog.entry
            cs = self.prog.find_section(entry)
            if cs is not None:
                code = cs.data[entry - cs.addr: entry - cs.addr + 0x100]
                for ins in self.dis.decode(code, entry):
                    m = ins.mnemonic
                    ops = ins.op_str
                    if m == "mov" and ops.startswith("rdi,"):
                        val = ops[4:].strip()
                        try:
                            return int(val, 0)
                        except ValueError:
                            pass
                    # _start 通常几十条内就 call __libc_start_main
                    if m == "call":
                        break
        except Exception:
            pass
        return self.prog.entry

    def _canon(self, name: str) -> str:
        if self.bits == 64:
            return ALIAS64.get(name, name)
        return name

    def _is_full(self, name: str) -> bool:
        return name in (REGS64 if self.bits == 64 else REGS32)

    def _sp_name(self) -> str:
        return "rsp" if self.bits == 64 else "esp"

    def _bp_names(self):
        return ("rbp", "ebp")

    def _parse_op(self, text: str) -> Expr:
        return self.lf._parse_one(text.strip())

    def _resolve(self, e: Expr, regs: dict, depth: int = 0) -> Expr:
        if isinstance(e, Var) and depth < 10 and e.name in regs:
            return self._resolve(regs[e.name], regs, depth + 1)
        return e

    def _rel_off(self, addr: Expr):
        sp = self._sp_name()
        if isinstance(addr, Var) and addr.name == sp:
            return 0
        if isinstance(addr, BinOp) and isinstance(addr.lhs, Var) and addr.lhs.name == sp \
                and isinstance(addr.rhs, Const):
            c = addr.rhs.val
            if addr.op == "+":
                return c
            if addr.op == "-":
                return -c
        return None

    def _collect_body(self, addr: int):
        sec = self.prog.find_section(addr)
        if sec is None:
            return []
        nxt = None
        for a in sorted(self.graph._func_addrs):
            if a > addr:
                nxt = a
                break
        limit = nxt if nxt is not None else sec.addr + sec.size
        avail = max(0, limit - addr)
        code = sec.data[addr - sec.addr: addr - sec.addr + min(avail, 0x4000)]
        out = []
        for ins in self.dis.decode(code, addr):
            out.append(ins)
            if ins.mnemonic == "ret":
                break
        return out

    def _simulate(self, insns) -> list:
        regs: dict = {}
        pushes: list = []
        rel: dict = {}
        events: list = []
        sp = "rsp" if self.bits == 64 else "esp"
        bp = "rbp" if self.bits == 64 else "ebp"
        esp_off = 0          # 相对函数入口 esp(即 saved-eip 所在)
        ebp_off = None       # 执行 mov ebp,esp 后才可知
        entry_mod = 8 if self.bits == 64 else 12

        def store_reg(name: str, val: Expr):
            c = self._canon(name)
            if self._is_full(c):
                regs[c] = self._resolve(val, regs)

        for ins in insns:
            m = ins.mnemonic
            ops_txt = _split_top_level(ins.op_str.strip(), ",") if ins.op_str.strip() else []
            if not ops_txt:
                continue
            if m == "lea":
                dst = self._parse_op(ops_txt[0])
                src = self._parse_op(ops_txt[1])
                if isinstance(dst, Var) and isinstance(src, Mem):
                    store_reg(dst.name, src.addr)
            elif m == "mov" and len(ops_txt) == 2:
                dst = self._parse_op(ops_txt[0])
                src = self._parse_op(ops_txt[1])
                if isinstance(dst, Var):
                    store_reg(dst.name, src)
                    if dst.name == sp and isinstance(src, Var) and src.name == bp \
                            and ebp_off is not None:
                        esp_off = ebp_off
                    elif dst.name == bp and isinstance(src, Var) and src.name == sp:
                        ebp_off = esp_off
                elif isinstance(dst, Mem):
                    k = self._rel_off(dst.addr)
                    if k is not None:
                        rel[k] = self._resolve(src, regs)
            elif m == "push" and len(ops_txt) == 1:
                v = self._parse_op(ops_txt[0])
                pushes.append(self._resolve(v, regs))
                esp_off -= self.ws
            elif m == "pop" and len(ops_txt) == 1:
                esp_off += self.ws
            elif m in ("sub", "add") and len(ops_txt) == 2:
                dst = self._parse_op(ops_txt[0])
                src = self._parse_op(ops_txt[1])
                if isinstance(dst, Var) and dst.name == sp and isinstance(src, Const):
                    v = src.val
                    esp_off = esp_off - v if m == "sub" else esp_off + v
            elif m == "and" and len(ops_txt) == 2:
                dst = self._parse_op(ops_txt[0])
                src = self._parse_op(ops_txt[1])
                if isinstance(dst, Var) and dst.name == sp and isinstance(src, Const):
                    c = src.val & ((1 << self.bits) - 1)
                    if c >= (1 << (self.bits - 1)):
                        c -= (1 << self.bits)
                    low = (~c) & ((1 << self.bits) - 1)
                    if low and ((low + 1) & low) == 0:
                        step = low + 1
                        esp_off -= (entry_mod + esp_off) % step
            elif m == "call" and len(ops_txt) == 1:
                t = self._parse_op(ops_txt[0])
                target = t.val if isinstance(t, Const) else None
                if target is None:
                    pushes, rel = [], {}
                    continue
                events.append(_CallEv(ins.addr, target,
                                      self._call_args(regs, pushes, rel),
                                      esp_off, ebp_off))
                pushes, rel = [], {}
            elif m == "leave":
                if ebp_off is not None:
                    esp_off = ebp_off + self.ws
                    ebp_off = None
                pushes, rel = [], {}
            elif m == "ret":
                pushes, rel = [], {}
                break
        return events

    def _call_args(self, regs: dict, pushes: list, rel: dict) -> list:
        if self.bits == 64:
            out = [regs[n] for n in ARG_REGS64 if n in regs]
            if rel:
                out += [v for _, v in sorted(rel.items())]
            return out
        if rel:
            return [v for _, v in sorted(rel.items())]
        if pushes:
            return list(reversed(pushes))
        return []

    def _fmt_expr(self, e: Expr) -> str:
        if isinstance(e, Const):
            s = self.prog.string_at(e.val) if self.prog is not None else None
            if s is not None:
                return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
            if e.val > 0x7fffffff:
                return str(e.val - (1 << 32))
            return hex(e.val)
        if isinstance(e, Var):
            return e.name
        if isinstance(e, Mem):
            return f"*({self._fmt_expr(e.addr)})"
        if isinstance(e, BinOp):
            return f"({self._fmt_expr(e.lhs)} {e.op} {self._fmt_expr(e.rhs)})"
        return "?"

    def _buffer_dist(self, e: Expr, esp_off: int, ebp_off) -> int | None:
        """把栈缓冲地址表达式换算为距函数入口 saved-eip 的字节数."""
        sp = "rsp" if self.bits == 64 else "esp"
        bp = "rbp" if self.bits == 64 else "ebp"
        reg_off = {sp: esp_off, bp: ebp_off}

        def base_off(expr):
            if isinstance(expr, Var):
                return reg_off.get(self._canon(expr.name))
            if isinstance(expr, BinOp) and isinstance(expr.lhs, Var) \
                    and isinstance(expr.rhs, Const):
                off = reg_off.get(self._canon(expr.lhs.name))
                if off is None:
                    return None
                if expr.op == "+":
                    return off + expr.rhs.val
                if expr.op == "-":
                    return off - expr.rhs.val
            return None

        base = base_off(e)
        if base is None or base >= 0:
            return None
        return -base

    def _reachable_map(self) -> set:
        seen = {self._root}
        stack = [self._root]
        while stack:
            cur = stack.pop()
            for ct in self.graph._edges.get(cur, []):
                if ct.callee in self.graph._func_addrs and ct.callee not in seen:
                    seen.add(ct.callee)
                    stack.append(ct.callee)
        return seen

    def _chain(self, target: int):
        if target == self._root:
            return [self._root]
        prev = {self._root: None}
        stack = [self._root]
        while stack:
            cur = stack.pop()
            if cur == target:
                break
            for ct in self.graph._edges.get(cur, []):
                if ct.callee in self.graph._func_addrs and ct.callee not in prev:
                    prev[ct.callee] = cur
                    stack.append(ct.callee)
        if target not in prev:
            return None
        path = []
        cur = target
        while cur is not None:
            path.append(cur)
            cur = prev[cur]
        return list(reversed(path))

    def _scan_gadgets(self) -> list:
        """在可执行节区滑扫并反汇编,返回常用 ROP gadget(地址+描述).

        覆盖 32 位: pop eax; ret / pop edx; pop ecx; pop ebx; ret / int 0x80
        以及 x86-64 常用: pop rdi; ret / pop rsi; ret / pop rdx; ret 等。
        返回形如 [{addr, asm, cat}],cat 为类别标签供 prompt 描述。
        """
        cs = self.prog.code_section
        if cs is None or not self.is_x86:
            return []
        want = {
            b"\x58\xc3": "pop eax; ret",
            b"\x59\xc3": "pop ecx; ret",
            b"\x5a\xc3": "pop edx; ret",
            b"\x5b\xc3": "pop ebx; ret",
            b"\x5f\xc3": "pop edi; ret",
            b"\x5e\xc3": "pop esi; ret",
            b"\x5d\xc3": "pop ebp; ret",
            b"\xc9\xc3": "leave; ret",
            b"\x94\xc3": "xchg eax, esp; ret",
            b"\x5a\x59\x5b\xc3": "pop edx; pop ecx; pop ebx; ret",
            b"\x58\x59\x5a\x5b\xc3": "pop eax; pop ecx; pop edx; pop ebx; ret",
        }
        if self.bits == 64:
            want = {
                b"\x5f\xc3": "pop rdi; ret",
                b"\x5e\xc3": "pop rsi; ret",
                b"\x5a\xc3": "pop rdx; ret",
                b"\x58\xc3": "pop rax; ret",
                b"\x5b\xc3": "pop rbx; ret",
                b"\x41\x5f\xc3": "pop r15; ret",
                b"\x41\x5e\xc3": "pop r14; ret",
                b"\x41\x5c\xc3": "pop r12; ret",
                b"\xc9\xc3": "leave; ret",
                b"\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3":
                    "pop r12; pop r13; pop r14; pop r15; ret",
            }
        data = cs.data
        base = cs.addr
        hits = {}

        # 通道1: 预设签名(字节匹配, 与指令对齐无关, 覆盖多弹序列)
        for pat, desc in want.items():
            start = 0
            while True:
                idx = data.find(pat, start)
                if idx < 0:
                    break
                hits.setdefault(base + idx, desc)
                start = idx + 1

        # 通道2: 滑窗反汇编(从每个偏移尝试解码, 收集以 ret 结尾的短 gadget)
        ok_ops = {"pop", "nop", "leave", "xchg", "add", "sub", "xor",
                  "mov", "inc", "dec", "and", "or", "shl", "shr", "sar",
                  "neg", "not", "test"}
        cap = min(len(data), 0x10000)
        md = self.dis.cs
        for i in range(cap):
            seq = []
            for ins in md.disasm(data[i:i + 16], base + i):
                m = ins.mnemonic
                if m in ("ret", "retf"):
                    seq.append(ins)
                    if len(seq) <= 5 and any(
                            x.mnemonic in ("pop", "leave", "xchg") for x in seq):
                        hits.setdefault(base + i,
                                        "; ".join(f"{x.mnemonic} {x.op_str}".strip()
                                                  for x in seq))
                    break
                if m not in ok_ops or "ptr [" in ins.op_str:
                    break
                seq.append(ins)
                if len(seq) > 5:
                    break

        if self.bits == 32:
            # int 0x80 单独处理(通常紧跟 ret 或不跟)
            start = 0
            while True:
                idx = data.find(b"\xcd\x80", start)
                if idx < 0:
                    break
                hits.setdefault(base + idx, "int 0x80")
                start = idx + 1
        out = []
        for addr in sorted(hits):
            out.append({"addr": addr, "asm": hits[addr], "cat": _gadget_cat(hits[addr])})
        return out

    def analyze(self) -> Evidence:
        ev = Evidence(arch=self.prog.arch, bits=self.prog.bits)
        if not self.is_x86:
            ev.unsupported = True
            ev.note = "taint 分析暂只支持 x86/x86-64"
            return ev
        ev.protections = detect_protections(self.prog, self.binary_path)
        libc_path = _find_libc(self.binary_path)
        if libc_path:
            ev.libc = _parse_libc(libc_path)
        reach = self._reachable_map()

        func_syscalls: dict[int, list] = {}
        raw_sinks: list = []

        for addr in sorted(self.graph._func_addrs):
            name = self.resolve(addr)
            body = self._collect_body(addr)
            if not body:
                continue
            for ce in self._simulate(body):
                callee_name = self.resolve(ce.target) if ce.target is not None else ""
                if callee_name in SOURCES:
                    info = SOURCE_BUF_ARG.get(callee_name, (0, None))
                    buf_idx, cnt_idx = info
                    args = ce.args
                    buf = args[buf_idx] if buf_idx < len(args) else None
                    dist = self._buffer_dist(buf, ce.esp_off, ce.ebp_off) \
                        if buf is not None else None
                    why = ""
                    if dist is None:
                        why = "未定位到栈缓冲区(可能经内存间接传入或非栈内存)"
                    else:
                        ret_off = dist
                        unbounded = False
                        if callee_name == "gets":
                            unbounded = True
                        elif callee_name in ("scanf", "fscanf", "__isoc99_scanf", "__isoc99_fscanf"):
                            fmt = args[0] if args else None
                            if isinstance(fmt, Const):
                                fs = self.prog.string_at(fmt.val) or ""
                                if "%s" in fs and not re.search(r"%\d+s", fs):
                                    unbounded = True
                        else:
                            if cnt_idx is not None and cnt_idx < len(args):
                                cnt = args[cnt_idx]
                                if isinstance(cnt, Const):
                                    unbounded = cnt.val > ret_off
                                else:
                                    why = "读入长度无法静态确认"
                        if unbounded:
                            why = (f"栈缓冲区距 saved-eip {ret_off}(0x{ret_off:x})"
                                   f"字节,可覆盖返回地址")
                            reentry = None
                            if _has_stack_realign(body) and ret_off > 8:
                                reentry = ret_off - 8
                                why += (f"; 该函数含栈对齐(and esp,-16), "
                                        f"若通过 ret 二次返回本函数再溢出, "
                                        f"偏移可能为 {reentry}")
                            ev.overflow.append(OverflowSite(
                                func=name, faddr=addr, site=ce.site, call=callee_name,
                                args=[self._fmt_expr(a) for a in args],
                                base="", disp=0, offset_to_ret=ret_off,
                                why=why, reachable=addr in reach,
                                reentry_offset=reentry))
                            if addr not in reach:
                                ev.unreachable.append({"name": name, "addr": addr})
                            continue
                    ev.sinks.append({
                        "func": name, "faddr": addr, "site": ce.site, "call": callee_name,
                        "args": [self._fmt_expr(a) for a in args], "note": why or "输入点",
                        "reachable": addr in reach,
                    })
                if callee_name in EXEC_FUNCS:
                    func_syscalls.setdefault(addr, []).append(ce)
                if callee_name in {"strcpy", "strcat", "sprintf", "vsprintf"}:
                    raw_sinks.append((addr, ce))

        for addr in sorted(self.graph._func_addrs):
            name = self.resolve(addr)
            ev.funcs.append({"name": name, "addr": addr, "reachable": addr in reach})
            if SUSPECT_NAME.search(name):
                ev.backdoors.append(Backdoor(name, addr, "函数名可疑,值得作为跳转目标考察"))
            for ce in func_syscalls.get(addr, []):
                note = f"调用 {self.resolve(ce.target)}"
                argstr = ", ".join(self._fmt_expr(a) for a in ce.args)
                if argstr:
                    note += f"({argstr})"
                    for a in ce.args:
                        if isinstance(a, Const) and self.prog is not None:
                            s = self.prog.string_at(a.val)
                            if s and SUSPECT_STR.search(s):
                                note += f";参数字符串含可疑内容: {s!r}"
                ev.backdoors.append(Backdoor(name, addr, note))

        for s in self.prog.symbols:
            if s.name in EXEC_FUNCS:
                ev.targets.append(Target("plt", s.name, f"0x{s.addr:x}"))
        for addr, text in sorted(self.prog.strings.items()):
            if SUSPECT_STR.search(text):
                ev.strings.append({"addr": addr, "text": text})

        ev.gadgets = self._scan_gadgets()

        ev.backdoors = _dedup_backdoor(ev.backdoors)
        for b in ev.backdoors:
            ev.targets.append(Target("backdoor", b.name, f"0x{b.addr:x}"))
        return ev



def _dedup_backdoor(items) -> list:
    best: dict[int, Backdoor] = {}
    for b in items:
        old = best.get(b.addr)
        if old is None or ("调用" in b.note and "调用" not in old.note):
            best[b.addr] = b
    return [best[k] for k in sorted(best)]

def _gadget_cat(asm: str) -> str:
    """按 gadget 用途归类: reg-set / stack-pivot / syscall / call / move / arith / other."""
    if asm in ("int 0x80", "syscall"):
        return "syscall"
    insns = [s.strip() for s in asm.split(";") if s.strip()]
    if not insns:
        return "other"
    mnems = [i.split()[0] for i in insns
             if i.split()[0] not in ("ret", "retf")]
    if not mnems:
        return "other"
    if any(m == "leave" or m.startswith("xchg") for m in mnems):
        return "stack-pivot"
    if all(m == "pop" for m in mnems):
        return "reg-set"
    if any(m == "call" for m in mnems):
        return "call"
    if any(m == "mov" for m in mnems):
        return "move"
    if any(m in ("add", "sub", "xor", "and", "or", "neg", "not",
                 "shl", "shr", "sar", "inc", "dec") for m in mnems):
        return "arith"
    return "other"

def is_large_static(prog, binary_path: str | None, text_limit: int = 0x40000) -> bool:
    """粗略判断是否为"全静态 + 代码区超大"的文件.

    这类文件(如刻意 strip/静态链接的大体积 CTF 题)函数发现会误报爆炸、
    taint 无法用 PLT 符号名识别 source,当前工具链不支持,应快速跳过。
    判据: 是 ELF 且无 .dynsym(全静态) 且 .text 大于 text_limit。
    """
    if not binary_path:
        return False
    try:
        with open(binary_path, "rb") as f:
            if f.read(4) != b"\x7fELF":
                return False
        from elftools.elf.elffile import ELFFile
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            dynsym = elf.get_section_by_name(".dynsym")
            cs = prog.code_section
            if cs is None:
                return False
            text_big = cs.size > text_limit
            return dynsym is None and text_big
    except Exception:
        return False

def _find_libc(binary_path: str | None) -> str | None:
    """在二进制同目录寻找 libc(libc.so* / libc-*.so)。"""
    if not binary_path:
        return None
    d = os.path.dirname(os.path.abspath(binary_path))
    try:
        names = sorted(os.listdir(d))
    except Exception:
        return None
    for fn in names:
        if re.match(r"^libc[\.-]", fn) or fn.startswith("libc.so"):
            p = os.path.join(d, fn)
            if not os.path.isfile(p):
                continue
            try:
                with open(p, "rb") as f:
                    if f.read(4) == b"\x7fELF":
                        return p
            except Exception:
                continue
    return None

def _parse_libc(path: str) -> dict:
    """解析 libc 中 system/puts/__libc_start_main 等符号偏移与 /bin/sh 地址。"""
    info: dict = {"path": path}
    try:
        from elftools.elf.elffile import ELFFile
        with open(path, "rb") as f:
            elf = ELFFile(f)
            want = {"system", "__libc_start_main", "puts", "read", "write",
                    "execve", "printf"}
            dynsym = elf.get_section_by_name(".dynsym")
            symtab = elf.get_section_by_name(".symtab")
            for tab in (dynsym, symtab):
                if tab is None:
                    continue
                for sym in tab.iter_symbols():
                    if sym.name in want and sym.entry.st_value and sym.name not in info:
                        info[sym.name] = sym.entry.st_value
            for s in elf.iter_sections():
                if s.name not in (".rodata", ".data"):
                    continue
                i = s.data().find(b"/bin/sh\x00")
                if i >= 0:
                    info["str_bin_sh"] = s.header.sh_addr + i
                    break
    except Exception as e:
        info["error"] = str(e)
    return info

def _has_stack_realign(body) -> bool:
    """判断函数序言是否含栈对齐(and esp/rsp, -16).

    这类函数若通过 ret 二次返回再触发溢出, 栈基址可能平移, 导致
    buffer->saved-eip 距离与首次不同(常见 8 字节差)。
    """
    for ins in body or []:
        if ins.mnemonic != "and":
            continue
        op = ins.op_str.replace(" ", "").lower()
        if op in ("esp,0xfffffff0", "esp,-16", "rsp,0xfffffff0", "rsp,-16"):
            return True
    return False

def detect_protections(prog, binary_path: str | None) -> dict:
    out = {"PIE": "unknown", "NX": "unknown", "RELRO": "unknown", "Canary": "off"}
    if any("stack_chk" in s.name for s in prog.symbols):
        out["Canary"] = "on"
    if not binary_path:
        return out
    try:
        with open(binary_path, "rb") as f:
            if f.read(4) != b"\x7fELF":
                return out
        from elftools.elf.elffile import ELFFile
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            out["PIE"] = "on" if elf.header.e_type == "ET_DYN" else "off"
            has_stack = False
            relro = False
            bind_now = False
            for seg in elf.iter_segments():
                t = seg.header.p_type
                if t == "PT_GNU_STACK":
                    has_stack = True
                    out["NX"] = "off" if (seg.header.p_flags & 1) else "on"
                elif t == "PT_GNU_RELRO":
                    relro = True
                elif t == "PT_DYNAMIC":
                    for tag in seg.iter_tags():
                        if tag.entry.d_tag == "DT_BIND_NOW":
                            bind_now = True
            out["RELRO"] = "full" if (relro and bind_now) else ("partial" if relro else "none")
            if not has_stack:
                out["NX"] = "on(无显式GNU_STACK)"
    except Exception:
        pass
    return out

def analyze(prog, graph, binary_path: str | None = None) -> Evidence:
    return TaintAnalyzer(prog, graph, binary_path).analyze()

if __name__ == "__main__":
    import sys
    from analysis import CallGraph
    from disasm import Disassembler
    from loader import guess_loader

    p = sys.argv[1]
    prog = guess_loader(p).load()
    g = CallGraph(prog, Disassembler(prog))
    g.build()
    print(analyze(prog, g, p).to_prompt_text())
