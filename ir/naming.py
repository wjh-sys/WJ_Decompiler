"""变量命名 + 类型恢复(IR 变换 pass).

把栈槽内存访问 *(ebp-X) / *(esp+X) 与编译器临时量 t0 重命名为可读变量,
把 lea/取址得到的栈帧地址重命名为 &slot, 并做轻量类型推断:
字符串字面量/字符串函数实参 -> char*, 被 gets 等写入的缓冲区 -> char[N],
其余默认 int。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .expressions import BinOp, Const, Mem, Var
from .instructions import Op

_BASES = ("ebp", "rbp", "esp", "rsp")
_SLOT_PREFIX = ("var_", "arg_", "stk_", "tmp", "buf_")
_ADDR_PREFIX = "&"
_DEFAULT_BUF = 0x40

_GPR = {
    "eax", "ebx", "ecx", "edx", "esi", "edi",
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "al", "ah", "ax", "bl", "bh", "bx", "cl", "ch", "cx",
    "dl", "dh", "dx", "si", "di",
}


def _is_slot(name: str) -> bool:
    return name.startswith(_SLOT_PREFIX)


def _is_ptr_dst(e) -> bool:
    """赋值目标是否为普通寄存器(非栈基址/栈指针), 用于判定右值可能是取址."""
    return isinstance(e, Var) and e.name not in _BASES


_CHAR_ARG = {
    "puts": (0,), "printf": (0,), "system": (0,), "strlen": (0,),
    "gets": (0,), "fgets": (0,), "strcpy": (0, 1), "strcat": (0, 1),
    "scanf": (1,), "__isoc99_scanf": (1,), "read": (1,), "fread": (0,),
    "execve": (0,),
}

@dataclass
class VarInfo:
    names: dict = field(default_factory=dict)
    types: dict = field(default_factory=dict)

def _slot_name(base: str, off: int) -> str:
    if base in ("ebp", "rbp"):
        if off < 0:
            return f"var_{(-off):x}"
        if base == "rbp":
            return f"arg_{(off - 0x10) // 8}" if off >= 0x10 else f"var_{off:x}"
        return f"arg_{(off - 8) // 4}" if off >= 8 else f"var_{off:x}"
    return f"stk_{off:x}"

def _key(addr):
    if isinstance(addr, Var) and addr.name in _BASES:
        return (addr.name, 0)
    if (isinstance(addr, BinOp) and addr.op in ("+", "-")
            and isinstance(addr.lhs, Var) and addr.lhs.name in _BASES
            and isinstance(addr.rhs, Const)):
        return (addr.lhs.name, addr.rhs.val if addr.op == "+" else -addr.rhs.val)
    return None

class _Namer:
    def __init__(self, prog) -> None:
        self.prog = prog
        self.map: dict = {}
        self.key_of: dict = {}
        self.types: dict = {}
        self.buffers: set = set()
        self.off_used: dict = {}

    def intern(self, key, size: int = 32) -> str:
        base, off = key
        self.off_used.setdefault(base, set()).add(off)
        nm = self.map.get(key)
        if nm is None:
            nm = _slot_name(base, off)
            self.map[key] = nm
            self.key_of[nm] = key
            self.types.setdefault(nm, "int")
        return nm

    def mark_buffer(self, name: str) -> None:
        self.buffers.add(name)

    def tmp(self, raw: str) -> str:
        nm = "tmp" + raw[1:]
        self.types.setdefault(nm, "int")
        return nm

    def finalize_buffers(self) -> None:
        for nm in self.buffers:
            key = self.key_of.get(nm)
            if key is None:
                continue
            base, off = key
            higher = [o for o in self.off_used.get(base, ()) if o > off]
            size = (min(higher) - off) if higher else _DEFAULT_BUF
            self.types[nm] = f"char[{hex(max(1, min(size, 0x1000)))}]"

def _rw(e, namer: _Namer, addr_of: bool = False):
    if isinstance(e, Mem):
        k = _key(e.addr)
        if k is not None:
            return Var(namer.intern(k, e.size), e.size)
        e.addr = _rw(e.addr, namer)
        return e
    if isinstance(e, BinOp):
        if addr_of:
            k = _key(e)
            if k is not None:
                return Var(_ADDR_PREFIX + namer.intern(k, e.size), e.size)
        e.lhs = _rw(e.lhs, namer)
        e.rhs = _rw(e.rhs, namer)
        return e
    if isinstance(e, Var):
        if len(e.name) > 1 and e.name[0] == "t" and e.name[1:].isdigit():
            return Var(namer.tmp(e.name), e.size)
        return e
    return e

def _sym_map(prog) -> dict:
    m: dict = {}
    if prog is not None:
        for s in prog.symbols:
            if s.addr and s.name and s.addr not in m:
                m[s.addr] = s.name
    return m

def _char_indices(name: str, args, prog) -> tuple:
    idxs = _CHAR_ARG.get(name)
    if not idxs:
        return ()
    if name in ("scanf", "__isoc99_scanf") and prog is not None and args:
        fmt = args[0]
        if isinstance(fmt, Const) and "%s" not in (prog.string_at(fmt.val) or ""):
            return ()
    return idxs


def _strip_addr(e, buffers: set):
    if isinstance(e, Var) and e.name.startswith(_ADDR_PREFIX) and e.name[1:] in buffers:
        return Var(e.name[1:], e.size)
    if isinstance(e, BinOp):
        e.lhs = _strip_addr(e.lhs, buffers)
        e.rhs = _strip_addr(e.rhs, buffers)
        return e
    if isinstance(e, Mem):
        e.addr = _strip_addr(e.addr, buffers)
        return e
    return e


def _infer_types(insts, namer: _Namer, prog) -> None:
    sym = _sym_map(prog)
    last_def: dict = {}
    for inst in insts:
        if inst.op == Op.ASSIGN and isinstance(inst.dst, Var):
            last_def[inst.dst.name] = inst.src
            if (isinstance(inst.src, Const) and _is_slot(inst.dst.name)
                    and prog is not None
                    and prog.string_at(inst.src.val) is not None):
                namer.types[inst.dst.name] = "char*"
        if inst.op == Op.CALL:
            for idx in _char_indices(sym.get(inst.target), inst.args, prog):
                if idx >= len(inst.args):
                    continue
                arg = inst.args[idx]
                if isinstance(arg, Var) and arg.name in last_def:
                    arg = last_def[arg.name]
                if not isinstance(arg, Var):
                    continue
                if arg.name.startswith(_ADDR_PREFIX) and _is_slot(arg.name[1:]):
                    namer.mark_buffer(arg.name[1:])
                elif _is_slot(arg.name):
                    namer.types[arg.name] = "char*"


def recover(insts, prog=None):
    """就地重写 IRInst 中的栈槽/临时量表达式, 返回 (insts, VarInfo)."""
    namer = _Namer(prog)
    for inst in insts:
        ptr_dst = _is_ptr_dst(inst.dst)
        if inst.dst is not None:
            inst.dst = _rw(inst.dst, namer)
        if inst.src is not None:
            inst.src = _rw(inst.src, namer, addr_of=ptr_dst)
        if inst.args:
            inst.args = [_rw(a, namer) for a in inst.args]
        if inst.cond is not None:
            inst.cond = _rw(inst.cond, namer)
        if inst.indirect is not None:
            inst.indirect = _rw(inst.indirect, namer)
    _infer_types(insts, namer, prog)
    namer.finalize_buffers()
    if namer.buffers:
        for inst in insts:
            if inst.dst is not None:
                inst.dst = _strip_addr(inst.dst, namer.buffers)
            if inst.src is not None:
                inst.src = _strip_addr(inst.src, namer.buffers)
            if inst.args:
                inst.args = [_strip_addr(a, namer.buffers) for a in inst.args]
            if inst.cond is not None:
                inst.cond = _strip_addr(inst.cond, namer.buffers)
            if inst.indirect is not None:
                inst.indirect = _strip_addr(inst.indirect, namer.buffers)
    return insts, VarInfo(names=dict(namer.map), types=dict(namer.types))


def _sub_reg(e, cur: dict):
    if isinstance(e, Var):
        nm = cur.get(e.name)
        return Var(nm, e.size) if nm else e
    if isinstance(e, BinOp):
        e.lhs = _sub_reg(e.lhs, cur)
        e.rhs = _sub_reg(e.rhs, cur)
        return e
    if isinstance(e, Mem):
        e.addr = _sub_reg(e.addr, cur)
        return e
    return e


def rename_registers(insts):
    """寄存器版本化重命名(基本块内 SSA 式线性编号).

    单个基本块内每次定义通用寄存器生成中性变量名(v1/v2/...), 后续使用引用
    最近的版本; 跨块边界(含跳转目标)重置映射, 使跨块使用的寄存器保留原名
    (不臆造版本), 从而避免多前驱合并点上的错误命名。
    栈指针(esp/ebp/rsp/rbp)不重命名, 以保留栈帧语义与序言/尾声折叠。
    返回 {变量名: 寄存器#序号} 映射(供输出注释追溯来源)。
    """
    regmap: dict = {}
    if not insts:
        return regmap
    leaders = {insts[0].addr}
    for idx, inst in enumerate(insts):
        if inst.op in (Op.BRANCH, Op.RET) and idx + 1 < len(insts):
            leaders.add(insts[idx + 1].addr)
        if inst.op == Op.BRANCH and inst.target is not None:
            leaders.add(inst.target)
    cur: dict = {}
    count: dict = {}
    seq = 0
    last = None
    for inst in insts:
        a = inst.addr
        if a in leaders and a != last:
            cur = {}
        last = a
        if inst.src is not None:
            inst.src = _sub_reg(inst.src, cur)
        if inst.args:
            inst.args = [_sub_reg(x, cur) for x in inst.args]
        if inst.cond is not None:
            inst.cond = _sub_reg(inst.cond, cur)
        if inst.indirect is not None:
            inst.indirect = _sub_reg(inst.indirect, cur)
        if inst.dst is None:
            continue
        if isinstance(inst.dst, Var) and inst.dst.name in _GPR:
            reg = inst.dst.name
            count[reg] = count.get(reg, 0) + 1
            seq += 1
            name = f"v{seq}"
            cur[reg] = name
            regmap[name] = f"{reg}#{count[reg]}"
            inst.dst = Var(name, inst.dst.size)
        else:
            inst.dst = _sub_reg(inst.dst, cur)
    return regmap
