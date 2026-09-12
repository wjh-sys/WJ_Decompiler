from __future__ import annotations

from disasm import Disassembler, Instruction
from .expressions import BinOp, Const, Expr, Mem, Var
from .instructions import IRInst, Op

REG_SIZE = {
    "al": 8, "ah": 8, "bl": 8, "bh": 8, "cl": 8, "ch": 8, "dl": 8, "dh": 8,
    "ax": 16, "bx": 16, "cx": 16, "dx": 16, "si": 16, "di": 16, "bp": 16, "sp": 16,
    "eax": 32, "ebx": 32, "ecx": 32, "edx": 32, "esi": 32, "edi": 32, "ebp": 32, "esp": 32,
}

_JCC = {
    "je": "==", "jz": "==",
    "jne": "!=", "jnz": "!=",
    "jg": ">", "jnle": ">",
    "jge": ">=", "jnl": ">=",
    "jl": "<", "jnge": "<",
    "jle": "<=", "jng": "<=",
    "ja": ">", "jnbe": ">",
    "jae": ">=", "jnb": ">=", "jnc": ">=",
    "jb": "<", "jnae": "<", "jc": "<",
    "jbe": "<=", "jna": "<=",
}

class Lifter:
    def __init__(self, dis: Disassembler):
        self.dis = dis
        self._pending_args: dict[int, Expr] = {}
        self._last_cmp = None
        self._last_alu = None

    def lift_text(self) -> list[IRInst]:
        return self.lift(self.dis.decode_text())

    def lift(self, instrs: list[Instruction]) -> list[IRInst]:
        out: list[IRInst] = []
        for ins in instrs:
            start = len(out)
            handled = self._dispatch(ins, out)
            if not handled:
                out.append(IRInst(Op.UNKN, raw=str(ins)))
            for k in range(start, len(out)):
                if out[k].addr == 0:
                    out[k].addr = ins.addr
        return out

    def _dispatch(self, ins: Instruction, out: list[IRInst]) -> bool:
        m = ins.mnemonic
        ops = self._parse_ops(ins.op_str)
        if m == "mov":
            return self._mov(ops, out)
        if m == "lea":
            return self._lea(ops, out)
        if m in ("add", "sub", "and", "or", "xor", "shl", "shr", "sar"):
            return self._alu(m, ops, out)
        if m == "call":
            return self._call(ops, out)
        if m == "ret" or (m.startswith("rep") and m.endswith("ret")):
            out.append(IRInst(Op.RET, src=Var("eax", 32)))
            self._pending_args.clear()
            self._last_cmp = self._last_alu = None
            return True
        if m == "leave":
            out.append(IRInst(Op.ASSIGN, dst=Var("esp", 32), src=Var("ebp", 32)))
            out.append(IRInst(Op.ASSIGN, dst=Var("ebp", 32), src=Mem(Var("esp", 32), 32)))
            return True
        if m in ("cmp", "test"):
            return self._cmp(m, ops)
        if m == "jmp":
            return self._branch(ops, out, None)
        if m.startswith("j") and len(ops) == 1:
            return self._branch(ops, out, m)
        if m in ("push", "pop", "nop", "hlt", "int"):
            return True
        return False

    def _mov(self, ops, out) -> bool:
        dst, src = ops[0], ops[1]
        if isinstance(dst, Mem) and isinstance(src, Mem):
            tmp = Var("t0", src.size)
            out.append(IRInst(Op.ASSIGN, dst=tmp, src=src))
            out.append(IRInst(Op.ASSIGN, dst=dst, src=tmp))
            return True
        out.append(IRInst(Op.ASSIGN, dst=dst, src=src))
        self._maybe_record_arg(dst, src)
        return True

    def _lea(self, ops, out) -> bool:
        dst, mem = ops[0], ops[1]
        if isinstance(mem, Mem):
            out.append(IRInst(Op.ASSIGN, dst=dst, src=mem.addr))
            self._maybe_record_arg(dst, mem.addr)
            return True
        return False

    def _alu(self, op, ops, out) -> bool:
        if len(ops) != 2:
            return False
        dst, src = ops[0], ops[1]
        size = getattr(dst, "size", 32)
        result = BinOp(op, dst, src, size)
        out.append(IRInst(Op.ASSIGN, dst=dst, src=result))
        if op == "sub":
            self._last_cmp = ("sub", dst, src)
            self._last_alu = None
        else:
            self._last_alu = result
            self._last_cmp = None
        return True

    def _call(self, ops, out) -> bool:
        if not ops:
            return False
        target = ops[0]
        args = [self._pending_args[o] for o in sorted(self._pending_args)]
        if isinstance(target, Const):
            out.append(IRInst(Op.CALL, dst=Var("eax", 32), target=target.val, args=args))
        else:
            out.append(IRInst(Op.CALL, dst=Var("eax", 32), args=args, indirect=target))
        self._pending_args.clear()
        self._last_cmp = self._last_alu = None
        return True

    def _maybe_record_arg(self, dst: Expr, src: Expr) -> None:
        if isinstance(dst, Mem) and isinstance(dst.addr, BinOp):
            a = dst.addr
            if a.op == "+" and isinstance(a.lhs, Var) and a.lhs.name == "esp" and isinstance(a.rhs, Const):
                self._pending_args[a.rhs.val] = src
            elif a.op == "+" and isinstance(a.lhs, Var) and a.lhs.name == "esp" and isinstance(a.rhs, BinOp):
                pass
        if isinstance(dst, Mem) and isinstance(dst.addr, Var) and dst.addr.name == "esp":
            self._pending_args[0] = src

    def _cmp(self, m, ops) -> bool:
        if len(ops) != 2:
            return False
        self._last_cmp = (m, ops[0], ops[1])
        self._last_alu = None
        return True

    def _branch(self, ops, out, mnem) -> bool:
        if not ops or not isinstance(ops[0], Const):
            return False
        cond = None
        if mnem is not None:
            cond = self._condition(mnem) or Var(mnem, 1)
        out.append(IRInst(Op.BRANCH, target=ops[0].val, cond=cond))
        return True

    def _condition(self, mnem) -> Expr | None:
        rel = _JCC.get(mnem)
        if rel is None:
            return None
        if self._last_cmp is not None:
            kind, lhs, rhs = self._last_cmp
            if kind == "test" and rhs == lhs:
                rhs = Const(0, 32)
            return BinOp(rel, lhs, rhs, 32)
        if self._last_alu is not None:
            return BinOp(rel, self._last_alu, Const(0, 32), 32)
        return None

    def _parse_ops(self, op_str: str) -> list[Expr]:
        op_str = op_str.strip()
        if not op_str:
            return []
        parts = [p.strip() for p in _split_top_level(op_str, ",")]
        return [self._parse_one(p) for p in parts]

    def _parse_one(self, text: str) -> Expr:
        text = text.strip()
        import re
        text = re.sub(r'^(?:byte|word|dword|qword|xword)\s+ptr\s+', '', text)
        text = re.sub(r'^(?:byte|word|dword|qword)\s+', '', text)
        if text.startswith("[") and text.endswith("]"):
            inner = text[1:-1].strip()
            return Mem(self._parse_one(inner), 32)
        if text in REG_SIZE:
            return Var(text, REG_SIZE[text])
        try:
            v = int(text, 0)
            return Const(v, 32)
        except ValueError:
            pass
        for op_sym in ("+", "-", "*"):
            idx = _find_top_level(text, op_sym)
            if idx > 0:
                lhs = self._parse_one(text[:idx])
                rhs = self._parse_one(text[idx + 1:])
                return BinOp(op_sym, lhs, rhs, 32)
        if ":" in text:
            return Var("segs", 16)
        return Var(text, 32)

def _split_top_level(text: str, sep: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for c in text:
        if c == "[":
            depth += 1
            cur += c
        elif c == "]":
            depth -= 1
            cur += c
        elif c == sep and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += c
    if cur:
        out.append(cur)
    return out

def _find_top_level(text: str, sym: str) -> int:
    depth = 0
    i = 0
    while i < len(text):
        c = text[i]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
        elif depth == 0 and c == sym:
            if sym == "-" and i > 0 and text[i - 1] in "+-":
                i += 1
                continue
            return i
        i += 1
    return -1