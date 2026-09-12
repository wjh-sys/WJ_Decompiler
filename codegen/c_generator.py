from __future__ import annotations

from ir import IRInst, Op
from ir.expressions import BinOp, Const, Expr, Mem, Var
from ir.naming import recover, rename_registers
from .cfg import Structurer

_RET_SIZE = 32

class CGenerator:
    def __init__(self, prog=None) -> None:
        self._prog = prog
        self._sym_map: dict[int, str] = {}
        if prog is not None:
            for s in prog.symbols:
                if s.addr and s.name and s.addr not in self._sym_map:
                    self._sym_map[s.addr] = s.name

    def generate(self, insts: list[IRInst]) -> str:
        insts = self._suppress_stack_args(insts)
        insts, vinfo = recover(insts, self._prog)
        rename_registers(insts)
        body: list[str] = []
        if vinfo is not None and vinfo.types:
            decls = "; ".join(self._decl(n, t) for n, t in sorted(vinfo.types.items()))
            body.append(f"    // 恢复变量: {decls}")
        body += Structurer(insts, self).structurize()
        return "\n".join(body)

    @staticmethod
    def _decl(name: str, typ: str) -> str:
        if "[" in typ:
            base, arr = typ.split("[", 1)
            return f"{base} {name}[{arr}"
        return f"{typ} {name}"

    def _fmt_inst(self, inst: IRInst):
        if inst.op == Op.ASSIGN:
            return self._fmt_assign(inst)
        if inst.op == Op.CALL:
            return self._fmt_call(inst)
        if inst.op == Op.RET:
            return self._fmt_ret(inst)
        if inst.op == Op.UNKN:
            return f"// 未实现: {inst.raw}"
        return None

    def _render_insts(self, insts: list[IRInst]) -> list[str]:
        lines: list[str] = []
        i = 0
        n = len(insts)
        while i < n:
            inst = insts[i]
            nxt = insts[i + 1] if i + 1 < n else None
            n2 = insts[i + 2] if i + 2 < n else None
            if self._is_prologue(inst, nxt, n2):
                lines.append("// 序言")
                i += 3
                continue
            if self._is_epilogue_block(inst, nxt):
                lines.append("// 尾声")
                i += 2
                continue
            ln = self._fmt_inst(inst)
            if ln is not None:
                lines.append(ln)
            i += 1
        return lines

    def _suppress_stack_args(self, insts: list[IRInst]) -> list[IRInst]:
        """清理 CALL 前连续 *(esp+X)=v 的栈传参噪声(已聚合进 CALL.args)."""
        keep = [True] * len(insts)
        j = 0
        while j < len(insts):
            dst = insts[j].dst
            if (insts[j].op == Op.ASSIGN and isinstance(dst, Mem)
                    and _esp_offset(dst.addr) is not None):
                k = j
                while (k < len(insts) and insts[k].op == Op.ASSIGN
                       and isinstance(insts[k].dst, Mem)
                       and _esp_offset(insts[k].dst.addr) is not None):
                    k += 1
                if k < len(insts) and insts[k].op == Op.CALL:
                    for x in range(j, k):
                        keep[x] = False
                j = k
            else:
                j += 1
        return [inst for inst, ok in zip(insts, keep) if ok]

    def _is_prologue(self, a, b, c) -> bool:
        if not (a and b and c):
            return False
        if a.op != Op.ASSIGN or b.op != Op.ASSIGN or c.op != Op.ASSIGN:
            return False
        ok0 = isinstance(a.dst, Var) and isinstance(a.src, Var) and a.dst.name == "ebp" and a.src.name == "esp"
        ok1 = isinstance(b.dst, Var) and b.dst.name == "esp" and isinstance(b.src, BinOp) and b.src.op == "and"
        ok2 = isinstance(c.dst, Var) and c.dst.name == "esp" and isinstance(c.src, BinOp) and c.src.op == "add"
        return ok0 and ok1 and ok2

    def _is_epilogue_block(self, a, b) -> bool:
        if not (a and b):
            return False
        if a.op != Op.ASSIGN or b.op != Op.ASSIGN:
            return False
        ok0 = isinstance(a.dst, Var) and a.dst.name == "esp" and isinstance(a.src, Var) and a.src.name == "ebp"
        ok1 = isinstance(b.dst, Var) and b.dst.name == "ebp"
        return ok0 and ok1

    def _fmt_assign(self, inst: IRInst) -> str:
        dst = self._fmt_expr(inst.dst)
        src = self._fmt_expr(inst.src)
        return f"{dst} = {src};"

    def _call_name(self, addr: int) -> str:
        """调用目标的符号名,无符号则回退到 sub_xxx."""
        name = self._sym_map.get(addr)
        if name:
            return name
        return f"sub_{addr:x}"

    def _fmt_call(self, inst: IRInst) -> str:
        if inst.indirect is not None:
            callee = self._fmt_callee_indirect(inst.indirect)
        else:
            callee = self._call_name(inst.target)
        args = ", ".join(self._fmt_arg(a) for a in inst.args)
        if inst.dst is None:
            return f"{callee}({args});"
        return f"{self._fmt_expr(inst.dst)} = {callee}({args});"

    def _fmt_callee_indirect(self, target: Expr) -> str:
        if isinstance(target, Var):
            return f"(*{target.name})"
        return f"({self._fmt_expr(target)})"

    def _fmt_ret(self, inst: IRInst) -> str:
        if inst.src is None:
            return "return;"
        return f"return {self._fmt_expr(inst.src)};"

    _REL = {"==", "!=", "<", "<=", ">", ">="}

    def _fmt_cond(self, expr: Expr) -> str:
        if isinstance(expr, BinOp) and expr.op in self._REL:
            return f"{self._fmt_expr(expr.lhs)} {expr.op} {self._fmt_expr(expr.rhs)}"
        return self._fmt_expr(expr)

    def _fmt_arg(self, expr: Expr) -> str:
        if isinstance(expr, Const):
            s = self._fmt_str(expr.val)
            if s is not None:
                return s
            if expr.val < 0x100000:
                return str(expr.val)
        return self._fmt_expr(expr)

    def _fmt_str(self, addr: int):
        if self._prog is None:
            return None
        s = self._prog.string_at(addr)
        if s is None:
            return None
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    def _fmt_expr(self, expr: Expr) -> str:
        if isinstance(expr, Var):
            return expr.name
        if isinstance(expr, Const):
            s = self._fmt_str(expr.val)
            if s is not None:
                return s
            return self._fmt_const(expr.val)
        if isinstance(expr, Mem):
            inner = self._fmt_expr(expr.addr)
            return f"*(int*){inner}"
        if isinstance(expr, BinOp):
            if expr.op == "add":
                rhs = self._fmt_add_rhs(expr.rhs)
                return f"{self._fmt_expr(expr.lhs)} + {rhs}"
            if expr.op == "and":
                return f"{self._fmt_expr(expr.lhs)} & {self._fmt_expr(expr.rhs)}"
            op = self._binop_c_symbol(expr.op)
            return f"({self._fmt_expr(expr.lhs)} {op} {self._fmt_expr(expr.rhs)})"
        return "?"

    def _fmt_add_rhs(self, rhs: Expr) -> str:
        if isinstance(rhs, Const):
            return self._fmt_const(rhs.val)
        return self._fmt_expr(rhs)

    def _fmt_const(self, val: int) -> str:
        if val == 0:
            return "0"
        if val > 0x7fffffff:
            s = val - (1 << 32)
            return str(s)
        return hex(val)

    def _binop_c_symbol(self, op: str) -> str:
        return {"add": "+", "sub": "-", "and": "&", "or": "|", "xor": "^",
                "shl": "<<", "shr": ">>", "sar": ">>",
                "==": "==", "!=": "!=", "<": "<", "<=": "<=",
                ">": ">", ">=": ">="}.get(op, op)

def _esp_offset(addr: Expr) -> int | None:
    if isinstance(addr, BinOp) and addr.op == "+":
        if isinstance(addr.lhs, Var) and addr.lhs.name == "esp" and isinstance(addr.rhs, Const):
            return addr.rhs.val
    if isinstance(addr, Var) and addr.name == "esp":
        return 0
    return None