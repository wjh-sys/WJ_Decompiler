from __future__ import annotations

from ir import IRInst, Op
from ir.expressions import BinOp, Const, Expr, Mem, Var

_RET_SIZE = 32

class CGenerator:
    def __init__(self, prog=None) -> None:
        self._suppress_offsets: set[int] = set()
        self._prog = prog
        self._sym_map: dict[int, str] = {}
        if prog is not None:
            for s in prog.symbols:
                if s.addr and s.name and s.addr not in self._sym_map:
                    self._sym_map[s.addr] = s.name

    def generate(self, insts: list[IRInst]) -> str:
        lines: list[str] = []
        labels = {x.target for x in insts if x.op == Op.BRANCH and x.target}
        i = 0
        n = len(insts)
        while i < n:
            inst = insts[i]
            nxt = insts[i + 1] if i + 1 < n else None
            n2 = insts[i + 2] if i + 2 < n else None

            if inst.addr and inst.addr in labels:
                lines.append(f"L_{inst.addr:x}:")

            if self._is_prologue(inst, nxt, n2):
                lines.append("    // 序言")
                i += 3
                continue
            if self._is_epilogue_block(inst, nxt):
                lines.append("    // 尾声")
                i += 2
                continue

            if inst.op == Op.ASSIGN:
                if self._should_suppress(inst):
                    i += 1
                    continue
                # 栈参数抑制(前瞻): 若从当前位置起是连续 esp 栈赋值,且其后
                # 紧跟 CALL,则这些赋值是栈传参实现细节(已聚合进 CALL.args),
                # 整体跳过只输出 CALL
                hit = self._skip_until_call(insts, i)
                if hit is not None:
                    nxt_call, nxt_call_index = hit
                    lines.append("    " + self._fmt_call(nxt_call))
                    i = nxt_call_index + 1
                    continue
                lines.append("    " + self._fmt_assign(inst))
            elif inst.op == Op.CALL:
                lines.append("    " + self._fmt_call(inst))
            elif inst.op == Op.RET:
                lines.append("    " + self._fmt_ret(inst))
            elif inst.op == Op.CMP:
                pass
            elif inst.op == Op.BRANCH:
                tgt = f"L_{inst.target:x}" if inst.target else "?"
                if isinstance(inst.cond, Var):
                    lines.append(f"    // IF <flags from {inst.cond.name}> goto {tgt};")
                elif inst.cond is not None:
                    lines.append(f"    if ({self._fmt_cond(inst.cond)}) goto {tgt};")
                else:
                    lines.append(f"    goto {tgt};")
            elif inst.op == Op.UNKN:
                lines.append(f"    // 未实现: {inst.raw}")
            i += 1
        return "\n".join(lines)

    def _skip_until_call(self, insts: list[IRInst], start: int):
        """从 start 起若为连续 *(esp+X)=v 赋值且其后紧跟 CALL,返回
        (call, index);否则返回 None. 被跳过的偏移记入 _suppress_offsets."""
        j = start
        offs = set()
        while j < len(insts) and insts[j].op == Op.ASSIGN:
            off = _esp_offset(insts[j].dst.addr) if isinstance(insts[j].dst, Mem) else None
            if off is None:
                break
            offs.add(off)
            j += 1
        if not offs or j >= len(insts) or insts[j].op != Op.CALL:
            return None
        self._suppress_offsets |= offs
        return insts[j], j

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

    def _should_suppress(self, inst: IRInst) -> bool:
        dst = inst.dst
        if not isinstance(dst, Mem):
            return False
        off = _esp_offset(dst.addr)
        if off is None:
            return False
        return off in self._suppress_offsets

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