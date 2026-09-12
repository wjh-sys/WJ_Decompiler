"""CFG 构建 + 控制结构恢复.

把 Lifter 产出的平坦 IRInst 序列(以 label + if/goto 表达控制流)切分为
基本块, 识别 if / if-else / while / do-while 结构并折叠为结构化伪代码;
无法安全识别的跳转回退为 `L_xxx: / goto`, 保证不会错译。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ir import BinOp, IRInst, Op

_INDENT = "    "
_REL_NEG = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}

@dataclass
class Block:
    start: int
    insts: list = field(default_factory=list)

    @property
    def term(self):
        last = self.insts[-1] if self.insts else None
        if last is not None and last.op in (Op.BRANCH, Op.RET):
            return last
        return None

    def body(self, drop_term: bool = True):
        if drop_term and self.term is not None and self.term.op == Op.BRANCH:
            return self.insts[:-1]
        return self.insts

def build_blocks(insts: list[IRInst]):
    if not insts:
        return {}, []
    leaders = {insts[0].addr}
    for idx, inst in enumerate(insts):
        if inst.op in (Op.BRANCH, Op.RET) and idx + 1 < len(insts):
            leaders.add(insts[idx + 1].addr)
        if inst.op == Op.BRANCH and inst.target is not None:
            leaders.add(inst.target)
    blocks, cur = {}, None
    for inst in insts:
        if inst.addr in leaders:
            cur = blocks.setdefault(inst.addr, Block(inst.addr))
        elif cur is None:
            cur = blocks.setdefault(inst.addr, Block(inst.addr))
        cur.insts.append(inst)
    return blocks, sorted(blocks)

class Structurer:
    def __init__(self, insts: list[IRInst], gen) -> None:
        self.gen = gen
        self.blocks, self.order = build_blocks(insts)
        self.index = {a: i for i, a in enumerate(self.order)}
        self.preds = {a: set() for a in self.order}
        self.emitted: set[int] = set()
        self.lines: list[str] = []
        self._build_preds()
        self._prep_returns()

    def structurize(self) -> list[str]:
        self._region(0, len(self.order), 0)
        return self._fix_labels(self.lines)

    def _build_preds(self) -> None:
        for i, start in enumerate(self.order):
            t = self.blocks[start].term
            if t is None:
                if i + 1 < len(self.order):
                    self.preds[self.order[i + 1]].add(start)
                continue
            if t.op == Op.RET:
                continue
            if t.target in self.preds:
                self.preds[t.target].add(start)
            if t.cond is not None and i + 1 < len(self.order):
                self.preds[self.order[i + 1]].add(start)

    def _prep_returns(self) -> None:
        """识别"仅含一条 return"的块; 若其全部前驱都能就地返回(显式分支跳来,
        或上一块落空进入), 则把该 return 内联到各前驱, 消除多分支共享 return
        块残留的 L_xxx: 标签。"""
        self.ret_only: set = {s for s, b in self.blocks.items()
                              if len(b.insts) == 1 and b.insts[0].op == Op.RET}
        self.fall_into: set = {self.order[i] for i in range(1, len(self.order))
                               if self._falls_into(self.order[i - 1], self.order[i])}
        self.inline_ret: set = set()
        for start in self.ret_only:
            preds = self.preds.get(start) or set()
            if preds and all(self._branch_edge(p, start) or self._falls_into(p, start)
                             for p in preds):
                self.inline_ret.add(start)

    def _branch_edge(self, pstart: int, tstart: int) -> bool:
        t = self.blocks[pstart].term
        return t is not None and t.op == Op.BRANCH and t.target == tstart

    def _falls_into(self, pstart: int, tstart: int) -> bool:
        """pstart 是否直接落空进入紧邻的 tstart(无跳转或无条件的条件跳转)。"""
        if self.index.get(pstart, -1) + 1 != self.index.get(tstart, -2):
            return False
        t = self.blocks[pstart].term
        return t is None or (t.op == Op.BRANCH and t.cond is not None)

    def _ret_stmt(self, start: int) -> str:
        return self.gen._fmt_ret(self.blocks[start].insts[-1])

    def _ind(self, depth: int) -> str:
        return _INDENT * (depth + 1)

    def _emit_insts(self, insts, depth: int) -> None:
        for ln in self.gen._render_insts(insts):
            self.lines.append(self._ind(depth) + ln)

    def _emit_block(self, start: int, depth: int, drop_term: bool = True) -> None:
        blk = self.blocks[start]
        if blk.start in self.emitted:
            return
        self.emitted.add(blk.start)
        self.lines.append(f"@@L@@{self._ind(depth)}{start:x}")
        self._emit_insts(blk.body(drop_term), depth)

    def _tail_name(self, target) -> str:
        fn = getattr(self.gen, "_call_name", None)
        if callable(fn) and target is not None:
            try:
                return fn(target)
            except Exception:
                pass
        return f"sub_{target:x}" if target is not None else "?"

    def _push_line(self, line: str) -> None:
        """追加一行; 被标签行隔开的相同尾调用注释也只保留一条."""
        for prev in reversed(self.lines):
            if prev.startswith("@@L@@"):
                continue
            if prev == line:
                return
            break
        self.lines.append(line)

    def _emit_goto(self, target, depth: int) -> None:
        if target is None:
            return
        ind = self._ind(depth)
        if target in self.inline_ret:
            self._push_line(f"{ind}{self._ret_stmt(target)}")
        elif target in self.blocks:
            self._push_line(f"{ind}goto L_{target:x};")
        else:
            self._push_line(f"{ind}// 尾调用 -> {self._tail_name(target)}(...);")

    def _emit_cond_goto(self, expr, target, depth: int) -> None:
        """无法折叠为 if/while 的条件分支: 保留为跳转, 不丢失控制流."""
        ind = self._ind(depth)
        cond = self.gen._fmt_cond(expr)
        if target in self.inline_ret:
            self._push_line(f"{ind}if ({cond}) {self._ret_stmt(target)}")
            return
        if target is not None and target in self.blocks:
            self._push_line(f"{ind}if ({cond}) goto L_{target:x};")
        else:
            self._push_line(f"{ind}if ({cond}) return {self._tail_name(target)}(...); // 尾调用")

    def _cond_str(self, expr, negate: bool = False) -> str:
        if not negate:
            return self.gen._fmt_cond(expr)
        if isinstance(expr, BinOp) and expr.op in _REL_NEG:
            return self.gen._fmt_cond(BinOp(_REL_NEG[expr.op], expr.lhs, expr.rhs, expr.size))
        return f"!({self.gen._fmt_expr(expr)})"

    def _region(self, i: int, stop: int, depth: int) -> int:
        while i < stop and i < len(self.order):
            start = self.order[i]
            if start in self.emitted:
                i += 1
                continue
            if start in self.inline_ret:
                if start in self.fall_into:
                    # 从上一块落空进入: 就地输出 return(不输出标签)
                    self.lines.append(f"{self._ind(depth)}{self._ret_stmt(start)}")
                # 其余入边已在各分支处内联为 return, 此处不再输出标签
                self.emitted.add(start)
                i += 1
                continue
            blk = self.blocks[start]
            loop = self._loop_at(i, stop)
            if loop is not None:
                i = self._emit_loop(loop, depth)
                continue
            self._emit_block(start, depth)
            term = blk.term
            if term is None or term.op == Op.RET:
                i += 1
                continue
            if term.cond is None:
                if term.target is not None and self.index.get(term.target) != i + 1:
                    self._emit_goto(term.target, depth)
                i += 1
                continue
            i = self._emit_cond(blk, i, stop, depth)
        return i

    def _emit_cond(self, blk, i: int, stop: int, depth: int) -> int:
        term = blk.term
        ti = self.index.get(term.target)
        fi = i + 1
        if ti is not None and ti == fi:
            self._emit_block(blk.start, depth)
            return i + 1
        if ti is not None and ti > fi and self._straight(fi, ti):
            self._emit_block(blk.start, depth)
            self.lines.append(f"{self._ind(depth)}if ({self._cond_str(term.cond, negate=True)}) {{")
            self._region(fi, ti, depth + 1)
            self.lines.append(f"{self._ind(depth)}}}")
            return ti
        x = fi
        while x < len(self.order) and x < stop:
            t2 = self.blocks[self.order[x]].term
            if t2 is not None and t2.op == Op.BRANCH and t2.cond is None:
                ji = self.index.get(t2.target)
                if (ji is not None and x + 1 == ti and ji > ti
                        and self._straight(ti, ji)):
                    self._emit_block(blk.start, depth)
                    self.lines.append(f"{self._ind(depth)}if ({self._cond_str(term.cond, negate=True)}) {{")
                    self._region(fi, x, depth + 1)
                    self._emit_block(self.order[x], depth + 1)
                    self.lines.append(f"{self._ind(depth)}}} else {{")
                    self._region(ti, ji, depth + 1)
                    self.lines.append(f"{self._ind(depth)}}}")
                    return ji
                break
            x += 1
        self._emit_block(blk.start, depth)
        self._emit_cond_goto(term.cond, term.target, depth)
        return i + 1

    def _straight(self, lo: int, hi: int) -> bool:
        if lo >= hi:
            return False
        for j in range(lo, hi):
            t = self.blocks[self.order[j]].term
            if t is None:
                continue
            if t.op == Op.RET:
                return False
            ti = self.index.get(t.target)
            if t.cond is None:
                if ti != j + 1:
                    return False
            elif ti is None or not (lo <= ti < hi):
                return False
        for j in range(lo + 1, hi):
            for p in self.preds.get(self.order[j], ()):
                if not (lo <= self.index[p] < hi):
                    return False
        return True

    def _loop_at(self, i: int, stop: int):
        blk = self.blocks[self.order[i]]
        term = blk.term
        h = blk.start
        if term is None or term.op != Op.BRANCH:
            return None
        if term.cond is not None and term.target == h:
            return ("do", i)
        if term.cond is None and term.target is not None:
            # 旋转式 while: 入口先 jmp 到循环底部条件块, 条件成立再跳回循环体首块
            hh = self.index.get(term.target)
            if hh is not None and i + 1 < hh < stop and self._rot_at(i, hh):
                return ("rot", i, hh)
        back = [j for j in range(i, min(stop, len(self.order)))
                if self.blocks[self.order[j]].term is not None
                and self.blocks[self.order[j]].term.target == h and j > i]
        if len(back) != 1:
            return None
        if term.cond is None:
            return None
        ti = self.index.get(term.target)
        if ti is None or ti <= i or not (i <= back[0] < ti):
            return None
        if self.blocks[self.order[back[0]]].term.cond is not None:
            return None
        return ("while", i, ti, back[0])

    def _rot_at(self, i: int, hh: int) -> bool:
        """条件块(底部)的条件跳转目标是循环体首块(i+1), 且循环体内无
        对外跳转/无 return 时, 判定为旋转式 while。"""
        cterm = self.blocks[self.order[hh]].term
        if cterm is None or cterm.op != Op.BRANCH or cterm.cond is None:
            return False
        if self.index.get(cterm.target) != i + 1:
            return False
        lo, hi = i + 1, hh + 1
        for j in range(lo, hi):
            t = self.blocks[self.order[j]].term
            if t is None:
                continue
            if t.op == Op.RET:
                return False
            if t.cond is None:
                if self.index.get(t.target) != j + 1:
                    return False
            else:
                ti = self.index.get(t.target)
                if ti is None or not (lo <= ti < hi):
                    return False
        for j in range(lo, hi):
            for p in self.preds.get(self.order[j], ()):
                pi = self.index[p]
                if not (lo <= pi < hi or pi == i):
                    return False
        return True

    def _emit_loop(self, loop, depth: int) -> int:
        ind = self._ind(depth)
        if loop[0] == "do":
            i = loop[1]
            blk = self.blocks[self.order[i]]
            self.emitted.add(blk.start)
            self.lines.append(f"@@L@@{ind}{blk.start:x}")
            self.lines.append(f"{ind}do {{")
            self._emit_insts(blk.body(True), depth + 1)
            self.lines.append(f"{ind}}} while ({self.gen._fmt_cond(blk.term.cond)});")
            return i + 1
        if loop[0] == "rot":
            _, i, hh = loop
            blk = self.blocks[self.order[i]]
            self.emitted.add(blk.start)
            self.lines.append(f"@@L@@{ind}{blk.start:x}")
            self._emit_insts(blk.body(True), depth)
            cblk = self.blocks[self.order[hh]]
            self.emitted.add(cblk.start)
            self.lines.append(f"{ind}while ({self.gen._fmt_cond(cblk.term.cond)}) {{")
            if hh > i + 1:
                self._region(i + 1, hh, depth + 1)
            self._emit_insts(cblk.body(True), depth + 1)
            self.lines.append(f"{ind}}}")
            return hh + 1
        _, i, ti, b = loop
        blk = self.blocks[self.order[i]]
        self.emitted.add(blk.start)
        self.lines.append(f"@@L@@{ind}{blk.start:x}")
        self.lines.append(f"{ind}while ({self._cond_str(blk.term.cond, negate=True)}) {{")
        self._emit_insts(blk.body(True), depth + 1)
        if b > i + 1:
            self._region(i + 1, b, depth + 1)
        self._emit_block(self.order[b], depth + 1)
        self.lines.append(f"{ind}}}")
        return ti

    def _fix_labels(self, lines: list[str]) -> list[str]:
        markers = {int(m.group(2), 16) for ln in lines
                   if (m := re.match(r"@@L@@( *)([0-9a-fA-F]+)$", ln))}
        used = {int(m.group(1), 16) for ln in lines
                if (m := re.search(r"goto L_([0-9a-fA-F]+);", ln))}
        out = []
        for ln in lines:
            m = re.match(r"@@L@@( *)([0-9a-fA-F]+)$", ln)
            if m:
                addr = int(m.group(2), 16)
                if addr in used:
                    out.append(f"{m.group(1)}L_{addr:x}:")
                continue
            g = re.match(r"( *)goto L_([0-9a-fA-F]+);$", ln)
            if g and int(g.group(2), 16) not in markers:
                # 目标不在本函数体内(如尾跳到另一函数), 无法定义标签
                out.append(f"{g.group(1)}// goto L_{g.group(2)};  (目标在函数体外, 疑似尾调用)")
                continue
            out.append(ln)
        return out
