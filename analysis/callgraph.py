from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from codegen import CGenerator
from disasm import Disassembler
from ir import Lifter, Op

from .function_finder import FunctionFinder, decode_function_body

@dataclass
class CallTarget:
    callee: int
    args: list[str] = field(default_factory=list)
    is_external: bool = False

@dataclass
class FunctionNode:
    addr: int
    name: str
    c_code: str
    callees: list[CallTarget] = field(default_factory=list)
    depth: int = 0
    is_external: bool = False

class CallGraph:
    def __init__(self, prog, dis: Disassembler):
        self.prog = prog
        self.dis = dis
        self._finder = FunctionFinder(prog, dis)
        self._gen = CGenerator(prog)
        self._edges: dict[int, list[CallTarget]] = {}
        self._func_addrs: set[int] = set()
        self._name_cache: dict[int, str] = {}
        for s in prog.symbols:
            if s.addr not in self._name_cache:
                self._name_cache[s.addr] = s.name

    def build(self) -> None:
        self._func_addrs = set(self._finder.find())
        for addr in self._func_addrs:
            self._edges[addr] = self._collect_call_targets(addr)

    def _collect_call_targets(self, addr: int) -> list[CallTarget]:
        ir = Lifter(self.dis).lift(self._decode_body(addr))
        targets: list[CallTarget] = []
        for inst in ir:
            if inst.op != Op.CALL:
                continue
            if inst.target is None:
                continue
            targets.append(CallTarget(
                callee=inst.target or 0,
                args=[str(a) for a in inst.args],
                is_external=inst.target not in self._func_addrs,
            ))
        return targets

    def _decode_body(self, addr: int):
        return decode_function_body(self.dis, self.prog, addr, self._func_addrs)

    def _decompile(self, addr: int) -> str:
        ir = Lifter(self.dis).lift(self._decode_body(addr))
        return self._gen.generate(ir)

    def resolve_name(self, addr: int) -> str:
        name = self._name_cache.get(addr)
        if name:
            return name
        return f"sub_{addr:x}"

    def expand(self, root: int, max_depth: int = 3, max_nodes: int = 20) -> list[FunctionNode]:
        if root not in self._edges:
            return []
        nodes: list[FunctionNode] = []
        seen: set[int] = set()
        queue: deque = deque([(root, 0)])
        while queue and len(nodes) < max_nodes:
            addr, depth = queue.popleft()
            if addr in seen:
                continue
            seen.add(addr)
            is_external = addr not in self._func_addrs
            nodes.append(FunctionNode(
                addr=addr,
                name=self.resolve_name(addr),
                c_code="" if is_external else self._decompile(addr),
                callees=self._edges.get(addr, []),
                depth=depth,
                is_external=is_external,
            ))
            if depth >= max_depth or is_external:
                continue
            for ct in nodes[-1].callees:
                if ct.callee not in seen:
                    queue.append((ct.callee, depth + 1))
        return nodes

    def format_graph(self, nodes: list[FunctionNode]) -> str:
        lines = []
        for node in nodes:
            if node.is_external:
                continue
            for ct in node.callees:
                arg_txt = f" [{', '.join(ct.args)}]" if ct.args else ""
                if ct.is_external:
                    lines.append(
                        f"{node.name} (0x{node.addr:x}) --> {self.resolve_name(ct.callee)} (libc/外部, 不展开){arg_txt}")
                else:
                    lines.append(f"{node.name} (0x{node.addr:x}) --> {self.resolve_name(ct.callee)}{arg_txt}")
        return "\n".join(lines) or "(无内部调用)"
