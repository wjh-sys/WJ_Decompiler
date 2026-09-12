import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loader import guess_loader
from disasm import Disassembler
from ir import Lifter, Op
from codegen import CGenerator
from analysis import CallGraph

def main():
    if len(sys.argv) != 2:
        print("用法: python demo_decompile_all.py <binary>")
        sys.exit(1)
    prog = guess_loader(sys.argv[1]).load()
    dis = Disassembler(prog)
    gen = CGenerator(prog)

    graph = CallGraph(prog, dis)
    graph.build()

    root = None
    for s in prog.symbols:
        if s.name == "main" and s.addr:
            root = s.addr
            break
    if root is None:
        root = prog.entry
    print(f'根函数入口: 0x{root:x}')
    
    root_name = graph.resolve_name(root)
    if root not in graph._func_addrs:
        print("[错误] 根函数不在调用图内，无法展开")
        sys.exit(1)

    visited: set[int] = set()
    order: list[int] = []
    depth_map: dict[int, int] = {}

    def walk(addr: int, depth: int = 0) -> None:
        if addr in visited:
            return
        visited.add(addr)
        order.append(addr)
        depth_map[addr] = depth
        for ct in graph._edges.get(addr, []):
            walk(ct.callee, depth + 1)

    walk(root)
    print(f'调用链展开（去重，共 {len(order)} 个函数，含外部/libc）')
    print("调用关系（缩进=调用深度）:")
    for addr in order:
        caller = graph.resolve_name(addr)
        indent = "  " * depth_map.get(addr, 0)
        for ct in graph._edges.get(addr, []):
            callee = graph.resolve_name(ct.callee)
            marker = " (外部/libc)" if ct.is_external else ""
            print(f"  {indent}{caller} --> {callee}{marker}")
    print()
    
    for addr in order:
        is_external = addr not in graph._func_addrs
        name = graph.resolve_name(addr)
        marker = "  (外部/libc)" if is_external else ""
        print(f"// ====== {name}{marker} ======")
        print(f"// 0x{addr:x}")
        sec = prog.find_section(addr)
        code = sec.data[addr - sec.addr:] if sec else b""
        instrs = dis.decode(code, addr)
        body = []
        for ins in instrs:
            body.append(ins)
            if ins.mnemonic in ("ret", "jmp"):
                break
        print("汇编：")
        for ins in body:
            raw = " ".join(f"{b:02x}" for b in ins.bytes)
            print(f"  {ins.addr:08x}  {raw:<24} {ins.mnemonic:<7} {ins.op_str}")
        print("\nC代码：")
        if is_external:
            print("// 外部 libc 函数（PLT stub），实现在动态库中")
        else:
            ir = Lifter(dis).lift(body)
            print("void func() {")
            print(gen.generate(ir))
            print("}")
        print()

if __name__ == "__main__":
    main()