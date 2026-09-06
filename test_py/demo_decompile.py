import sys
from loader import guess_loader
from disasm import Disassembler
from ir import Lifter
from codegen import CGenerator

prog = guess_loader(sys.argv[1]).load()
dis = Disassembler(prog)
start = int(sys.argv[2], 16)
count = int(sys.argv[3]) if len(sys.argv) > 3 else 30

cs = prog.code_section
instrs = dis.decode(cs.data[start - cs.addr:], start)[:count]

ir = Lifter(dis).lift(instrs)
c_code = CGenerator(prog).generate(ir)

print(f"// 反编译 0x{start:x} ({count} 条指令)\n")
print("void func() {")
print(c_code)
print("}")