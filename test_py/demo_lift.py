import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loader import guess_loader
from disasm import Disassembler
from ir import Lifter

prog = guess_loader(sys.argv[1]).load()
dis = Disassembler(prog)
start = int(sys.argv[2], 16)
count = int(sys.argv[3]) if len(sys.argv) > 3 else 30

cs = prog.code_section
code = cs.data[start - cs.addr:]
instrs = dis.decode(code, start)[:count]

print(f"从 0x{start:x} lift {count} 条指令:\n")
lifter = Lifter(dis)
for i, ir in enumerate(lifter.lift(instrs)):
    print(f"  {i:2}  {ir}")