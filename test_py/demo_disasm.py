import sys
from loader import guess_loader
from disasm import Disassembler

prog = guess_loader(sys.argv[1]).load()
print(f"架构: {prog.arch} ({prog.bits}bit)  入口: 0x{prog.entry:x}")
print(f"反汇编 .text 前 20 条指令:\n")

dis = Disassembler(prog)
for i, ins in enumerate(dis.decode_text()):
    if i >= 20:
        break
    print(f"  {ins}")