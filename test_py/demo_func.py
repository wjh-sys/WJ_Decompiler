import sys
from loader import guess_loader
from disasm import Disassembler

prog = guess_loader(sys.argv[1]).load()
dis = Disassembler(prog)

start = int(sys.argv[2], 16)          # 起始地址，如 0x8048648
count = int(sys.argv[3]) if len(sys.argv) > 3 else 30

cs = prog.code_section
offset = start - cs.addr               # 把地址换算成 .text 内的偏移
code = cs.data[offset:]                # 从偏移处截取字节流

print(f"架构: {prog.arch} ({prog.bits}bit)")
print(f"从 0x{start:x} 反汇编 {count} 条:\n")
for i, ins in enumerate(dis.decode(code, start)):
    if i >= count:
        break
    print(f"  {ins}")