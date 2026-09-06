import sys
from loader import guess_loader

def main():
    if len(sys.argv) != 2:
        sys.exit(1)

    prog = guess_loader(sys.argv[1]).load()
    print(f"架构: {prog.arch} ({prog.bits}bit)")
    print(f"入口点: 0x{prog.entry:x}")
    print(f"镜像基址: 0x{prog.image_base:x}")
    print("\n节区:")
    for s in prog.sections:
        print(f"{s.name:16s} 0x{s.addr:x} {s.size} {s.perm}")
    code = prog.code
    print(f"\n可执行段大小: {len(code)} bytes")

if __name__ == "__main__":
    main()