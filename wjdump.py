"""WJ_Decompiler 的 objdump 风格命令行工具.

用法 (尽量对齐 GNU objdump 的排版):
    python wjdump.py -f <binary>                 # 文件头
    python wjdump.py -h <binary>                 # 节区头
    python wjdump.py -d <binary>                 # 反汇编可执行节区 (带 <符号> 标注)
    python wjdump.py -D <binary>                 # 反汇编所有节区
    python wjdump.py -s <binary>                 # hex dump 所有节区内容
    python wjdump.py -s -j .rodata <binary>      # hex dump 指定节区
    python wjdump.py -t <binary>                 # 符号表
    python wjdump.py -C <binary>                 # 各函数 C 伪代码
    python wjdump.py -d -j .text --start-address=0x8048648 --stop-address=0x80486c8 <bin>
    python wjdump.py -d -M intel <binary>        # 指定语法 intel/att

等价 objdump 选项: -f -h -d -D -s -t -j --start-address --stop-address -M
"""
from __future__ import annotations

import argparse
import os
import sys

from loader import guess_loader
from disasm import Disassembler
from analysis.function_finder import FunctionFinder
from ir import Lifter
from codegen import CGenerator

SYNTAX = ("intel", "att")

_ARCH_STR = {
    ("x86", 32): "i386",
    ("x86", 64): "i386:x86-64",
    ("x86_64", 64): "i386:x86-64",
    ("arm", 32): "arm",
    ("aarch64", 64): "aarch64:little",
}

def _arch_label(prog) -> str:
    return _ARCH_STR.get((prog.arch, prog.bits), f"{prog.arch}:{prog.bits}")

def _build_symtab(prog):
    """返回 (addr->名称, 属于 .plt 的地址集合),供反汇编标注 <name>/<name@plt>."""
    tab = {}
    plt_addrs = set()
    for s in prog.symbols:
        if s.addr and s.name and s.addr not in tab:
            tab[s.addr] = s.name
        if s.addr and s.section == ".plt":
            plt_addrs.add(s.addr)
    return tab, plt_addrs

def _file_format(prog, path: str) -> str:
    """objdump 风格格式名,如 elf32-i386 / elf64-x86-64 / pei-x86-64."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        magic = b""
    if magic == b"\x7fELF":
        elf_bits = "64" if prog.bits == 64 else "32"
        arch = {"x86": "i386", "x86_64": "x86-64",
                "arm": "arm", "aarch64": "aarch64"}.get(prog.arch, prog.arch)
        return f"elf{elf_bits}-{arch}"
    if magic[:2] == b"MZ":
        arch = "x86-64" if prog.bits == 64 else "i386"
        return f"pei-{arch}"
    return "unknown"


def cmd_f(prog, path: str) -> None:
    print(f"{path}:     file format {_file_format(prog, path)}")
    print(f"architecture: {_arch_label(prog)}")
    print(f"start address 0x{prog.entry:x}")
    print(f"image base 0x{prog.image_base:x}")

def cmd_h(prog) -> None:
    # ELF 节区标志位(SHF_*) 用于仿 objdump 属性行
    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    SHF_MERGE = 0x10
    SHF_STRINGS = 0x20
    SHF_INFO_LINK = 0x40
    SHF_TLS = 0x400

    addr_w = 16 if prog.bits == 64 else 8
    print("Sections:")
    print(f"{'Idx':>3} {'Name':<20} {'Size':>{addr_w}} {'VMA':>{addr_w}} "
          f"{'LMA':>{addr_w}} {'File off':>{addr_w}} {'Algn':>6}")
    for i, s in enumerate(prog.sections):
        if s.name == "" and s.type in ("SHT_NULL", ""):
            continue  # 跳过 idx0 空节
        algn = s.align if s.align else 1
        algn_str = f"2**{algn.bit_length()-1}"
        print(f"{i:3d} {s.name:<20} {s.size:{addr_w}x} {s.addr:0{addr_w}x} "
              f"{s.addr:0{addr_w}x} {s.file_off:0{addr_w}x} {algn_str:>6}")
        # 属性行(仿 objdump 第二行)
        attrs = []
        f = s.flags
        if f is None:
            f = 0
        is_nobits = s.type == "SHT_NOBITS"
        if s.data or is_nobits:
            if not is_nobits and s.size:
                attrs.append("CONTENTS")
            if f & SHF_ALLOC:
                attrs.append("ALLOC")
            if s.loaded and not is_nobits:
                attrs.append("LOAD")
            if s.data and not (f & SHF_WRITE):
                attrs.append("READONLY")
            if f & SHF_EXECINSTR:
                attrs.append("CODE")
            elif f & SHF_ALLOC and s.data:
                attrs.append("DATA")
            if s.name.startswith(".debug"):
                attrs.append("DEBUGGING")
                attrs.append("OCTETS")
        if attrs:
            print(f"       {', '.join(attrs)}")
        else:
            print(f"       {s.type}")

def _iter_sections(prog, only_exec: bool):
    for s in prog.sections:
        if only_exec and "x" not in s.perm:
            continue
        if not s.data:
            continue
        yield s

def _fmt_bytes(raw: bytes, width: int = 7) -> str:
    """仿 objdump 的机器码列,最多 width 个字节,超出省略."""
    if not raw:
        return ""
    hexs = " ".join(f"{b:02x}" for b in raw[:width])
    if len(raw) > width:
        hexs += "..."
    return hexs

def _disasm_section(prog, dis, sec, symtab, plt_addrs, start=None, stop=None,
                     use_d=False):
    """反汇编单个节区,仿 objdump -d 排版(含 <name> 符号标注)."""
    if use_d:
        print(f"\nDisassembly of section {sec.name}:")
    data = sec.data
    base = sec.addr
    lo = base if start is None else max(base, start)
    hi = base + len(data) if stop is None else min(base + len(data), stop)
    if lo >= hi:
        return
    off = lo - base
    code = data[off: hi - base]
    if not code:
        return

    def _label(addr: int) -> str:
        n = symtab[addr]
        return f"{n}@plt" if addr in plt_addrs else n

    labels = sorted(a for a in symtab if lo <= a < hi)

    cur = lo
    printed = 0
    for ins in dis.cs.disasm(code, cur):
        addr = ins.address
        # 打印函数标签
        if labels and addr in labels:
            print(f"\n{addr:08x} <{_label(addr)}>:")
        # 若越过 stop 则停(disasm 天然顺序,stop 由切片控制)
        line_bytes = _fmt_bytes(ins.bytes)
        mnem = ins.mnemonic
        ops = ins.op_str
        # 对直接跳转/调用目标追加 <name> 标注
        if mnem in ("call", "jmp", "je", "jne", "jg", "jl", "jge", "jle",
                    "ja", "jb", "jae", "jbe", "jz", "jnz", "js", "jns",
                    "jo", "jno", "jp", "jnp", "loop", "jecxz", "jrcxz"):
            tgt = _parse_imm_target(ops)
            if tgt is not None and tgt in symtab:
                ops = f"{ops} <{_label(tgt)}>"
        print(f"{addr:08x}:\t{line_bytes:<24}\t{mnem}\t{ops}")
        printed += 1
    if printed == 0:
        print(f"{lo:08x}:\t... (无法反汇编)")

def _parse_imm_target(op_str: str):
    """从操作数解析立即数目标;支持 0x... 或数字."""
    s = op_str.strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None

def cmd_d(prog, dis, symtab, plt_addrs, only_exec, start=None, stop=None):
    print(f"\n{prog.arch} ({prog.bits}-bit)")
    for sec in _iter_sections(prog, only_exec):
        _disasm_section(prog, dis, sec, symtab, plt_addrs, start, stop,
                        use_d=True)

def cmd_s(prog, jsec=None):
    """仿 objdump -s: 逐节区 hex dump,16 字节一行 + ascii 列."""
    for s in prog.sections:
        if jsec and s.name != jsec:
            continue
        if not s.data:
            continue
        print(f"\nContents of section {s.name}:")
        data = s.data
        base = s.addr
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hexpart = " ".join(f"{b:02x}" for b in chunk[:8])
            hexpart2 = " ".join(f"{b:02x}" for b in chunk[8:])
            ascii_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
            print(f" {base+i:04x} {hexpart:<23} {hexpart2:<23} {ascii_part}")

def cmd_t(prog):
    """仿 objdump -t: 符号表."""
    bind_w = 7
    typ_w = 1
    sec_w = max((len(s.section or "*UND*") for s in prog.symbols if s.addr), default=4)
    print("SYMBOL TABLE:")
    for s in prog.symbols:
        if not s.addr:
            continue
        bind = {"STB_GLOBAL": "g", "STB_LOCAL": "l", "STB_WEAK": "w"}.get(s.bind, "?")
        typ = {"STT_FUNC": "F", "STT_OBJECT": "O", "STT_NOTYPE": "",
               "STT_SECTION": "S", "STT_FILE": "f", "STT_TLS": "T"}.get(
                   s.sym_type, s.sym_type or "")
        sec = s.section or "*UND*"
        print(f"{s.addr:016x} {bind} {typ:>{typ_w}} {sec:<{sec_w+2}} {s.name}")


def cmd_c(prog, dis, symtab, start=None, stop=None, max_funcs: int = 200) -> None:
    """生成各函数的 C 伪代码(反汇编 -> IR -> CGenerator)."""
    if prog.arch not in ("x86", "x86_64"):
        print("[提示] -C 伪代码生成暂仅支持 x86/x86-64", file=sys.stderr)
        return
    try:
        addrs = FunctionFinder(prog, dis).find(max_verify=max_funcs)
    except Exception as exc:
        print(f"[错误] 函数发现失败: {exc}", file=sys.stderr)
        return
    if start is not None:
        addrs = [a for a in addrs if a >= start]
    if stop is not None:
        addrs = [a for a in addrs if a < stop]
    gen = CGenerator(prog)
    lf = Lifter(dis)
    for addr in addrs[:max_funcs]:
        name = symtab.get(addr, f"sub_{addr:x}")
        sec = prog.find_section(addr)
        if sec is None:
            continue
        # 反汇编函数体:到首个 ret 结束
        off = addr - sec.addr
        body = []
        for ins in dis.decode(sec.data[off:off + 0x4000], addr):
            body.append(ins)
            if ins.mnemonic == "ret" or (ins.mnemonic.startswith("rep")
                                          and ins.mnemonic.endswith("ret")):
                break
        if not body:
            continue
        print(f"\n// ====== {name} @ 0x{addr:x} ======")
        ir = lf.lift(body)
        print("void func() {")
        c = gen.generate(ir)
        print(c if c else "    // (空函数体)")
        print("}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="wjdump",
        description="WJ_Decompiler 反汇编/二进制查看工具(仿 objdump)",
        add_help=False,
    )
    ap.add_argument("--help", action="help", help="显示此帮助并退出")
    ap.add_argument("binary", help="目标二进制(ELF/PE)")
    ap.add_argument("-f", action="store_true", help="显示文件头")
    ap.add_argument("-h", action="store_true", help="显示节区头")
    ap.add_argument("-d", action="store_true", help="反汇编可执行节区")
    ap.add_argument("-D", action="store_true", help="反汇编所有节区(含数据)")
    ap.add_argument("-s", action="store_true", help="hex dump 节区内容")
    ap.add_argument("-t", action="store_true", help="显示符号表")
    ap.add_argument("-C", action="store_true", help="生成函数 C 伪代码")
    ap.add_argument("-j", metavar="SECTION", default=None, help="仅处理指定节区")
    ap.add_argument("--start-address", default=None, help="反汇编起始地址")
    ap.add_argument("--stop-address", default=None, help="反汇编结束地址(不含)")
    ap.add_argument("-M", default=None, choices=SYNTAX, help="汇编语法 intel/att")
    args = ap.parse_args(argv)

    if not any([args.f, args.h, args.d, args.D, args.s, args.t, args.C]):
        ap.print_help()
        return 2

    try:
        prog = guess_loader(args.binary).load()
    except Exception as exc:
        print(f"[错误] 无法加载 {args.binary}: {exc}", file=sys.stderr)
        return 1

    start = int(args.start_address, 0) if args.start_address else None
    stop = int(args.stop_address, 0) if args.stop_address else None
    symtab, plt_addrs = _build_symtab(prog)
    dis = Disassembler(prog)
    if args.M:
        dis.set_syntax(args.M)

    if args.f:
        cmd_f(prog, args.binary)
    if args.h:
        cmd_h(prog)
    if args.d or args.D:
        cmd_d(prog, dis, symtab, plt_addrs, only_exec=bool(args.d and not args.D),
              start=start, stop=stop)
    if args.s:
        cmd_s(prog, jsec=args.j)
    if args.t:
        cmd_t(prog)
    if args.C:
        cmd_c(prog, dis, symtab, start=start, stop=stop)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (BrokenPipeError, OSError) as e:
        # 输出管道被提前关闭(如 | head / | Select-Object)
        if isinstance(e, OSError) and e.errno not in (32, 22):
            raise
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except Exception:
            pass
        os._exit(0)