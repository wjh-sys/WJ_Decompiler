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
from analysis.function_finder import FunctionFinder, decode_function_body
from ir import Lifter
from codegen import CGenerator

SYNTAX = ("intel", "att")

_ARCH_STR = {
    ("x86", 32): "i386",
    ("x86", 64): "i386:x86-64",
    ("x86_64", 64): "i386:x86-64",
    ("arm", 32): "arm",
    ("aarch64", 64): "aarch64",
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


_BFD_FLAG_BITS = (
    (0x01, "HAS_RELOC"),
    (0x02, "EXEC_P"),
    (0x04, "HAS_LINENO"),
    (0x08, "HAS_DEBUG"),
    (0x10, "HAS_SYMS"),
    (0x20, "HAS_LOCALS"),
    (0x40, "DYNAMIC"),
    (0x80, "WP_TEXT"),
    (0x100, "D_PAGED"),
)


def _elf_type(path: str):
    """读取 ELF 文件类型(ET_REL/ET_EXEC/ET_DYN); 非 ELF 或异常返回 None."""
    try:
        with open(path, "rb") as f:
            if f.read(4) != b"\x7fELF":
                return None
            f.seek(0)
            from elftools.elf.elffile import ELFFile
            return ELFFile(f).header.e_type
    except Exception:
        return None


def _bfd_flags(prog, path: str) -> int:
    """按 BFD 规则计算文件标志位, 用于仿 objdump 的 flags 0x... 行.

    EXEC_P⟸ET_EXEC, DYNAMIC⟸ET_DYN, HAS_RELOC⟸ET_REL,
    HAS_SYMS⟸存在 .symtab, D_PAGED⟸有可装载节(PT_LOAD)。
    """
    etype = _elf_type(path)
    names = {s.name for s in prog.sections}
    flags = 0
    if etype == "ET_REL":
        flags |= 0x01
    elif etype == "ET_EXEC":
        flags |= 0x02
    elif etype == "ET_DYN":
        flags |= 0x40
    if ".symtab" in names:
        flags |= 0x10
    if any(getattr(s, "loaded", False) for s in prog.sections):
        flags |= 0x100
    return flags


def _flag_names(flags: int, width: int = 70) -> str:
    """标志名列表; 超宽时按列折行(行尾补逗号), 仿 objdump."""
    names = [n for bit, n in _BFD_FLAG_BITS if flags & bit]
    lines, cur = [], ""
    for n in names:
        if cur and len(cur) + 2 + len(n) > width:
            lines.append(cur + ",")
            cur = n
        else:
            cur = f"{cur}, {n}" if cur else n
    if cur:
        lines.append(cur)
    return "\n".join(lines)


def _print_format_line(prog, path: str) -> None:
    """打印 objdump 的 `path:     file format X` 行; 同一文件只打印一次.

    注意: 仅 `-d/-D/-h` 等组合时只需此行; architecture/flags 行仅属 -f.
    """
    if getattr(prog, "_wjdump_format_line", False):
        return
    try:
        prog._wjdump_format_line = True
    except Exception:
        pass
    print(f"\n{path}:     file format {_file_format(prog, path)}")


def cmd_f(prog, path: str) -> None:
    """仿 objdump -f: file format 行 + architecture/flags + start address."""
    _print_format_line(prog, path)
    flags = _bfd_flags(prog, path)
    vma_w = 16 if prog.bits == 64 else 8
    print(f"architecture: {_arch_label(prog)}, flags 0x{flags:08x}:")
    names = _flag_names(flags)
    if names:
        print(names)
    print(f"start address 0x{prog.entry:0{vma_w}x}")

def cmd_h(prog, path=None, jsec=None) -> None:
    # ELF 节区标志位(SHF_*) 用于仿 objdump 属性行
    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    SHF_MERGE = 0x10
    SHF_STRINGS = 0x20
    SHF_INFO_LINK = 0x40
    SHF_TLS = 0x400

    if path is not None:
        _print_format_line(prog, path)
    addr_w = 16 if prog.bits == 64 else 8
    name_w = 13
    attr_ind = " " * (3 + 1 + name_w + 1)
    print("\nSections:")
    print(f"{'Idx':>3} {'Name':<{name_w}} {'Size':<8}  {'VMA':<{addr_w}}  "
          f"{'LMA':<{addr_w}}  {'File off':<{addr_w}}  Algn")
    idx = -1
    for s in prog.sections:
        if s.name == "" and s.type in ("SHT_NULL", ""):
            continue  # 跳过 NULL 节; objdump 对余下节从 0 重新编号
        idx += 1
        if jsec and s.name != jsec:
            continue
        algn = s.align if s.align else 1
        algn_str = f"2**{algn.bit_length()-1}"
        print(f"{idx:>3} {s.name:<{name_w}} {s.size:0{addr_w}x}  "
              f"{s.addr:0{addr_w}x}  {s.addr:0{addr_w}x}  "
              f"{s.file_off:0{addr_w}x}  {algn_str}")
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
            print(f"{attr_ind}{', '.join(attrs)}")
        else:
            print(f"{attr_ind}{s.type}")

def _iter_sections(prog, only_exec: bool, jsec=None):
    for s in prog.sections:
        if jsec and s.name != jsec:
            continue
        if only_exec and "x" not in s.perm:
            continue
        if not s.data:
            continue
        yield s

def _byte_lines(raw: bytes, per_line: int = 7) -> list:
    """按 objdump 规则把机器码切成每行至多 per_line 字节的块(超出者换行续排)."""
    if not raw:
        return [b""]
    return [raw[i:i + per_line] for i in range(0, len(raw), per_line)]


def _hex_bytes(chunk: bytes) -> str:
    return " ".join(f"{b:02x}" for b in chunk)

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

    # 标注表: 符号优先; 无符号时用节区起点名(仿 objdump 的节区符号, 如 <.plt>)
    ann = {s.addr: s.name for s in prog.sections if s.addr}
    for _a, _n in symtab.items():
        ann[_a] = _n
    ann_items = sorted(ann.items())
    vma_w = 16 if prog.bits == 64 else 8

    def _label(addr: int) -> str:
        n = ann.get(addr, "")
        return f"{n}@plt" if addr in plt_addrs else n

    def _annotate(tgt: int):
        """目标标注: 精确命中 -> <name>; 否则最近前趋符号 -> <name+0xoff>."""
        if tgt in ann:
            return f"<{_label(tgt)}>"
        best = None
        for a, n in ann_items:
            if a <= tgt:
                best = (a, n)
            else:
                break
        if best is None:
            return None
        a, n = best
        return f"<{n}+0x{tgt - a:x}>"

    labels = sorted(a for a in ann if lo <= a < hi)
    _JMP = ("call", "jmp", "je", "jne", "jg", "jl", "jge", "jle",
            "ja", "jb", "jae", "jbe", "jz", "jnz", "js", "jns",
            "jo", "jno", "jp", "jnp", "loop", "jecxz", "jrcxz")

    cur = lo
    printed = 0
    prev_zero = False      # 上一条指令是否全为 00 字节
    dot_printed = False    # 当前零字节段是否已输出过 "..."
    for ins in dis.cs.disasm(code, cur):
        addr = ins.address
        # 打印标签(objdump: 标签地址按位宽补零)
        if labels and addr in labels:
            print(f"\n{addr:0{vma_w}x} <{_label(addr)}>:")
            # 符号边界结束当前零字节折叠(仿 objdump)
            prev_zero = False
            dot_printed = False
        # 零字节折叠(仿 objdump): 连续纯 00 字节的对齐填充只保留首条指令,
        # 从第二条起折叠为一行 "\t...", 直至遇非零指令或符号标签。
        is_zero = bool(ins.bytes) and not any(ins.bytes)
        if is_zero and prev_zero:
            if not dot_printed:
                print("\t...")
                dot_printed = True
            printed += 1
            continue
        prev_zero = is_zero
        if not is_zero:
            dot_printed = False
        mnem = ins.mnemonic
        ops = ins.op_str
        # 对直接跳转/调用目标追加 <name> / <name+off> 标注
        if mnem in _JMP:
            tgt = _parse_imm_target(ops)
            note = _annotate(tgt) if tgt is not None else None
            if note:
                ops = f"{ops} {note}"
        # 机器码列: 每行至多 7 字节, 超出者换行续排(续行带递进地址, 无助记符)
        chunks = _byte_lines(ins.bytes)
        sep = "" if len(mnem) < 7 else " "
        print(f"{addr:>{vma_w}x}:\t{_hex_bytes(chunks[0]):<23}\t{mnem:<7}{sep}{ops}")
        off = len(chunks[0])
        for ch in chunks[1:]:
            print(f"{addr + off:>{vma_w}x}:\t{_hex_bytes(ch):<23}")
            off += len(ch)
        printed += 1
    if printed == 0:
        print(f"{lo:0{vma_w}x}:\t... (无法反汇编)")

def _parse_imm_target(op_str: str):
    """从操作数解析立即数目标;支持 0x... 或数字."""
    s = op_str.strip()
    if not s:
        return None
    try:
        return int(s, 0)
    except ValueError:
        return None

def cmd_d(prog, dis, symtab, plt_addrs, only_exec, start=None, stop=None,
          path=None, jsec=None):
    if path is not None:
        _print_format_line(prog, path)
    for sec in _iter_sections(prog, only_exec, jsec):
        _disasm_section(prog, dis, sec, symtab, plt_addrs, start, stop,
                        use_d=True)

def cmd_s(prog, jsec=None, path=None, start=None, stop=None):
    """仿 objdump -s: 逐节区 hex dump.

    16 字节一行, 每 4 字节一组(如 `2f6c6962 2f6c642d`), 地址为最小 4 位
    十六进制(与 objdump 一致, 不补前导零), 十六进制列定宽后接 ASCII 列。
    先打文件头行, 头行后空一行, 各节区连续输出(节区间不空行)。
    """
    if path is not None:
        _print_format_line(prog, path)
        print()
    for s in prog.sections:
        if jsec and s.name != jsec:
            continue
        if not s.data:
            continue
        print(f"Contents of section {s.name}:")
        data = s.data
        base = s.addr
        for i in range(0, len(data), 16):
            row = base + i
            if start is not None and row + 16 <= start:
                continue
            if stop is not None and row >= stop:
                break
            chunk = data[i:i + 16]
            groups = " ".join(
                "".join(f"{b:02x}" for b in chunk[k:k + 4])
                for k in range(0, len(chunk), 4)
            )
            ascii_part = "".join(chr(b) if 0x20 <= b < 0x7f else "."
                                 for b in chunk)
            print(f" {base + i:04x} {groups:<35}  {ascii_part}")

_VIS = {1: ".internal ", 2: ".hidden ", 3: ".protected "}
_VIS_NAME = {"STV_INTERNAL": 1, "STV_HIDDEN": 2, "STV_PROTECTED": 3}


def _vis_prefix(entry) -> str:
    """符号可见性前缀(.hidden/.internal/.protected).

    pyelftools 的 st_other 是 BitStruct(Container), 其 visibility 返回字符串
    名("STV_HIDDEN" 等); 旧版下 st_other 也可能是 int。两种都兼容。
    """
    other = getattr(entry, "st_other", 0)
    if not isinstance(other, int):
        other = getattr(other, "visibility", 0)
    if isinstance(other, str):
        bits = _VIS_NAME.get(other, 0)
    else:
        try:
            bits = int(other)
        except Exception:
            bits = 0
    return _VIS.get(bits & 0x3, "")


def _sym_flags(bind, typ, sec="") -> str:
    """构造 objdump 的 7 字符 flags 字段.

    位置: 0=绑定(l/g/空格), 1=弱(w/空格), 2-4=空格,
    5=调试(d: section/file), 6=类型(F/O/f/T/i/空格).
    例: 局部节区→`l    d `, 局部函数→`l     F`, 文件→`l    df`。
    未定义节区(*UND*)的全局符号不显示绑定字母(仿 objdump)。
    """
    b0 = "l" if bind == "STB_LOCAL" else ("g" if bind == "STB_GLOBAL" else " ")
    if b0 == "g" and sec == "*UND*":
        b0 = " "
    b1 = "w" if bind == "STB_WEAK" else " "
    d = "d" if typ in ("STT_SECTION", "STT_FILE") else " "
    t = {"STT_FUNC": "F", "STT_OBJECT": "O", "STT_FILE": "f",
         "STT_TLS": "T", "STT_GNU_IFUNC": "i"}.get(typ, " ")
    return f"{b0}{b1}   {d}{t}"


def cmd_t(prog, path=None):
    """仿 objdump -t: 符号表(value / flags / section / size / name).

    直接读取 .symtab 全量符号(含 section/file/object/undefined), 不限于
    函数符号; value 按位宽(32→8, 64→16); 先打文件头行。无 .symtab 时
    回退到 Program.symbols。
    """
    if path is not None:
        _print_format_line(prog, path)
        print()
    print("SYMBOL TABLE:")
    got = _read_symtab(path) if path else None
    if got is None:
        _symtab_fallback(prog)
        return
    aw, rows = got
    for v, bind, typ, sec, sz, name in rows:
        print(f"{v:0{aw}x} {_sym_flags(bind, typ, sec)} {sec}\t{sz:0{aw}x}              {name}")


def _read_symtab(path):
    """读取 .symtab 全量符号, 返回 (地址宽度, [(value,bind,typ,sec,size,name)]).

    仅在文件/节区不可用等情况下返回 None(触发回退); 单个符号异常则跳过,
    避免因个别符号字段差异而静默降级到回退路径。
    """
    try:
        from elftools.elf.elffile import ELFFile
        f = open(path, "rb")
    except Exception:
        return None
    with f:
        try:
            elf = ELFFile(f)
            st = elf.get_section_by_name(".symtab")
        except Exception:
            return None
        if st is None:
            return None
        aw = 16 if elf.elfclass == 64 else 8
        rows = []
        for i, sym in enumerate(st.iter_symbols()):
            if i == 0:
                continue  # 跳过 symtab 索引 0 的 NULL 符号
            try:
                e = sym.entry
                shndx = e.st_shndx
                if isinstance(shndx, str):
                    sec = {"SHN_UNDEF": "*UND*", "SHN_ABS": "*ABS*",
                           "SHN_COMMON": "*COM*"}.get(shndx, "*ABS*")
                else:
                    try:
                        sec = elf.get_section(shndx).name
                    except Exception:
                        sec = "*ABS*"
                typ = e.st_info.type
                raw = sec if typ == "STT_SECTION" else sym.name
                vis = _vis_prefix(e) if raw else ""
                rows.append((e.st_value, e.st_info.bind, typ, sec,
                             e.st_size, vis + raw))
            except Exception:
                continue
        return aw, rows


def _symtab_fallback(prog) -> None:
    """无 .symtab 时的回退: 用 Program.symbols 渲染(尺寸未知记 0)."""
    aw = 16 if prog.bits == 64 else 8
    for s in prog.symbols:
        sec = s.section or "*UND*"
        print(f"{s.addr:0{aw}x} {_sym_flags(s.bind, s.sym_type, sec)} {sec}\t"
              f"{'0' * aw}              {s.name}")


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
        body = decode_function_body(dis, prog, addr, addrs)
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

    if args.j and not any(s.name == args.j for s in prog.sections):
        print(f"wjdump: section '{args.j}' mentioned in a -j option, "
              f"but not found in sections", file=sys.stderr)
    if args.f:
        cmd_f(prog, args.binary)
    if args.h:
        cmd_h(prog, args.binary, jsec=args.j)
    if args.d or args.D:
        cmd_d(prog, dis, symtab, plt_addrs, only_exec=bool(args.d and not args.D),
              start=start, stop=stop, path=args.binary, jsec=args.j)
    if args.s:
        cmd_s(prog, jsec=args.j, path=args.binary, start=start, stop=stop)
    if args.t:
        cmd_t(prog, args.binary)
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