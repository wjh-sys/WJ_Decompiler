import re

from capstone import (
    Cs,
    CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_AARCH64,
    CS_MODE_32, CS_MODE_64, CS_MODE_ARM,
)
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from .base import BaseLoader, Program, Section, Symbol

SHF_WRITE = 0x01
SHF_EXECINSTR = 0x04

class ElfLoader(BaseLoader):
    def load(self) -> Program:
        with open(self.path, "rb") as f:
            elf = ELFFile(f)
            arch = self._arch(elf)
            bits = 64 if elf.elfclass == 64 else 32
            symbols = self._symbols(elf)
            symbols += self._plt_symbols(elf, arch, bits)
            return Program(
                arch=arch,
                bits=bits,
                entry=elf.header.e_entry,
                sections=self._sections(elf),
                symbols=symbols,
                strings=self._strings(elf),
                image_base=0,
            )
        
    def _arch(self, elf) -> str:
        m = elf.header.e_machine
        return {
            "EM_X86_64": "x86_64",
            "EM_386": "x86",
            "EM_ARM": "arm",
            "EM_AARCH64": "aarch64",
        }.get(m, m) # type: ignore
    
    def _sections(self, elf) -> list[Section]:
        # 收集 PT_LOAD 段的 VMA 区间,用于判定节的 LOAD 属性
        load_ranges = []
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_LOAD":
                load_ranges.append((seg.header.p_vaddr,
                                    seg.header.p_vaddr + seg.header.p_memsz))

        def _loaded(addr: int, size: int) -> bool:
            if not size:
                return False
            return any(a <= addr < b or (a < addr + size and addr < b)
                       for a, b in load_ranges)

        sections = []
        for s in elf.iter_sections():
            flags = s.header.sh_flags
            perm = "r"
            if flags & SHF_WRITE:
                perm += "w"
            if flags & SHF_EXECINSTR:
                perm += "x"

            is_nobits = s.header.sh_type == "SHT_NOBITS"
            sections.append(Section(
                name=s.name,
                addr=s.header.sh_addr,
                size=s.header.sh_size,
                data=b"" if is_nobits else s.data(),
                perm=perm,
                type=s.header.sh_type,
                align=s.header.sh_addralign,
                file_off=s.header.sh_offset,
                flags=s.header.sh_flags,
                loaded=_loaded(s.header.sh_addr, s.header.sh_size),
            ))
        return sections
        
    def _symbols(self, elf) -> list[Symbol]:
        symbols = []
        for s in elf.iter_sections():
            if isinstance(s, SymbolTableSection):
                for sym in s.iter_symbols():
                    if sym.entry.st_info.type == "STT_FUNC" and sym.entry.st_value:
                        # 反查符号所在节区名
                        sec_name = ""
                        try:
                            shndx = sym.entry.st_shndx
                            if isinstance(shndx, str):
                                sec_name = shndx  # 如 "ABS" / "UND"
                            else:
                                sec_name = elf.get_section(shndx).name
                        except Exception:
                            sec_name = ""
                        symbols.append(Symbol(
                            name=sym.name,
                            addr=sym.entry.st_value,
                            is_func=True,
                            sym_type=sym.entry.st_info.type,
                            bind=sym.entry.st_info.bind,
                            section=sec_name,
                        ))
        return symbols

    def _plt_symbols(self, elf, arch, bits) -> list[Symbol]:
        """通过 .plt 反汇编 + .rel.plt 重定位 + .dynsym 符号表，
        把 PLT stub 地址映射为真实导入函数名（gets/puts 等）。"""
        plt = elf.get_section_by_name(".plt")
        dynsym = elf.get_section_by_name(".dynsym")
        if plt is None or dynsym is None:
            return []
        rel = elf.get_section_by_name(".rel.plt") or elf.get_section_by_name(".rela.plt")
        if rel is None or not isinstance(rel, RelocationSection):
            return []

        got_to_name: dict[int, str] = {}
        for r in rel.iter_relocations():
            got = r.entry.r_offset
            if hasattr(r.entry, "r_info_sym"):
                idx = r.entry.r_info_sym
            else:
                idx = r.entry.r_info >> 8
            try:
                name = dynsym.get_symbol(idx).name
            except Exception:
                name = ""
            if name:
                got_to_name[got] = name
        if not got_to_name:
            return []

        key = (arch, bits)
        arch_id, mode = {
            ("x86", 32): (CS_ARCH_X86, CS_MODE_32),
            ("x86", 64): (CS_ARCH_X86, CS_MODE_64),
            ("x86_64", 64): (CS_ARCH_X86, CS_MODE_64),
            ("arm", 32): (CS_ARCH_ARM, CS_MODE_ARM),
            ("aarch64", 64): (CS_ARCH_AARCH64, CS_MODE_ARM),
        }[key]
        md = Cs(arch_id, mode)

        out = []
        for ins in md.disasm(plt.data(), plt.header.sh_addr):
            if ins.mnemonic != "jmp" or "[" not in ins.op_str:
                continue
            got = _plt_got_target(ins.op_str, ins.address, ins.size)
            if got is None:
                continue
            name = got_to_name.get(got)
            if name:
                out.append(Symbol(name=name, addr=ins.address, is_func=True,
                                  sym_type="STT_FUNC", bind="STB_GLOBAL",
                                  section=".plt"))
        return out

    def _strings(self, elf) -> dict:
        out: dict[int, str] = {}
        for s in elf.iter_sections():
            if s.name not in (".rodata", ".data"):
                continue
            base = s.header.sh_addr
            data = s.data()
            i = 0
            n = len(data)
            while i < n:
                j = i
                while j < n and 0x20 <= data[j] < 0x7f:
                    j += 1
                if j > i + 3 and (j == n or data[j] == 0):
                    s_val = data[i:j].decode("ascii", errors="ignore")
                    out[base + i] = s_val
                    i = j + 1
                else:
                    i = j + 1
        return out


def _plt_got_target(op_str: str, ins_addr: int, ins_size: int):
    """解析 PLT 中 jmp 指令的 GOT 目标地址.

    支持两种形式:
      x86  : jmp dword ptr [0x804a004]        (绝对寻址)
      x86-64: jmp qword ptr [rip + 0x200bd2]   (RIP 相对寻址)
    """
    m = re.search(r"\[(0x[0-9a-fA-F]+)\]", op_str)
    if m:
        return int(m.group(1), 16)
    m = re.search(r"\[rip\s*([+-])\s*(0x[0-9a-fA-F]+)\]", op_str, re.I)
    if m:
        disp = int(m.group(2), 16)
        if m.group(1) == "-":
            disp = -disp
        return ins_addr + ins_size + disp
    return None

    
