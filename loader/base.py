from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Section:
    name: str
    addr: int
    size: int
    data: bytes
    perm: str = 'r'
    type: str = ""        # 节区类型,如 SHT_PROGBITS (ELF)
    align: int = 0         # 对齐字节数
    file_off: int = 0      # 文件内偏移
    flags: int = 0         # 原始节区标志位(ELF sh_flags / PE Characteristics)
    loaded: bool = False   # 是否被可装载段(PT_LOAD)覆盖,objdump -h 的 LOAD 属性
    seg_exec: bool = False # 所在 PT_LOAD 段是否可执行(运行时真实权限, 可能与 sh_flags 不一致)

@dataclass
class Symbol:
    name: str
    addr: int
    is_func: bool = False
    sym_type: str = ""    # STT_FUNC / STT_OBJECT / STT_NOTYPE ...
    bind: str = ""        # STB_GLOBAL / STB_LOCAL / STB_WEAK
    section: str = ""     # 所在节区名(用于 -t 输出)

@dataclass
class Program:
    arch: str
    bits: int
    entry: int
    sections: list[Section] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    strings: dict = field(default_factory=dict)
    image_base: int = 0

    @property
    def code_section(self):
        for s in self.sections:
            if s.name == ".text":
                return s
        for s in self.sections:
            if "x" in s.perm:
                return s
        return None

    @property
    def code(self) -> bytes:
        cs = self.code_section
        return cs.data if cs else b""

    def find_section(self, addr: int) -> Optional[Section]:
        for s in self.sections:
            if addr >= s.addr and addr < s.addr + s.size:
                return s
        return None

    def is_executable(self, addr: int) -> bool:
        """地址是否可执行: 节标志为 X 或所在段为可执行段."""
        sec = self.find_section(addr)
        if sec is None:
            return False
        return "x" in (sec.perm or "") or bool(getattr(sec, "seg_exec", False))

    def string_at(self, addr: int) -> Optional[str]:
        s = self.strings.get(addr)
        if s is not None:
            return s
        # 兜底: strings 表按起始地址精确建键, 且只收录 .rodata/.data 中长度>3 的串.
        # 因此短串(如 scanf 的 "%s")或落在串内部的地址会查不到, 而调用方常以
        # `or ""` 静默降级, 导致判定反转(如 scanf 无界性误判). 此处按节区字节
        # 直接读到 NUL 作为回退; 跳过可执行节区, 避免把代码字节当成字符串.
        sec = self.find_section(addr)
        if sec is None or "x" in (sec.perm or ""):
            return None
        off = addr - sec.addr
        if not (0 <= off < len(sec.data)):
            return None
        end = sec.data.find(b"\x00", off)
        if end < 0:
            end = min(len(sec.data), off + 256)
        txt = "".join(chr(b) for b in sec.data[off:end] if 0x20 <= b < 0x7f)
        return txt or None

class BaseLoader(ABC):
    def __init__(self, path: str):
        self.path = path

    @abstractmethod
    def load(self) -> Program:
        ...
        

        