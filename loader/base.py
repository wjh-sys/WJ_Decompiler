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

    def string_at(self, addr: int) -> Optional[str]:
        return self.strings.get(addr)

class BaseLoader(ABC):
    def __init__(self, path: str):
        self.path = path

    @abstractmethod
    def load(self) -> Program:
        ...
        

        