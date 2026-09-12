from dataclasses import dataclass
from capstone import (
    Cs,
    CS_ARCH_X86, CS_ARCH_ARM,
    CS_MODE_32, CS_MODE_64, CS_MODE_ARM,
)
try:
    from capstone import CS_ARCH_AARCH64
except ImportError:
    from capstone import CS_ARCH_ARM64 as CS_ARCH_AARCH64

from loader import Program

@dataclass
class Instruction:
    addr: int
    mnemonic: str
    bytes: bytes
    op_str: str
    size: int

    def __str__(self):
        return f"0x{self.addr:08x}  {self.mnemonic:<6} {self.op_str}".rstrip()
    
_ARCH_MAP = {
    ("x86", 32): (CS_ARCH_X86, CS_MODE_32),
    ("x86", 64): (CS_ARCH_X86, CS_MODE_64),
    ("x86_64", 64): (CS_ARCH_X86, CS_MODE_64),
    ("arm", 32): (CS_ARCH_ARM, CS_MODE_ARM),
    ("aarch64", 64): (CS_ARCH_AARCH64, CS_MODE_ARM),
}
   
class Disassembler:
    def __init__(self, prog: Program):
        key = (prog.arch, prog.bits)
        if key not in _ARCH_MAP:
            raise ValueError(f"不支持的架构: {key}")
        arch, mode = _ARCH_MAP[key]
        self.cs = Cs(arch, mode)
        self.cs.detail = True
        self.prog = prog

    def set_syntax(self, syntax: str) -> None:
        """设置汇编语法: 'intel' 或 'att' (仅 x86 有效)."""
        if self.prog.arch in ("x86", "x86_64"):
            from capstone import CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT, CS_OPT_SYNTAX_INTEL
            if syntax == "att":
                self.cs.syntax = CS_OPT_SYNTAX_ATT
            else:
                self.cs.syntax = CS_OPT_SYNTAX_INTEL

    def decode_text(self) -> list[Instruction]:
        cs = self.prog.code_section
        if not cs:
            return []
        return self.decode(cs.data, cs.addr)
    
    def decode(self, code: bytes, addr: int) -> list[Instruction]:
       out = []
       for i in self.cs.disasm(code, addr):
           out.append(Instruction(
               i.address,
               i.mnemonic,
               i.bytes,
               i.op_str,
               i.size,
           ))
       return out
    
