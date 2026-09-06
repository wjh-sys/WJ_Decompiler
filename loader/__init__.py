from .base import BaseLoader, Program, Section, Symbol
from .elf_loader import ElfLoader
from .pe_loader import PeLoader

__all__ = [
    "BaseLoader",
    "Program",
    "Section",
    "Symbol",
    "ElfLoader",
    "PeLoader",
    "guess_loader",
]

def guess_loader(path: str) ->BaseLoader:
    with open(path, "rb") as f:
        data = f.read(4)
        if data == b"\x7fELF":
            return ElfLoader(path)
        elif data == b"MZ":
            return PeLoader(path)
        else:
            raise ValueError("Unknown file format")
