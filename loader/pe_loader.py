import pefile
from .base import BaseLoader, Program, Section, Symbol

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

class PeLoader(BaseLoader):
    def load(self) -> Program:
        pe = pefile.PE(self.path, fast_load=True)
        pe.parse_data_directories()
        try:
            return Program(
                arch="x86_64" if pe.FILE_HEADER.Machine == 0x8664 else "x86",
                bits=64 if pe.FILE_HEADER.Machine == 0x8664 else 32,
                entry=pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                sections=self._sections(pe),
                symbols=self._symbols(pe),
                image_base=pe.OPTIONAL_HEADER.ImageBase,
            )
        finally:
            pe.close()

    def _sections(self, pe) -> list:
        base = pe.OPTIONAL_HEADER.ImageBase
        out = []
        for s in pe.sections:
            flags = s.Characteristics
            perm = ""
            if flags & IMAGE_SCN_MEM_READ:
                perm += "r"
            if flags & IMAGE_SCN_MEM_WRITE:
                perm += "w"
            if flags & IMAGE_SCN_MEM_EXECUTE:
                perm += "x"
            out.append(Section(
                name=s.Name.rstrip(b"\x00").decode(errors="ignore"),
                addr=base + s.VirtualAddress,
                size=s.Misc_VirtualSize,
                data=s.get_data(),
                perm=perm or "r",
                flags=flags,
                loaded=True,
            ))
        return out

    def _symbols(self, pe) -> list:
        out = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.address:
                        name = imp.name.decode() if imp.name else f"ord_{imp.ordinal}"
                        out.append(Symbol(addr=imp.address, name=name, is_func=True))
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.address:
                    name = exp.name.decode() if exp.name else f"ord_{exp.ordinal}"
                    out.append(Symbol(
                        addr=pe.OPTIONAL_HEADER.ImageBase + exp.address,
                        name=name,
                        is_func=True,
                    ))
        return out