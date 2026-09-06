from disasm import Disassembler

PROLOGUE_PATTERNS = (
    bytes([0x55, 0x89, 0xe5]),          # push ebp; mov ebp, esp (x86)
    bytes([0x55, 0x48, 0x89, 0xe5]),    # push rbp; mov rbp, rsp (x86-64)
)

class FunctionFinder:
    def __init__(self, prog, dis: Disassembler):
        self.prog = prog
        self.dis = dis
        self.cs = prog.code_section

    def find(self, max_verify: int = 4000) -> list[int]:
        # 符号表种子是精确函数起点,永不丢弃;扫描种子仅当其落进已确认区间时才视为误报
        sym_seeds = {s.addr for s in self.prog.symbols if s.is_func and s.addr
                     and self.cs is not None and self._in_text(s.addr)}
        scan_seeds = {a for a in self._collect_seeds() if a not in sym_seeds}

        kept: set[int] = set()
        covered: list[tuple[int, int]] = []

        def accept(addr: int) -> bool:
            if self._is_thunk(addr):
                return False
            end = self._func_end(addr)
            if end is None:
                return False
            covered.append((addr, end))
            kept.add(addr)
            return True

        verified = 0
        for addr in sorted(sym_seeds):
            accept(addr)
            verified += 1
            if verified >= max_verify:
                break
        for addr in sorted(scan_seeds):
            if any(s <= addr < e for s, e in covered):
                continue
            if verified >= max_verify:
                break
            if accept(addr):
                verified += 1
        return sorted(kept)

    def _func_end(self, addr: int) -> int | None:
        """从 addr 线性解码,返回首个 ret 的下一条地址;解码异常/超长返回 None."""
        if self.cs is None or not self._in_text(addr):
            return None
        offset = addr - self.cs.addr
        if offset >= len(self.cs.data):
            return None
        count = 0
        for ins in self.dis.cs.disasm(self.cs.data[offset:], addr):
            count += 1
            if count > 200:
                return None
            if _is_ret(ins.mnemonic):
                return ins.address + ins.size
        return None

    def _collect_seeds(self) -> set[int]:
        seeds = {self.prog.entry}
        for s in self.prog.symbols:
            if s.is_func and s.addr:
                seeds.add(s.addr)
        if self.cs:
            for ins in self.dis.decode_text():
                if ins.mnemonic == "call":
                    t = _parse_call_target(ins)
                    if t is not None and self._in_text(t):
                        seeds.add(t)
            seeds |= self._scan_prologues()
        return seeds

    def _in_text(self, addr: int) -> bool:
        return self.cs is not None and self.cs.addr <= addr < self.cs.addr + self.cs.size

    def _scan_prologues(self) -> set[int]:
        found = set()
        data = self.cs.data
        for pat in PROLOGUE_PATTERNS:
            start = 0
            while True:
                idx = data.find(pat, start)
                if idx < 0:
                    break
                addr = self.cs.addr + idx
                if self._verify_function(addr):
                    found.add(addr)
                start = idx + 1
        return found

    def _verify_function(self, addr: int) -> bool:
        code = self.cs.data[addr - self.cs.addr:]
        count = 0
        for ins in self.dis.cs.disasm(code, addr):
            count += 1
            if count > 200:
                return False
            if _is_ret(ins.mnemonic):
                return True
        return False

    def _is_thunk(self, addr: int) -> bool:
        if self.cs is None or not self._in_text(addr):
            return True
        offset = addr - self.cs.addr
        if offset >= len(self.cs.data):
            return True
        it = self.dis.cs.disasm(self.cs.data[offset:], addr)
        try:
            first = next(it)
        except StopIteration:
            return True
        return first.mnemonic == "jmp"

def _parse_call_target(ins) -> int | None:
    op = ins.op_str.strip()
    if not op:
        return None
    try:
        return int(op, 0)
    except ValueError:
        return None

def _is_ret(mnemonic: str) -> bool:
    """判断是否函数返回指令,兼容 ret/repz ret/rep ret/retn."""
    if mnemonic == "ret":
        return True
    return mnemonic.startswith("rep") and mnemonic.endswith("ret")