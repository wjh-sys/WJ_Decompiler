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
        spans = self._symbol_spans()

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
            if self._in_symbol_span(addr, spans):
                continue
            if any(s <= addr < e for s, e in covered):
                continue
            if verified >= max_verify:
                break
            if accept(addr):
                verified += 1
        return sorted(kept)

    def _symbol_spans(self) -> list:
        """已知符号(在 .text 内)按地址排序形成的连续区间 [(start, next), ...]."""
        if self.cs is None:
            return []
        addrs = sorted({s.addr for s in self.prog.symbols
                        if s.addr and s.name and self._in_text(s.addr)})
        end = self.cs.addr + self.cs.size
        return [(a, addrs[i + 1] if i + 1 < len(addrs) else end)
                for i, a in enumerate(addrs)]

    def _in_symbol_span(self, addr: int, spans) -> bool:
        """addr 是否落在两个已知符号之间(即某符号区间内部).

        这类地址属于既有函数的中间/填充, 不应作为独立函数起点;
        仅用于过滤扫描种子, 不影响符号表给出的真实函数。
        """
        for start, nxt in spans:
            if start >= addr:
                return False
            if addr < nxt:
                return True
        return False

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


def _jump_target(ins) -> int | None:
    """直接跳转(jcc/jmp)的常量目标; 间接跳转/非跳转返回 None."""
    m = ins.mnemonic
    if not m.startswith("j") or m == "j":
        return None
    try:
        return int(ins.op_str.strip(), 0)
    except ValueError:
        return None


def _forward_targets(body: dict) -> set:
    out = set()
    for ins in body.values():
        t = _jump_target(ins)
        if t is not None:
            out.add(t)
    return out


def decode_function_body(dis, prog, addr: int, starts, max_ins: int = 2000) -> list:
    """解码函数体(按地址升序返回指令列表).

    线性解码至首个 ret / 下一个已知函数起点 / 无条件 jmp(其后为死代码);
    若函数内仍有前向跳转目标未被覆盖(典型: `cmp/jcc L; ret; L: ...`
    这种 early-return 布局), 继续解码这些目标直至全部覆盖。
    目标落在下一函数起点之后(真正的尾调用)时不展开; 间接跳转不展开。
    供 wjdump / callgraph / demo 复用, 保证各处函数体解码口径一致。
    """
    sec = prog.find_section(addr)
    if sec is None:
        return []
    starts = set(starts)
    later = sorted(s for s in starts if s > addr)
    limit = later[0] if later else sec.addr + sec.size
    body: dict = {}
    queue = [addr]
    while queue:
        cur = queue.pop(0)
        for ins in dis.decode(sec.data[cur - sec.addr:], cur):
            a = ins.addr
            if a >= limit or a in body or (a != cur and a in starts):
                break
            body[a] = ins
            if len(body) >= max_ins:
                return [body[k] for k in sorted(body)]
            if _is_ret(ins.mnemonic) or ins.mnemonic == "jmp":
                # 终止(ret/jmp; jmp 后为死代码), 并补齐函数内未覆盖的前向目标:
                # 仅取 (当前地址, 下一函数起点) 区间, 向后跳/真尾调用不展开。
                for t in sorted(x for x in _forward_targets(body)
                                if a < x < limit and x not in body):
                    queue.append(t)
                break
    return [body[k] for k in sorted(body)]