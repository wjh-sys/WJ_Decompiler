"""List Table: Evidence 的派生索引层.

把 Evidence 中异构的十类证据(符号/gadget/字符串/libc/偏移/函数/后门/保护)
归一为统一行模型 ToolEntry, 并提供精确键查询 / 分区降级查询 / 能力串求值。

消费方(均只认 ListTable, 不再各自投影 Evidence):
  - prompt 渲染        : table.render()
  - resolver 反查      : table.lookup(problem.kind, problem.target)
  - 技术路线可行性判定  : techniques.eval_routes(table)
  - Algorithm 2 覆盖度  : status -> {HIT:1.0, DERIVED:0.7, SECTION:0.5, MISS:0.0}
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .taint import EXEC_FUNCS

CATEGORIES = ("sym", "libc", "gadget", "offset", "str", "backdoor",
              "decoy", "exec_site", "func", "prot", "arch")
STATUS_SCORE = {"HIT": 1.0, "DERIVED": 0.7, "SECTION": 0.5, "MISS": 0.0}

def hx(a) -> str:
    try:
        return f"0x{int(str(a), 0):x}"
    except (TypeError, ValueError):
        return str(a).strip().lower()

def iv(v):
    try:
        return int(str(v), 0)
    except (TypeError, ValueError):
        return None

@dataclass
class ToolEntry:
    key: str
    category: str
    name: str
    addr: int | None
    detail: str
    source: str
    tags: list = field(default_factory=list)

@dataclass
class LookupResult:
    status: str
    entries: list = field(default_factory=list)
    hint: str = ""

    @property
    def score(self) -> float:
        return STATUS_SCORE.get(self.status, 0.0)

class ListTable:
    def __init__(self, entries: list):
        self.entries = sorted(entries, key=lambda e: (e.category, e.addr or 0, e.key))
        self.index: dict = {}
        self.by_cat: dict = {}
        self.by_tag: dict = {}
        for e in self.entries:
            self.index.setdefault(e.key, e)
            self.by_cat.setdefault(e.category, []).append(e)
            for t in e.tags:
                self.by_tag.setdefault(t, []).append(e)

    @classmethod
    def from_evidence(cls, ev, prog=None) -> "ListTable":
        E: list = []
        for t in getattr(ev, "targets", []) or []:
            E.append(ToolEntry(f"sym:{t.name.lower()}", "sym", t.name, iv(t.detail),
                               f"{t.kind} {t.name} @ {t.detail}",
                               "plt" if t.kind == "plt" else "symtab",
                               ["exec"] if t.name in EXEC_FUNCS else []))
        for b in getattr(ev, "backdoors", []) or []:
            k = getattr(b, "kind", "jump_target")
            cat, pref = {"jump_target": ("backdoor", "bd"),
                         "decoy": ("decoy", "decoy")}.get(k, ("exec_site", "execsite"))
            E.append(ToolEntry(f"{pref}:{hx(b.addr)}", cat, b.name, b.addr,
                               b.note, "symtab", [cat]))
        for g in getattr(ev, "gadgets", []) or []:
            E.append(ToolEntry(f"gadget:{hx(g['addr'])}", "gadget", g.get("asm", ""),
                               g.get("addr"), g.get("asm", ""), "disasm",
                               [g.get("cat", "other")]))
        for s in getattr(ev, "strings", []) or []:
            E.append(ToolEntry(f"str:{s['text'].lower()}", "str", s["text"], s["addr"],
                               repr(s["text"]), "string-scan", ["suspicious"]))
        for o in getattr(ev, "overflow", []) or []:
            E.append(ToolEntry(f"offset:{o.func}", "offset", o.func, o.offset_to_ret,
                               f"{o.call} -> saved-ret {o.offset_to_ret}", "taint",
                               ["saved_ret"]))
        for f in getattr(ev, "funcs", []) or []:
            E.append(ToolEntry(f"func:{hx(f['addr'])}", "func", f["name"], f["addr"],
                               f["name"], "symtab",
                               ["reachable"] if f.get("reachable") else []))
        for k, v in (getattr(ev, "libc", {}) or {}).items():
            if k == "path":
                continue
            E.append(ToolEntry(f"libc:{k.lower()}", "libc", k,
                               v if isinstance(v, int) else None,
                               hx(v) if isinstance(v, int) else str(v), "libc",
                               ["leak_src"]))
        p = getattr(ev, "protections", {}) or {}
        nx = str(p.get("NX", "")).strip().lower()
        pie = str(p.get("PIE", "")).strip().lower()
        canary = str(p.get("Canary", "")).strip().lower()
        relro = str(p.get("RELRO", "")).strip().lower()
        pt = []
        pt.append("nx_off" if nx == "off" else "nx_on")
        pt.append("pie_on" if pie == "on" else "no_pie")
        if canary in ("no", "off", "false", "none", ""):
            pt.append("no_canary")
        elif canary in ("yes", "on", "true"):
            pt.append("canary_on")
        if "partial" in relro or relro in ("no", "off"):
            pt.append("relro_weak")
        if "full" in relro:
            pt.append("relro_full")
        if pt:
            E.append(ToolEntry("prot:main", "prot", "protections", None,
                               ",".join(pt), "detect", pt))
        bits = getattr(ev, "bits", 0)
        arch = (getattr(ev, "arch", "") or "").lower()
        if bits:
            tags = [f"bits{bits}"] + ([f"arch_{arch}"] if arch else [])
            E.append(ToolEntry("arch:main", "arch", arch or f"bits{bits}", bits,
                               f"{arch or '?'} {bits}bit", "detect", tags))
        return cls(E)

    def _cat_status(self, cat: str, target: str = "") -> LookupResult:
        es = self.by_cat.get(cat) or []
        if not es:
            return LookupResult("MISS", [], f"无 {cat} 分区")
        return LookupResult("SECTION", es,
                            f"{cat} 分区存在({len(es)})但无 {target!r} 精确命中")

    def cap_status(self, cap: str) -> LookupResult:
        """能力串求值: 前缀:目标 -> 四态. 严格分级, 禁止裸子串模糊命中."""
        c, _, t = cap.partition(":")
        t = t.strip().lower()
        if c == "prot":
            es = self.by_tag.get(t) or []
            if es:
                return LookupResult("HIT", es, f"保护条件满足 {t}")
            return LookupResult("SECTION" if self.by_cat.get("prot") else "MISS", [],
                                f"保护条件不满足 {t}")
        if c == "arch":
            es = self.by_tag.get(t) or []
            if es:
                return LookupResult("HIT", es, f"架构条件满足 {t}")
            return LookupResult("SECTION" if self.by_cat.get("arch") else "MISS", [],
                                f"架构条件不满足 {t}")
        if c == "offset":
            es = self.by_cat.get("offset") or []
            if es:
                return LookupResult("HIT", es, "实测偏移可用")
            return LookupResult("MISS", [], "无实测偏移")
        if c == "bd":
            es = self.by_cat.get("backdoor") or []
            if es:
                return LookupResult("HIT", es, "存在后门/win 函数")
            return self._cat_status("backdoor", "backdoor")
        if c == "exec":
            for k in (f"sym:{t}", f"libc:{t}"):
                if t and self.index.get(k):
                    return LookupResult("HIT", [self.index[k]], f"{k} 命中")
            ex = self.by_tag.get("exec") or []
            if ex:
                return LookupResult("DERIVED", ex, f"无 {t}, 有替代执行类符号")
            # 目标非执行类符号(如栈/全局缓冲地址): 回退到 sym 分区列全部可利用目标,
            # 而非报"无 libc 分区"这种误导性结论
            if self.by_cat.get("sym"):
                return self._cat_status("sym", t)
            return self._cat_status("libc", t)
        if c == "func":
            es = [x for x in self.by_cat.get("func", []) if t and t in x.name.lower()]
            if es:
                return LookupResult("HIT", es, f"函数名匹配 {t}")
            return self._cat_status("func", t)
        if c == "gadget":
            e = self.index.get(f"gadget:{t}") if t.startswith("0x") else None
            if e:
                return LookupResult("HIT", [e], "gadget 地址精确命中")
            gs = [x for x in self.by_cat.get("gadget", []) if t and t in x.name.lower()]
            if gs:
                return LookupResult("DERIVED", gs, f"gadget 按名匹配 {t}")
            return self._cat_status("gadget", t)
        if c in ("str", "libc"):
            e = self.index.get(f"{c}:{t}") if t else None
            if e:
                return LookupResult("HIT", [e], "精确命中")
            es = self.by_cat.get(c) or []
            if es:
                return LookupResult("DERIVED", es, f"{c} 分区存在但无 {t!r}")
            return self._cat_status(c, t)
        e = self.index.get(f"sym:{t}") if t else None
        if e:
            return LookupResult("HIT", [e], "符号精确命中")
        return self._cat_status("sym", t)

    def lookup(self, kind: str, target: str = "") -> LookupResult:
        """按 problem.kind 反查: 把原先散落的 if kind== 分支收敛为一次调用."""
        t = (target or "").strip().lower()
        if kind == "addr_missing":
            if t:
                return self.cap_status(f"exec:{t}")
            es = (self.by_cat.get("sym") or []) + (self.by_cat.get("backdoor") or [])
            if es:
                return LookupResult("SECTION", es,
                                    f"sym/backdoor 共 {len(es)} 项(未指定目标)")
            return LookupResult("MISS", [], "无 sym/backdoor 分区")
        if kind == "gadget_missing":
            return self.cap_status(f"gadget:{t}")
        if kind == "string_missing":
            return self.cap_status(f"str:{t}")
        if kind == "offset_wrong":
            return self.cap_status("offset:*")
        if kind in ("need_leak", "libc_missing", "libc_mismatch"):
            if self.by_cat.get("libc"):
                return LookupResult("HIT", self.by_cat["libc"], "同目录 libc 符号可用")
            return self.cap_status("exec:puts")
        return self._cat_status("", t)

    def counts(self) -> dict:
        return {c: len(self.by_cat.get(c) or []) for c in CATEGORIES}

    def to_dict(self) -> dict:
        return {"counts": self.counts(),
                "entries": [{"key": e.key, "category": e.category, "name": e.name,
                             "addr": e.addr, "detail": e.detail,
                             "source": e.source, "tags": e.tags}
                            for e in self.entries]}

    def render(self, budget: int = 40) -> str:
        """预算受限投影: 长尾分区只给计数, 避免挤爆上下文窗口."""
        L = ["[List Table 工具清单]"]
        for c in CATEGORIES:
            es = self.by_cat.get(c) or []
            if not es:
                continue
            L.append(f"· {c} ({len(es)})")
            for e in es[:budget]:
                a = f"0x{e.addr:x}" if isinstance(e.addr, int) else "-"
                L.append(f"    {a:>10}  {e.name}  <{e.source}>")
            if len(es) > budget:
                L.append(f"    ... 另 {len(es) - budget} 项")
        return "\n".join(L)