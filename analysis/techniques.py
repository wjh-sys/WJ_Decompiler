"""经典栈溢出利用技术路线表 (Knowledge Base).

每个 Route 用 requires 声明前置能力, 可行性由 ListTable 反查得出:
  AVAILABLE = 全部前置满足 / PARTIAL = 部分满足 / BLOCKED = 全部缺失

三重用途:
  1. 方向推荐: 供 LLM 在 prompt 中挑选可行路线, 而非只想到 system@plt + /bin/sh
  2. 路线评分: status -> 可行度, 与 EXP 实际所走路线(infer_route) 匹配后计分
  3. 缺口定位: missing 直接列出差哪些能力, 供 resolver 精确反查

权重/阈值不放这里(属 Algorithm 2), 本模块只给"可能性"与"证据引用".
"""
from __future__ import annotations

from dataclasses import dataclass, field

@dataclass
class Route:
    name: str
    family: str
    requires: list = field(default_factory=list)
    status: str = "BLOCKED"
    satisfied: list = field(default_factory=list)
    missing: list = field(default_factory=list)
    note: str = ""
    advisory: bool = False
    rank: int = 50      # 策略层优先级: 越小越优先. 与 status(能力层)正交.

# rank 五波段(依据: 直达 shell 的程度 = 阶段数 + 前置依赖数):
#   10s 直达(单阶段, 无需泄漏) | 20s 两阶段(需泄漏基址)
#   30s 专用技巧(缺常规手段时的替代) | 40s 辅助/通用(通常组合使用, 非首选)
#   50s 受限兜底(仅在溢出空间不足等约束下) | 60s 仅提示不计分

STATUS_SCORE = {"AVAILABLE": 1.0, "PARTIAL": 0.5, "BLOCKED": 0.0}

TECHNIQUES = [
    Route("ret2text", "control-flow", ["offset:*", "bd:*"], rank=10,
          note="有后门/win 函数且偏移已知: 直接把返回地址改为后门(依赖最少)"),
    Route("ret2shellcode", "shellcode", ["offset:*", "prot:nx_off"], rank=11,
          note="NX 关闭: 跳到可写可执行区执行 shellcode"),
    Route("ret2libc", "libc", ["offset:*", "exec:system", "str:/bin/sh"], rank=12,
          note="有 system 与 /bin/sh: 直接 system('/bin/sh')"),
    Route("ret2libc-leak", "libc", ["offset:*", "exec:puts", "libc:puts"], rank=20,
          note="需先泄漏 libc 基址: 两阶段 ret2libc"),
    Route("ret2csu", "gadget", ["offset:*", "func:__libc_csu_init", "arch:bits64"], rank=30,
          note="64 位缺 pop rdx/rsi: 用 __libc_csu_init 万能序列(仅 64 位)"),
    Route("ret2syscall", "syscall",
          ["offset:*", "gadget:int 0x80", "gadget:pop eax", "arch:bits32"], rank=31,
          note="32 位: 经 int 0x80 直接 execve('/bin/sh')"),
    Route("srop", "syscall",
          ["offset:*", "gadget:syscall", "gadget:pop rax", "arch:bits64"], rank=32,
          note="64 位: sigreturn 使全部寄存器可控(仅 64 位)"),
    Route("ret2dlresolve", "gadget", ["offset:*", "sym:read"], rank=33,
          note="无 system@plt 且无 libc: 伪造符号解析"),
    Route("ret2rop", "gadget", ["offset:*", "gadget:pop"], rank=40,
          note="通用 ROP 链: 组合寄存器 gadget 调任意函数(无特定目标, 非首选)"),
    Route("format-leak", "format", ["offset:*", "sym:printf"], rank=41,
          note="格式化字符串泄漏 canary/libc/栈地址(通常作为其他路线的前置)"),
    Route("canary-bypass", "canary", ["offset:*", "sym:printf", "prot:canary_on"], rank=42,
          note="先泄 canary, 再正常溢出覆盖返回地址(仅在 Canary 开启时适用)"),
    Route("stack-pivot", "stack",
          [["gadget:leave", "gadget:jmp esp", "gadget:jmp rsp"]], rank=50,
          note="溢出空间不足: 用 leave;ret 或 jmp esp/寄存器 把栈迁移到可控区"),
    Route("partial-overwrite", "control-flow", ["offset:*", "prot:pie_on"], rank=60,
          note="只覆盖返回地址低字节(1~2 byte)绕 PIE/ASLR, 需爆破", advisory=True),
]

# 路线签名: 每条路线是若干"签名组", 任一组内子串全部出现才算命中(AND),
# 组间为或(OR). 仅"提及某词"(注释/占位地址/banner)不再构成命中.
ROUTE_MARKERS = {
    "ret2text": [["backdoor"], ["win("], ["get_shell"], ["shell()"],
                 ["success_addr"], ["backdoor_addr"], ["win_addr"],
                 ["getshell"], ["p32(target)"], ["p64(target)"]],
    "ret2shellcode": [["shellcraft"], ["asm("], ["shellcode"]],
    "ret2libc": [["/bin/sh"], ["str_bin_sh"], ["binsh"], ["libc.symbols"]],
    "ret2libc-leak": [["libc_base"], ["libc.address"], ["__libc_start_main"],
                      ["u32(", "recv"], ["u64(", "recv"],
                      ["u32(", "got"], ["u64(", "got"], ["elf.got"]],
    "ret2csu": [["__libc_csu_init"], ["csu_front"], ["csu_end"], ["csu"]],
    "ret2dlresolve": [["ret2dlresolve"], ["dlresolve"]],
    "ret2syscall": [["int 0x80"], ["pop ebx", "pop ecx", "pop edx"],
                    ["execve"]],
    "srop": [["sigreturn"], ["srop"]],
    "ret2rop": [["rop."], ["rop("], ["pop_rdi"], ["pop rdi"], ["flat("]],
    "stack-pivot": [["pivot"], ["xchg eax, esp"], ["xchg rax, rsp"],
                    ["jmp esp"], ["jmp rsp"], ["push esp"], ["push rsp"]],
    "format-leak": [["fmtstr"], ["%p"], ["format_string"], ["%n"]],
    "canary-bypass": [["canary"], ["__stack_chk"]],
    "partial-overwrite": [["partial"], ["低字节"], ["p8("], ["p16("],
                          ["爆破"], ["brute"]],
}

def eval_routes(table, techs=None) -> list:
    """用 ListTable 反查每条路线的前置能力, 返回带 status 的路线副本(不污染模板)."""
    out = []
    for t in (techs or TECHNIQUES):
        sat, miss = [], []
        for cap in t.requires:
            # 字符串=单项能力(与其他项 AND); 列表/元组=可替代项(内部 OR)
            if isinstance(cap, (list, tuple)):
                sts = [table.cap_status(c).status for c in cap]
                ok = any(s in ("HIT", "DERIVED") for s in sts)
                (sat if ok else miss).append("|".join(cap))
            else:
                st = table.cap_status(cap).status
                (sat if st in ("HIT", "DERIVED") else miss).append(cap)
        status = "AVAILABLE" if not miss else ("PARTIAL" if sat else "BLOCKED")
        out.append(Route(name=t.name, family=t.family, requires=list(t.requires),
                         status=status, satisfied=sat, missing=miss, note=t.note,
                         advisory=getattr(t, "advisory", False),
                         rank=getattr(t, "rank", 50)))
    return out

def route_order(r) -> tuple:
    """策略排序键: 先按能力状态, 同状态内按 rank(越小越优先)."""
    return ({"AVAILABLE": 0, "PARTIAL": 1, "BLOCKED": 2}.get(r.status, 3), r.rank)

def rank_routes(routes) -> list:
    """按策略优先级排序路线: 首选路线排在前, 供 LLM 按顺序择一."""
    return sorted(routes, key=route_order)

def scoring_routes(routes) -> list:
    """仅参与计分的路线: 排除 advisory 纯提示项(如 partial-overwrite)."""
    return [r for r in routes if not getattr(r, "advisory", False)]

def render_routes(routes) -> str:
    """路线推荐投影: 只给 AVAILABLE/PARTIAL, 按策略优先级排序并标出首选."""
    L = ["[可选利用方向](已按策略优先级排序, 请优先选择靠前者, "
         "并在 payload_layout 中说明所选路线)"]
    advance = [r for r in rank_routes(routes)
               if not r.advisory and r.status != "BLOCKED"]
    avail = [r for r in advance if r.status == "AVAILABLE"]
    best = avail[0].name if avail else ""
    for r in advance:
        tag = "可用" if r.status == "AVAILABLE" else "部分可用"
        star = " ★首选" if r.name == best else ""
        L.append(f"  [{tag}] {r.name} <{r.family}>{star}  {r.note}")
        if r.missing:
            L.append(f"        缺口: {', '.join(r.missing)}")
        if star:
            L.append("        说明: 依赖最少且单阶段直达, 除非有反向证据否则优先采用")
    hints = [r for r in routes if r.advisory and r.status != "BLOCKED"]
    if hints:
        L.append("[仅作提示, 不计分]")
        for r in hints:
            L.append(f"  {r.name}: {r.note}")
    return "\n".join(L)

def _sig_hit(groups, low: str) -> bool:
    """AND 签名组匹配: 组内子串须全部出现; 任一组成立即命中."""
    return any(all(m in low for m in grp) for grp in groups)

def infer_route(blob: str, routes=None) -> list:
    """从 EXP 代码/payload 描述反推实际采用的路线, 仅保留可行路线.

    命中采用 AND 签名组: 组内子串须同时出现,
    避免"注释/占位地址/banner 仅提及某词"造成误判.
    """
    low = (blob or "").lower()
    hit = [name for name, groups in ROUTE_MARKERS.items() if _sig_hit(groups, low)]
    if routes is None:
        return hit
    ok = {r.name for r in routes if r.status != "BLOCKED" and not r.advisory}
    return [n for n in hit if n in ok]