#!/usr/bin/env python3
"""EXP 对照: 官方题解 vs 项目生成产物(并排 + 结构化差异).

用法:
    # 1) 先生成(另开终端, WSL + venv)
    python3 analyze.py <binary> --refine --rounds 3 --json-out cmp.json --no-color
    # 2) 再对照(自动识别 reports/ 下的 batch_<名>.json 或 <名>.json)
    python3 test_py/compare_exp.py <binary>
    python3 test_py/compare_exp.py <binary> --gen reports/cmp.json

对比维度: 偏移 / 技术路线 / 是否需泄漏 / 交互点 / 关键地址 / Py2-Py3 兼容性
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
for p in (ROOT, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from analysis.techniques import infer_route          # noqa: E402
from calibrate_weights import find_exp               # noqa: E402

ADDR = re.compile(r"0x[0-9a-fA-F]{4,12}")
PAD = re.compile(r"(?:['\"][\w\\x]+['\"]|\w+)\s*\*\s*(0x[0-9a-fA-F]+|\d+)")
LEAK = re.compile(r"u32\s*$|u64\s*\(|recv\s*\(\s*[48]\s*$|libc_base|LibcSearcher")
RECV = re.compile(r"\brecv(?:until|line|some)?\s*\(")
SEND = re.compile(r"\bsend(?:line|after)?\s*\(")
PY2 = re.compile(r"\bprint\s+[^(\s]|\w+\s*=\s*\"[^\"]*\\x|ljust\(\s*\d+\s*,\s*'[^']*'")

def est_offset(code: str) -> str:
    """官方偏移估计: 取填充常量最大值 + 保存值(4/8). 仅供粗比, 生成侧以 JSON 为准."""
    vals = []
    for m in PAD.finditer(code):
        try:
            vals.append(int(m.group(1), 0))
        except ValueError:
            pass
    return f"0x{max(vals):x}(+保存值)" if vals else "-"

def summarize(code: str) -> dict:
    return {
        "routes": sorted(set(infer_route(code))),
        "addrs": sorted({m.group(0).lower() for m in ADDR.finditer(code)}),
        "leak": bool(LEAK.search(code)),
        "recv": len(RECV.findall(code)),
        "send": len(SEND.findall(code)),
        "py2": bool(PY2.search(code)),
        "lines": len([x for x in code.splitlines() if x.strip()]),
    }

def load_gen(binary: str, gen: str | None) -> str:
    stem = os.path.splitext(os.path.basename(binary))[0]
    cands = [gen] if gen else [f"reports/batch_{stem}.json", f"reports/{stem}.json"]
    for c in cands:
        if not c:
            continue
        p = c if os.path.isabs(c) else os.path.join(ROOT, c)
        if not os.path.isfile(p):
            continue
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        dl = d.get("_deliverable") or {}
        code = dl.get("exp_code") or (d.get("exploit_plan") or {}).get("exp_code") or ""
        meta = {"stage": dl.get("stage"), "score": dl.get("score"),
                "offset": dl.get("offset"), "gaps": [g.get("kind") for g in (dl.get("gaps") or [])],
                "used": dl.get("route_used"), "verdict": dl.get("verdict"),
                "available": dl.get("routes_available")}
        return code, meta, os.path.relpath(p, ROOT)
    return "", {}, "(未找到生成产物, 请先用 analyze.py --refine --json-out 生成)"

def main() -> int:
    ap = argparse.ArgumentParser(prog="compare_exp", description="官方 exp vs 项目生成对照")
    ap.add_argument("binary")
    ap.add_argument("--gen", default=None, help="生成产物 JSON 路径(默认自动识别 reports/)")
    ap.add_argument("--head", type=int, default=30, help="每侧最多显示行数")
    args = ap.parse_args()

    official_path = find_exp(args.binary)
    if not official_path:
        print(f"[!] 未找到官方 exp(与二进制同目录)", file=sys.stderr)
        return 1
    with open(official_path, encoding="utf-8", errors="replace") as f:
        off_src = f.read()
    gen_src, meta, gen_from = load_gen(args.binary, args.gen)

    print("=" * 78)
    print(f"EXP 对照: {os.path.basename(args.binary)}")
    print("=" * 78)
    for tag, src, src_from in (("官方题解", off_src, os.path.relpath(official_path, ROOT)),
                               ("项目生成", gen_src, gen_from)):
        print(f"\n--- {tag}  <{src_from}> ---")
        lines = [x for x in src.splitlines() if x.strip()]
        for ln in lines[:args.head]:
            print("  " + ln)
        if len(lines) > args.head:
            print(f"  ...(另 {len(lines) - args.head} 行)")

    if not gen_src:
        print("\n[!] 无生成产物, 仅展示官方题解")
        return 1

    o, g = summarize(off_src), summarize(gen_src)
    print("\n--- 结构化对比 ---")
    rows = [
        ("技术路线", " ".join(o["routes"]) or "-", " ".join(g["routes"]) or "-"),
        ("需泄漏", "是" if o["leak"] else "否", "是" if g["leak"] else "否"),
        ("偏移", est_offset(off_src), str(meta.get("offset") or "-")),
        ("代码行数", str(o["lines"]), str(g["lines"])),
        ("交互点 recv/send", f'{o["recv"]}/{o["send"]}', f'{g["recv"]}/{g["send"]}'),
        ("Py2 语法", "是(需改)" if o["py2"] else "否", "是(需改)" if g["py2"] else "否"),
        ("关键地址数", str(len(o["addrs"])), str(len(g["addrs"]))),
        ("验证阶段", "-", str(meta.get("stage") or "-")),
        ("完成度", "-", str(meta.get("score") or "-")),
        ("终止判定", "-", str(meta.get("verdict") or "-")),
        ("缺口", "-", ", ".join(meta.get("gaps") or []) or "无"),
    ]
    w = max(len(r[0]) for r in rows)
    print(f"{'项目'.ljust(w)}   {'官方题解':<32}{'项目生成'}")
    for k, a, b in rows:
        print(f"{k.ljust(w)}   {a:<32}{b}")
    inter = set(o["addrs"]) & set(g["addrs"])
    print(f"\n地址交集({len(inter)}): {' '.join(sorted(inter)) or '-'}")
    print(f"仅官方({len(set(o['addrs']) - inter)}): {' '.join(sorted(set(o['addrs']) - inter)) or '-'}")
    print(f"仅生成({len(set(g['addrs']) - inter)}): {' '.join(sorted(set(g['addrs']) - inter)) or '-'}")
    return 0

if __name__ == "__main__":
    sys.exit(main())