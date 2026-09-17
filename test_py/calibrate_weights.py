#!/usr/bin/env python3
"""Algorithm 2 离线校准: 用题库官方 exp 校验路线反推与能力模型.

不依赖 LLM/网络, 纯静态, 可在 WSL 或本机直接跑:
    python3 test_py/calibrate_weights.py
    python3 test_py/calibrate_weights.py --verbose

每项校验都以"官方题解"为 ground truth:
  1) 偏移实测 : taint 静态测出的 offset 是否等于官方题解使用的 offset
  2) 路线反推 : infer_route(官方 exp 源码) 是否命中该题官方技术路线(查全率)
  3) 模型自洽 : 官方路线是否被 eval_routes 判为 AVAILABLE(能力模型无假阴性)

第 1 项错 -> 偏移子分恒为 0; 第 3 项错 -> 分数上限被锁死.
这两项是权重体系的上游, 上游错则任何权重都无意义.
"""
from __future__ import annotations

import argparse
import os
import sys
from types import SimpleNamespace as NS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
for p in (ROOT, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from run_stackoverflow_batch import CASES, EXPECT_ROUTE   # noqa: E402
from analysis.listtable import ListTable                  # noqa: E402
from analysis.techniques import eval_routes, infer_route  # noqa: E402
from analyze import score_exp                             # noqa: E402

EXP_PRIORITY = ("exploit.py", "exp.py", "solve.py")
SKIP_NAMES = {"__init__.py", "roputils.py", "roptool.py"}

def find_exp(binary_path: str) -> str | None:
    """在二进制同目录找官方 exp 源码(优先惯用名, 其次同名 .py)."""
    d = os.path.dirname(binary_path)
    stem = os.path.splitext(os.path.basename(binary_path))[0]
    try:
        files = os.listdir(d)
    except OSError:
        return None
    for name in EXP_PRIORITY:
        if name in files:
            return os.path.join(d, name)
    for cand in (f"{stem}.py", f"{stem}_exp.py"):
        if cand in files:
            return os.path.join(d, cand)
    rest = [f for f in sorted(files)
            if f.endswith(".py") and f not in SKIP_NAMES
            and not f.startswith("stage") and "manual" not in f
            and "roptool" not in f]
    return os.path.join(d, rest[0]) if rest else None

def load_evidence(binary_path: str):
    from loader import guess_loader
    from disasm import Disassembler
    from analysis import CallGraph, analyze, is_large_static
    prog = guess_loader(binary_path).load()
    if is_large_static(prog, binary_path):
        raise RuntimeError("large/static, skipped")
    graph = CallGraph(prog, Disassembler(prog))
    graph.build()
    return analyze(prog, graph, binary_path)

def run_case(case: dict, verbose: bool) -> dict:
    rec = {"name": case["name"], "bits": case["bits"], "static_off": None,
           "off_ok": None, "used": [], "expect": [], "recall_ok": None,
           "avail": [], "model_ok": None, "raw": None, "err": ""}
    exp_file = find_exp(case["path"])
    if not exp_file or not os.path.isfile(exp_file):
        rec["err"] = "no exp file"
        return rec
    try:
        with open(exp_file, encoding="utf-8", errors="replace") as f:
            src = f.read()
        ev = load_evidence(case["path"])
    except Exception as exc:
        rec["err"] = str(exc)[:80]
        return rec

    table = ListTable.from_evidence(ev)
    rec["static_off"] = ev.overflow[0].offset_to_ret if ev.overflow else None
    rec["off_ok"] = (rec["static_off"] == case["offset"])
    rec["used"] = infer_route(src)
    rec["expect"] = list(EXPECT_ROUTE.get(case["tech"], []))
    if rec["expect"]:
        rec["recall_ok"] = bool(set(rec["used"]) & set(rec["expect"]))
    rec["avail"] = sorted({r.name for r in eval_routes(table)
                           if r.status == "AVAILABLE"})
    if rec["expect"]:
        rec["model_ok"] = bool(set(rec["expect"]) & set(rec["avail"]))

    J = NS(confidence=1.0, exploit_plan=NS(offset=str(case["offset"]),
                                           exp_code=src, payload_layout=[]))
    F = NS(ok=False, stage="no_marker")
    A = NS(score=1.0, evidence="静态证据: 实测偏移与官方题解一致, 路线与官方技术路线匹配",
           problems=[])
    rec["raw"] = score_exp(J, ev, F, A, table=table).raw
    if verbose:
        print(f"    exp={os.path.basename(exp_file)}  used={rec['used']}  "
              f"expect={rec['expect']}")
    return rec

def fmt_row(r: dict) -> str:
    def mark(v):
        return "-" if v is None else ("OK" if v else "NG")
    off = f"0x{r['static_off']:x}" if r["static_off"] is not None else "-"
    raw = f"{r['raw']:.3f}" if r["raw"] is not None else "-"
    return (f"{r['name']:<18}{r['bits']:>4}{off:>7}{mark(r['off_ok']):>5}"
            f"{mark(r['recall_ok']):>6}{mark(r['model_ok']):>6}{raw:>8}"
            f"   {r['err']}")

def main() -> int:
    ap = argparse.ArgumentParser(prog="calibrate_weights",
                                 description="Algorithm 2 离线校准(官方 exp 作 ground truth)")
    ap.add_argument("--tier", choices=["1", "2", "all"], default="all")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    sel = [c for c in CASES if args.tier == "all" or str(c["tier"]) == args.tier]
    rows = []
    for c in sel:
        print(f"[*] {c['name']} ...", flush=True)
        rows.append(run_case(c, args.verbose))

    head = (f"{'题目':<18}{'位':>4}{'实测偏移':>7}{'偏移':>5}"
            f"{'路线':>6}{'模型':>6}{'raw':>8}")
    print("\n" + head)
    print("-" * 70)
    for r in rows:
        print(fmt_row(r))

    n = len(rows)
    ok_off = sum(1 for r in rows if r["off_ok"])
    ok_rec = sum(1 for r in rows if r["recall_ok"])
    ok_mod = sum(1 for r in rows if r["model_ok"])
    scored = [r["raw"] for r in rows if r["raw"] is not None]
    print("-" * 70)
    print(f"共 {n} 题 | 偏移实测符合 {ok_off}/{n} | 路线反推命中 {ok_rec}/{n} | "
          f"模型覆盖官方路线 {ok_mod}/{n}")
    if scored:
        print(f"官方 exp 的 Algorithm 2 静态分(raw): 平均 {sum(scored)/len(scored):.3f}"
              f"  最低 {min(scored):.3f}  最高 {max(scored):.3f}")
    miss = [r["name"] for r in rows if r["recall_ok"] is False]
    if miss:
        print(f"\n[!] 路线反推漏报: {', '.join(miss)}  -> 需补 ROUTE_MARKERS 签名")
    nm = [r["name"] for r in rows if r["model_ok"] is False]
    # 区分根因: 偏移不可测 -> 含 offset:* 的路线全部落出 AVAILABLE,
    # 这是证据缺失导致的不可判定(已被可测性门控排除), 不是能力模型缺陷.
    blind = [n for n in nm
             if next(r for r in rows if r["name"] == n)["static_off"] is None]
    real = [n for n in nm if n not in blind]
    if blind:
        print(f"[i] 证据缺失故不可判定(非模型缺陷, 已由可测性门控排除): "
              f"{', '.join(blind)}")
    if real:
        print(f"[!] 能力模型未覆盖官方路线: {', '.join(real)}  -> 需补 requires 前置")
    return 0

if __name__ == "__main__":
    sys.exit(main())