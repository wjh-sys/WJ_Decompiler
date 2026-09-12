#!/usr/bin/env python3
"""栈溢出题库批量验证: 逐题跑 refine.py, 与官方 exp 基准对照, 输出对照表.

须在 WSL/Linux 运行(refine.py 依赖 pwntools 验证真机). 用法:
    python3 test_py/run_stackoverflow_batch.py                 # 跑第一梯队(32位)
    python3 test_py/run_stackoverflow_batch.py --tier all      # 跑全部可测题目
    python3 test_py/run_stackoverflow_batch.py --only ret2libc1
    python3 test_py/run_stackoverflow_batch.py --rounds 2
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SO = os.path.join(ROOT, "test", "user-mode", "stackoverflow")

# 官方 exp 基准(offset 单位: 字节; tech 为官方技术路线; key 为官方关键地址)
CASES = [
    {"name": "ret2text", "tier": 1, "bits": 32,
     "path": f"{SO}/ret2text/bamboofox-ret2text/ret2text",
     "offset": 112, "tech": "ret2text",
     "key": "0x804863a(backdoor)"},
    {"name": "stack_example", "tier": 1, "bits": 32,
     "path": f"{SO}/stackoverflow-intro/stack-example/stack_example",
     "offset": 24, "tech": "ret2text", "key": "0x804843b(success)"},
    {"name": "ret2libc1", "tier": 1, "bits": 32,
     "path": f"{SO}/ret2libc/ret2libc1/ret2libc1",
     "offset": 112, "tech": "ret2libc", "key": "system@plt=0x8048460, /bin/sh=0x8048720"},
    {"name": "ret2libc2", "tier": 1, "bits": 32,
     "path": f"{SO}/ret2libc/ret2libc2/ret2libc2",
     "offset": 112, "tech": "ret2libc+gadget",
     "key": "gets@plt, system@plt=0x8048490, pop_ebx=0x804843d"},
    {"name": "ret2libc3", "tier": 1, "bits": 32,
     "path": f"{SO}/ret2libc/ret2libc3/ret2libc3",
     "offset": 112, "offset2": 104, "tech": "leak(puts)",
     "key": "puts@plt 泄漏, 二次偏移 104"},
    {"name": "ret2shellcode", "tier": 1, "bits": 32,
     "path": f"{SO}/ret2shellcode/ret2shellcode-example/ret2shellcode",
     "offset": 112, "tech": "ret2shellcode", "key": "buf2=0x804a080, NX off"},
    {"name": "train_ret2libc", "tier": 1, "bits": 32,
     "path": f"{SO}/ret2libc/train.cs.nctu.edu.tw/ret2libc/ret2libc",
     "offset": 32, "tech": "leak(program prints)",
     "key": "程序自打印 sh/puts 地址"},
    {"name": "ropasaurusrex", "tier": 1, "bits": 32,
     "path": f"{SO}/rop/2013-PlaidCTF-ropasaurusrex/ropasaurusrex",
     "offset": 140, "tech": "ROP leak(write)",
     "key": "write@plt 泄漏, pop3_ret=0x80484b6"},
    {"name": "shellcode_x64", "tier": 2, "bits": 64,
     "path": f"{SO}/ret2shellcode/sniperoj-pwn100-shellcode-x86-64/shellcode",
     "offset": 24, "tech": "ret2shellcode(x64)",
     "key": "程序泄漏 buf 地址"},
    {"name": "hitcon_level5", "tier": 2, "bits": 64,
     "path": f"{SO}/ret2__libc_csu_init/hitcon-level5/level5",
     "offset": 136, "tech": "ret2csu",
     "key": "csu_end=0x40061a, csu_front=0x400600"},
    {"name": "r0pbaby", "tier": 2, "bits": 64,
     "path": f"{SO}/rop/2015-Defcon Qualifier R0pbaby/r0pbaby",
     "offset": 8, "tech": "menu leak(system)+pop rdi",
     "key": "pop_rdi off=0x21102, 菜单泄漏 system"},
]

TECH_HINT = {
    "ret2text": ["backdoor", "win", "success", "system@plt", "ret2text"],
    "ret2libc": ["system", "bin/sh", "/bin/sh"],
    "ret2libc+gadget": ["pop", "system"],
    "leak(puts)": ["puts", "leak", "recv", "u32"],
    "leak(program prints)": ["recv", "leak", "u32"],
    "ret2shellcode": ["shellcraft", "asm", "shellcode"],
    "ret2shellcode(x64)": ["shellcode", "asm", "\\x0f\\x05"],
    "ROP leak(write)": ["write", "read", "got", "pop"],
    "ret2csu": ["csu", "pop r", "pop_r"],
    "menu leak(system)+pop rdi": ["system", "pop rdi", "rdi"],
}

def _run_one(case: dict, rounds: int, theta: float, timeout: int) -> dict:
    out_name = f"batch_{case['name']}.json"
    cmd = [sys.executable, os.path.join(ROOT, "refine.py"), case["path"],
           "--rounds", str(rounds), "--theta", str(theta),
           "--json-out", out_name, "--no-color"]
    rec = {"name": case["name"], "status": "?", "score": 0.0, "pass": False,
           "offset": None, "offset_ok": None, "tech": case["tech"],
           "tech_ok": None, "gaps": [], "note": "", "ms": 0}
    import time
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=timeout)
        rec["ms"] = int((time.time() - t0) * 1000)
        if r.returncode == 2:
            rec["status"] = "SKIP(large/static)"
            rec["note"] = "is_large_static 跳过"
            return rec
        rep_path = os.path.join(ROOT, "reports", out_name)
        if not os.path.isfile(rep_path):
            rec["status"] = "NO_REPORT"
            rec["note"] = (r.stderr or b"")[-200:].decode("utf-8", "replace")
            return rec
        with open(rep_path, encoding="utf-8") as f:
            data = json.load(f)
        d = data.get("_deliverable") or {}
        rec["status"] = d.get("status", "?")
        rec["score"] = float(d.get("score") or 0.0)
        rec["pass"] = bool(d.get("ready_to_use"))
        rec["gaps"] = [g.get("kind", "?") for g in (d.get("gaps") or [])]
        # 偏移比对
        off = d.get("offset") or ""
        try:
            off_num = int(str(off), 0)
        except Exception:
            off_num = None
        rec["offset"] = off_num
        cand = {case.get("offset"), case.get("offset2")}
        cand.discard(None)
        rec["offset_ok"] = (off_num in cand) if off_num is not None else False
        # 技术路线比对
        blob = (d.get("exp_code") or "") + " " + " ".join(d.get("payload_layout") or [])
        hints = TECH_HINT.get(case["tech"], [])
        rec["tech_ok"] = any(h.lower() in blob.lower() for h in hints) if hints else None
    except subprocess.TimeoutExpired:
        rec["status"] = "TIMEOUT"
        rec["note"] = f">{timeout}s"
    except Exception as e:
        rec["status"] = "ERROR"
        rec["note"] = str(e)[:160]
    return rec

def _fmt_table(rows: list) -> str:
    head = f"{'题目':<18}{'位':>3}{'状态':<14}{'完成度':>7}{'偏移':>7}{'基准':>7}{'偏离':>5}{'技术':>5}{'gap':>4}"
    sep = "-" * 90
    lines = [head, sep]
    for r in rows:
        m = {c["name"]: c for c in CASES}[r["name"]]
        off = f"0x{r['offset']:x}" if r["offset"] is not None else "-"
        base = f"0x{m['offset']:x}" if m.get("offset") else "-"
        ok = "✔" if r["offset_ok"] else ("✘" if r["offset_ok"] is False else "-")
        tk = "✔" if r["tech_ok"] else ("✘" if r["tech_ok"] is False else "-")
        lines.append(f"{r['name']:<18}{m['bits']:>3}{r['status']:<14}"
                     f"{r['score'] * 100:>6.1f}%{off:>7}{base:>7}{ok:>5}{tk:>5}"
                     f"{len(r['gaps']):>4}")
    return "\n".join(lines)

def main() -> int:
    ap = argparse.ArgumentParser(prog="run_stackoverflow_batch",
                                 description="栈溢出题库批量验证(refine.py 对照官方 exp)")
    ap.add_argument("--tier", choices=["1", "2", "all"], default="1",
                    help="1=32位第一梯队(默认), 2=64位, all=全部")
    ap.add_argument("--only", default=None, help="仅跑指定题目名")
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--theta", type=float, default=0.95)
    ap.add_argument("--timeout", type=int, default=300, help="单题超时秒数")
    args = ap.parse_args()

    sel = [c for c in CASES if args.tier == "all" or str(c["tier"]) == args.tier]
    if args.only:
        sel = [c for c in CASES if c["name"] == args.only]
    if not sel:
        print("[错误] 无匹配题目", file=sys.stderr)
        return 1

    print(f"[*] 待测 {len(sel)} 题: {', '.join(c['name'] for c in sel)}\n")
    rows = []
    for i, c in enumerate(sel, 1):
        print(f"[{i}/{len(sel)}] {c['name']} ...", flush=True)
        rec = _run_one(c, args.rounds, args.theta, args.timeout)
        rows.append(rec)
        print(f"     -> {rec['status']}  score={rec['score']*100:.1f}%  "
              f"offset={rec['offset']}  gaps={rec['gaps']}")

    print("\n" + "=" * 90)
    print("栈溢出题库验证对照表")
    print("=" * 90)
    print(_fmt_table(rows))
    n_ok = sum(1 for r in rows if r["pass"])
    n_off = sum(1 for r in rows if r["offset_ok"])
    n_tech = sum(1 for r in rows if r["tech_ok"])
    print("-" * 90)
    print(f"总计 {len(rows)} 题 | PASS {n_ok} | 偏移符合 {n_off} | "
          f"技术符合 {n_tech} | 平均完成度 "
          f"{sum(r['score'] for r in rows) / max(1, len(rows)) * 100:.1f}%")

    out = os.path.join(ROOT, "reports", "batch_summary.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)
    print(f"\n[+] 明细已写入 {out}")
    return 0

if __name__ == "__main__":
    sys.exit(main())