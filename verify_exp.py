"""WJ_Decompiler - LLM 生成 EXP 的本地自动验证器(方案A).

在 WSL/Linux 中运行(需要 pwntools,且目标是 Linux ELF):
    python3 verify_exp.py <binary> <report.json> [--flag 文件路径] [--timeout 秒]

<binary>      : 目标 ELF 的真实路径(如 ./ret2text)
<report.json> : analyze.py --json-out 导出的结构化报告(含 exploit_plan)

原理:
    1. 从 report 的 exploit_plan.exp_code 中提取 "payload = ..." 与后续
       "payload += ..." 行,用 pwntools 的 p32/p64/flat 等沙箱化求值,
       得到真实 payload 字节(完全复用 LLM 的利用构造,但不执行它的
       process()/interactive()/recv 包装代码)。
    2. 自己 spawn 目标、发 payload,保持 stdin 打开,再发探活命令。
    3. 判定: 输出含随机标记 => 拿到 shell/命令执行 => PASS。
"""
from __future__ import annotations

import argparse
import json
import random
import re
import string
import sys
import time

def _load_report(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def _extract_payload_lines(exp_code: str) -> list[str]:
    """从 exp_code 提取 payload 构造语句(payload = / payload += ...)."""
    lines = []
    for ln in exp_code.splitlines():
        s = ln.strip()
        if re.match(r"^payload\s*(\+=|=)", s):
            # 去掉行尾注释
            s = re.sub(r"\s*#.*$", "", s).strip()
            lines.append(s)
    return lines

def _build_payload(exp_code: str, binary: str) -> bytes | None:
    """沙箱化求值 payload 构造行,返回字节."""
    lines = _extract_payload_lines(exp_code)
    if not lines:
        return None
    # 注入 pwntools 常用打包/解包函数,使 payload += p32(...) 可求值
    env: dict = {"__builtins__": __builtins__}
    try:
        from pwn import p8, p16, p32, p64, u8, u16, u32, u64, flat, context, ELF
        env.update({"p8": p8, "p16": p16, "p32": p32, "p64": p64,
                    "u8": u8, "u16": u16, "u32": u32, "u64": u64,
                    "flat": flat})
        context.binary = binary
        env["context"] = context
        env["elf"] = ELF(binary)
        env["ELF"] = ELF
    except Exception:
        pass  # 无 pwntools 时仅支持纯 bytes/整数构造
    src = "\n".join(lines)
    try:
        code = compile(src, "<exp>", "exec")
        exec(code, env)
    except Exception as e:
        print(f"[!] payload 求值失败: {e}")
        return None
    payload = env.get("payload")
    if payload is None:
        return None
    if isinstance(payload, str):
        payload = payload.encode("latin-1", errors="replace")
    if not isinstance(payload, (bytes, bytearray)):
        return None
    return bytes(payload)

def _try_pwn(binary: str, payload: bytes, flag_path: str | None,
             timeout: float) -> tuple[bool, str, str]:
    """spawn + 发 payload + 探活. 返回 (成功?, stdout, stderr)."""
    from pwn import process, context
    context.log_level = "error"
    marker = "PWNED_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))

    try:
        p = process([binary])
    except Exception as e:
        return False, "", f"spawn 失败: {e}"

    out_chunks: list[str] = []
    try:
        # 先读一点初始输出(可选,容错)
        try:
            p.recv(timeout=0.3)
        except Exception:
            pass
        p.sendline(payload)
        time.sleep(0.2)
        # 探活: 若能拿到 shell,echo 会回显标记
        p.sendline(f"echo {marker}".encode())
        if flag_path:
            p.sendline(b"cat " + flag_path.encode() + b" 2>/dev/null")
            p.sendline(b"cat flag* 2>/dev/null")
        # 收集输出
        deadline = time.time() + timeout
        collected = b""
        while time.time() < deadline:
            try:
                chunk = p.recv(timeout=0.3)
            except Exception:
                break
            if not chunk:
                break
            collected += chunk
            if marker.encode() in collected:
                break
        out_chunks.append(collected.decode(errors="replace"))
    except Exception as e:
        out_chunks.append(f"[异常] {e}")
    finally:
        try:
            p.close()
        except Exception:
            pass

    stdout = "\n".join(out_chunks)
    ok = marker in stdout
    reason = f"命令回显命中({marker}),已获得 shell/命令执行" if ok else "未见标记回显"
    if flag_path and not ok:
        # flag 文件内容出现也算成功
        if re.search(r"flag\{[^}]*\}|ctf\{[^}]*\}|[A-Z0-9]{16,}", stdout):
            ok = True
            reason = "输出包含疑似 flag 内容"
    return ok, reason, stdout

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="verify_exp",
        description="验证 analyze.py 生成的 EXP 是否真的能打通(方案A, 需在 WSL/Linux 运行)",
    )
    ap.add_argument("binary", help="目标 ELF 路径(相对当前目录,如 ./ret2text)")
    ap.add_argument("report", help="analyze.py --json-out 导出的 JSON 报告")
    ap.add_argument("--flag", default=None, help="题目目录下 flag 文件名(存在时自动 cat 探测)")
    ap.add_argument("--timeout", type=float, default=3.0, help="探活等待秒数(默认 3)")
    args = ap.parse_args()

    try:
        rep = _load_report(args.report)
    except Exception as e:
        print(f"[错误] 读取报告失败: {e}", file=sys.stderr)
        return 2

    ep = rep.get("exploit_plan") or {}
    exp_code = ep.get("exp_code") or ""
    if not exp_code:
        print("[FAIL] 报告中 exploit_plan.exp_code 为空,无法验证", file=sys.stderr)
        return 1

    print("=== 目标信息 ===")
    print(f"vulnerability_type : {rep.get('vulnerability_type')}")
    print(f"漏洞函数           : {rep.get('vulnerable_function')}")
    print(f"offset             : {ep.get('offset')}")
    if ep.get("payload_layout"):
        print("payload_layout     :")
        for item in ep["payload_layout"]:
            print(f"  - {item}")
    print(f"verification       : {ep.get('verification')}")
    print()

    payload = _build_payload(exp_code, args.binary)
    if payload is None:
        print("[FAIL] 无法从 exp_code 提取/求值 payload 构造逻辑", file=sys.stderr)
        print("---- exp_code ----")
        print(exp_code)
        return 1
    print(f"[*] 提取到 payload {len(payload)} 字节")
    print(f"[*] 前 32 字节: {payload[:32].hex()}")

    ok, reason, stdout = _try_pwn(args.binary, payload, args.flag, args.timeout)
    print(f"\n判定: {'PASS' if ok else 'FAIL'}  {reason}")
    if stdout:
        print("---- 程序输出(截断) ----")
        print(stdout[:800])
    print()
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())