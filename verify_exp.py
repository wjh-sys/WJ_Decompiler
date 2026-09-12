"""WJ_Decompiler - LLM 生成 EXP 的本地自动验证器

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
import hashlib
import json
import os
import random
import re
import string
import sys
import time
import traceback
from dataclasses import dataclass

STAGES = ("no_exp_code", "payload_eval", "spawn_fail", "segv",
          "timeout", "eof", "no_marker", "marker_ok")

_INTERACT = re.compile(
    r"\b(process|remote|ssh|listen|connect|send|sendline|sendafter|"
    r"recv|recvline|recvuntil|interactive|gdb|attach|wait|shell|pwnlib)\b"
)

@dataclass
class ExpFeedback:
    ok: bool = False
    stage: str = "no_exp_code"
    stdout_tail: str = ""
    exp_traceback: str = ""
    fingerprint: str = ""
    diagnosis: str = ""

def _fingerprint(stage: str, tb: str, out: str) -> str:
    raw = f"{stage}|{tb}|{out}".encode("utf-8", "replace")
    return hashlib.md5(raw).hexdigest()[:12]

def _exp_code_of(report) -> str:
    if isinstance(report, dict):
        return (report.get("exploit_plan") or {}).get("exp_code") or ""
    ep = getattr(report, "exploit_plan", None)
    return getattr(ep, "exp_code", "") or ""

def _ld_env(binary: str) -> dict:
    """若二进制同目录存在 libc, 返回让其优先加载的环境变量(减少 libc 不匹配)."""
    try:
        d = os.path.dirname(os.path.abspath(binary))
        names = sorted(os.listdir(d))
    except Exception:
        return {}
    for fn in names:
        if re.match(r"^libc[\.-]", fn) or fn.startswith("libc.so"):
            p = os.path.join(d, fn)
            if os.path.isfile(p):
                return {"LD_PRELOAD": p, "LD_LIBRARY_PATH": d}
    return {}

def _load_report(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def _extract_payload_lines(exp_code: str) -> list[str]:
    """从 exp_code 提取可沙箱求值的构造语句.

    保留: import 语句 + 变量赋值(含 payload/offset/system_plt 等依赖定义);
    剔除: 与目标交互的语句(process/remote/send/recv/interactive 等), 这些会
          spawn/连接进程, 不能在此沙箱执行。
    """
    lines = []
    for ln in exp_code.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        s = re.sub(r"\s*#.*$", "", s).strip()
        if not s:
            continue
        if re.match(r"^(import|from)\s", s):
            lines.append(s)
            continue
        if re.match(r"^[A-Za-z_]\w*\s*(\+?=)", s):
            if _INTERACT.search(s):
                continue
            lines.append(s)
    return lines

def _build_payload(exp_code: str, binary: str) -> tuple[bytes | None, str]:
    """沙箱化求值 payload 构造行,返回 (字节, 错误描述)."""
    lines = _extract_payload_lines(exp_code)
    if not lines:
        return None, "未找到可求值的构造语句(赋值/import 行)"
    # 注入 pwntools 常用打包/解包函数,使 payload += p32(...) 可求值
    env: dict = {"__builtins__": __builtins__}
    try:
        from pwn import p8, p16, p32, p64, u8, u16, u32, u64, flat, context, ELF
        env.update({"p8": p8, "p16": p16, "p32": p32, "p64": p64,
                    "u8": u8, "u16": u16, "u32": u32, "u64": u64,
                    "flat": flat})
        context.log_level = "error"
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
    except Exception:
        return None, traceback.format_exc()
    payload = env.get("payload")
    if payload is None:
        return None, "payload 变量未定义"
    if isinstance(payload, str):
        payload = payload.encode("latin-1", errors="replace")
    if not isinstance(payload, (bytes, bytearray)):
        return None, f"payload 类型不支持: {type(payload)}"
    return bytes(payload), ""

def _try_pwn(binary: str, payload: bytes, flag_path: str | None,
             timeout: float) -> tuple[bool, str, str, str]:
    """spawn + 发 payload + 探活. 返回 (成功?, stage, 说明, stdout)."""
    from pwn import process, context
    context.log_level = "error"
    marker = "PWNED_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))

    env = _ld_env(binary)
    try:
        p = process([binary], env={**os.environ, **env}) if env else process([binary])
    except Exception as e:
        return False, "spawn_fail", f"spawn 失败: {e}", ""

    out_chunks: list[str] = []
    try:
        try:
            p.recv(timeout=0.3)
        except Exception:
            pass
        p.sendline(payload)
        time.sleep(0.2)
        p.sendline(f"echo {marker}".encode())
        if flag_path:
            p.sendline(b"cat " + flag_path.encode() + b" 2>/dev/null")
            p.sendline(b"cat flag* 2>/dev/null")
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

    stdout = "\n".join(out_chunks)
    if marker in stdout:
        stage, ok = "marker_ok", True
        reason = f"命令回显命中({marker}),已获得 shell/命令执行"
    else:
        code = None
        try:
            code = p.poll(block=False)
        except Exception:
            code = None
        if code is not None and code < 0:
            stage, ok = "segv", False
            reason = f"进程被信号终止(signal {-code}),疑似崩溃"
        elif code is not None:
            stage, ok = "eof", False
            reason = f"进程正常退出(exit {code})但未见标记回显"
        else:
            stage, ok = "timeout", False
            reason = "探活超时,未见标记回显"
        if flag_path and re.search(r"flag\{[^}]*\}|ctf\{[^}]*\}|[A-Z0-9]{16,}", stdout):
            stage, ok, reason = "marker_ok", True, "输出包含疑似 flag 内容"
    try:
        p.close()
    except Exception:
        pass
    return ok, stage, reason, stdout

_RUN_PREAMBLE = (
    "import sys\n"
    "def _report(name, value):\n"
    "    try:\n"
    "        sys.stdout.write('@@VAR@@%s=%r@@END@@' % (name, value))\n"
    "        sys.stdout.flush()\n"
    "    except Exception:\n"
    "        pass\n"
    "def _probe(p, marker):\n"
    "    try:\n"
    "        p.sendline(b'echo ' + marker.encode())\n"
    "        data = p.recv(timeout=2).decode('latin-1')\n"
    "        sys.stdout.write('@@RECV_BEGIN@@' + data + '@@RECV_END@@')\n"
    "        sys.stdout.flush()\n"
    "    except Exception:\n"
    "        pass\n"
)

def _instrument_vars(script: str) -> str:
    """在疑似泄漏/基址变量赋值后插入 _report 探针(AST 注入), 用于可视化泄漏值."""
    import ast
    interesting = re.compile(r"(leak|base|system|binsh|libc)", re.I)
    try:
        tree = ast.parse(script)
    except Exception:
        return script

    def inject(body):
        out = []
        for node in body:
            out.append(node)
            name = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                name = node.target.id
            if name and interesting.search(name):
                out.append(ast.Expr(value=ast.Call(
                    func=ast.Name(id="_report", ctx=ast.Load()),
                    args=[ast.Constant(value=name),
                          ast.Name(id=name, ctx=ast.Load())],
                    keywords=[])))
        return out

    for node in list(ast.walk(tree)):
        for fld in ("body", "orelse", "finalbody"):
            lst = getattr(node, fld, None)
            if isinstance(lst, list) and lst and all(isinstance(x, ast.stmt) for x in lst):
                setattr(node, fld, inject(lst))
    try:
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except Exception:
        return script

def _diagnosis(raw: str) -> str:
    """从 _report 输出提取关键变量, 并对 libc 基址做页对齐自检."""
    import ast as _ast
    pairs = re.findall(r"@@VAR@@([^=@]+)=(.*?)@@END@@", raw, re.S)
    if not pairs:
        return ""
    lines, base = [], None
    for name, txt in pairs:
        try:
            val = _ast.literal_eval(txt.strip())
        except Exception:
            val = txt.strip()
        if isinstance(val, int):
            lines.append(f"  {name} = 0x{val:x}")
            if re.search(r"base", name, re.I):
                base = val
        else:
            lines.append(f"  {name} = {val!r}")
    lines = ["● 泄漏/关键变量:"] + lines
    if base is not None and (base & 0xfff) != 0:
        lines.append(f"  ⚠ libc 基址 0x{base:x} 未页对齐(base&0xfff=0x{base & 0xfff:x}); "
                     "疑运行时 libc 与题目目录 libc.so 不一致, 偏移不可套用")
    return "\n".join(lines)

def _try_run_exp(binary: str, exp_code: str, timeout: float):
    """真实执行整段 EXP 脚本(支持多阶段交互): 改写相对路径 + 拦截 interactive 探活."""
    import os as _os, subprocess, tempfile
    marker = "PWNED_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=10))
    base_dir = _os.path.dirname(_os.path.abspath(binary))

    def _fix(m):
        cand = _os.path.join(base_dir, _os.path.basename(m.group(2)))
        return repr(cand) if _os.path.exists(cand) else m.group(0)

    script = re.sub(r"(['\"])((?:\./|\.\./)[^'\"]*)\1", _fix, exp_code)
    script = re.sub(r"log_level\s*=\s*['\"]debug['\"]", "log_level='error'", script)
    script = _instrument_vars(script)
    if re.search(r"\binteractive\s*\(\s*\)", script):
        script, n = re.subn(r"(\w+)\.interactive\s*\(\s*\)",
                            lambda m: f"_probe({m.group(1)}, {marker!r})", script)
        if n == 0:
            script = re.sub(r"\binteractive\s*\(\s*\)", f"_probe(p, {marker!r})", script)
    else:
        script += f"\n_probe(p, {marker!r})\n"
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        env = _ld_env(binary)
        pre = _RUN_PREAMBLE
        if env:
            pre = ("import os as _os\n"
                   f"_os.environ['LD_PRELOAD'] = {env['LD_PRELOAD']!r}\n"
                   f"_os.environ['LD_LIBRARY_PATH'] = {env['LD_LIBRARY_PATH']!r}\n") + pre
        f.write(pre + "\n" + script + "\n")
        path = f.name
    try:
        r = subprocess.run([sys.executable, path], capture_output=True,
                           timeout=timeout + 10.0)
        raw = (r.stdout or b"").decode("latin-1") + (r.stderr or b"").decode("latin-1")
        m = re.search(r"@@RECV_BEGIN@@(.*?)@@RECV_END@@", raw, re.S)
        recv = m.group(1) if m else ""
        diag = _diagnosis(raw)
        out = re.sub(r"@@VAR@@.*?@@END@@", "", raw, flags=re.S)
        out = re.sub(r"@@RECV_BEGIN@@|@@RECV_END@@", "", out)
        if marker in recv:
            return True, "marker_ok", "run 模式生效(命令回显命中)", out, diag
        if r.returncode < 0:
            return False, "segv", f"脚本被信号终止 {-r.returncode}", out, diag
        return False, "no_marker", "run 模式未见标记回显", out, diag
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or b"") + (e.stderr or b"")).decode("latin-1")
        return False, "timeout", "run 模式超时", out, ""
    finally:
        try:
            _os.unlink(path)
        except Exception:
            pass

def run_verify(binary: str, report, flag: str | None = None,
               timeout: float = 3.0, mode: str = "run") -> ExpFeedback:
    """Algorithm 1 的 RunVerify: 沿 EXP 生命周期逐阶段打点, 返回结构化反馈."""
    exp_code = _exp_code_of(report)
    if not exp_code:
        tb = "exploit_plan.exp_code 为空"
        return ExpFeedback(stage="no_exp_code", exp_traceback=tb,
                           fingerprint=_fingerprint("no_exp_code", tb, ""))
    payload, err = _build_payload(exp_code, binary)
    if payload is not None:
        ok, stage, _reason, stdout = _try_pwn(binary, payload, flag, timeout)
        tail = stdout[-800:]
        return ExpFeedback(ok=ok, stage=stage, stdout_tail=tail, exp_traceback="",
                           fingerprint=_fingerprint(stage, "", tail))
    # 沙箱预构造失败(多阶段/依赖运行时交互的 EXP) -> 回退真实执行整段脚本
    ok, stage, _reason, out, diag = _try_run_exp(binary, exp_code, timeout)
    tail = (out or "")[-800:]
    tb = "" if stage != "payload_eval" else err
    return ExpFeedback(ok=ok, stage=stage, stdout_tail=tail, exp_traceback=tb,
                       diagnosis=diag or "", fingerprint=_fingerprint(stage, tb, tail))

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

    payload, err = _build_payload(exp_code, args.binary)
    if payload is None:
        print(f"[FAIL] 无法从 exp_code 提取/求值 payload: {err}", file=sys.stderr)
        print("---- exp_code ----")
        print(exp_code)
        return 1
    print(f"[*] 提取到 payload {len(payload)} 字节")
    print(f"[*] 前 32 字节: {payload[:32].hex()}")

    ok, stage, reason, stdout = _try_pwn(args.binary, payload, args.flag, args.timeout)
    print(f"\n判定: {'PASS' if ok else 'FAIL'}  stage={stage}  {reason}")
    if stdout:
        print("---- 程序输出(截断) ----")
        print(stdout[:800])
    print()
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())