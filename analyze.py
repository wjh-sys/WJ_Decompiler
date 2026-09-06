#!/usr/bin/env python3
"""WJ 反编译器 - LLM 辅助漏洞分析命令行入口

用法:
    python analyze.py <binary> [addr] [--depth N] [--max-nodes N]
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analysis import CallGraph, analyze as taint_analyze, is_large_static
from disasm import Disassembler
from llm.client import LLMClient, LLMError
from llm.config import LLMConfigError, load_config
from llm.parser import parse_report
from llm.prompt import build_graph_text, build_messages, build_prog_info
from loader import guess_loader

def _find_root(prog, dis, addr: str | None) -> int:
    if addr is not None:
        return int(addr, 0)
    for s in prog.symbols:
        if s.name == "main" and s.addr:
            return s.addr
    # strip 二进制: 从 _start 反汇编找 mov rdi, imm(传给 __libc_start_main)
    try:
        entry = prog.entry
        cs = prog.find_section(entry)
        if cs is not None:
            code = cs.data[entry - cs.addr: entry - cs.addr + 0x100]
            for ins in dis.decode(code, entry):
                m, ops = ins.mnemonic, ins.op_str
                if m == "mov" and ops.startswith("rdi,"):
                    try:
                        return int(ops[4:].strip(), 0)
                    except ValueError:
                        pass
                if m == "call":
                    break
    except Exception:
        pass
    return prog.entry

def _print_report(report) -> None:
    line = "=" * 60
    print("\n" + line)
    print("漏洞分析报告")
    print(line)
    print(f"漏洞类型   : {report.vulnerability_type}")
    print(f"确信度     : {report.confidence:.2f}")
    print(f"入口函数   : {report.entry_function or 'N/A'}")
    print(f"涉及函数   : {', '.join(report.involved_functions) if report.involved_functions else 'N/A'}")
    print(f"漏洞函数   : {report.vulnerable_function or 'N/A'}")
    print(f"调用链     : {' -> '.join(report.call_chain) if report.call_chain else 'N/A'}")
    print(f"概述       : {report.summary}")
    for i, dp in enumerate(report.danger_points, 1):
        loc = f"{dp.addr or '?'}  {dp.call}({dp.args})"
        print(f"危险点{i}    : {loc}  {dp.note}")
    det = report.details
    if det.buffer_size is not None or det.overflow_length or det.overwritten_target or det.protection:
        print("细节       :")
        if det.buffer_size is not None:
            print(f"            缓冲区大小: {det.buffer_size}")
        if det.overflow_length:
            print(f"            溢出长度  : {det.overflow_length}")
        if det.overwritten_target:
            print(f"            覆盖目标  : {det.overwritten_target}")
        if det.protection:
            print(f"            防护      : {', '.join(det.protection)}")
    print(f"利用思路   : {report.exploitation or 'N/A'}")
    print(f"误报说明   : {report.false_positive_reason or 'N/A'}")
    ep = report.exploit_plan
    if ep.offset or ep.exp_code:
        print("\nEXP 方案:")
        if ep.offset:
            print(f"  溢出偏移  : {ep.offset}")
        if ep.payload_layout:
            print(f"  payload   : {ep.payload_layout}")
        if ep.exp_code:
            print("  exp_code  :")
            print(ep.exp_code)
        if ep.verification:
            print(f"  验证方式  : {ep.verification}")
    print(line)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="analyze",
        description="LLM 辅助 CTF 漏洞分析：反编译 + 调用图展开 + 大模型研判",
    )
    parser.add_argument("binary", help="目标二进制文件路径")
    parser.add_argument("addr", nargs="?", default=None,
                        help="根函数地址(十六进制)；缺省使用 main 符号或程序入口")
    parser.add_argument("--depth", type=int, default=3, metavar="N",
                        help="调用图最大展开深度(默认 3)")
    parser.add_argument("--max-nodes", type=int, default=20, metavar="N",
                        help="调用图最多纳入函数数(默认 20)")
    parser.add_argument("--json-out", default=None, metavar="FILE",
                        help="将结构化报告(含 exploit_plan)写入 JSON 文件,供 verify_exp.py 读取;"
                             "未指定目录时默认存入项目根 reports/ 下")
    args = parser.parse_args(argv)

    try:
        config = load_config()
    except LLMConfigError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1

    try:
        prog = guess_loader(args.binary).load()
        dis = Disassembler(prog)
    except Exception as exc:
        print(f"[错误] 无法加载二进制 {args.binary}: {exc}", file=sys.stderr)
        return 1

    if is_large_static(prog, args.binary):
        print(f"[跳过] 该文件为全静态大体积二进制,当前工具链不支持"
              f"(函数发现误报多、无 PLT 符号可识别 source),请换动态链接题目", file=sys.stderr)
        return 2

    graph = CallGraph(prog, dis)
    graph.build()
    root = _find_root(prog, dis, args.addr)
    nodes = graph.expand(root, max_depth=args.depth, max_nodes=args.max_nodes)
    if not nodes:
        print(f"[错误] 根函数 0x{root:x} 展开结果为空，无法分析", file=sys.stderr)
        return 1

    ev = taint_analyze(prog, graph, args.binary)
    evidence_text = ev.to_prompt_text()

    print(f"[*] 根函数 0x{root:x}，展开 {len(nodes)} 个函数"
          f"（深度≤{args.depth}，节点≤{args.max_nodes}），正在请求模型分析...")
    messages = build_messages(
        build_prog_info(prog),
        build_graph_text(graph, nodes),
        nodes,
        evidence_text=evidence_text,
    )
    try:
        client = LLMClient(config)
        raw = client.chat(messages)
    except LLMError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1

    report = parse_report(raw)
    _print_report(report)
    if args.json_out:
        try:
            import dataclasses
            import json
            import os

            out_path = args.json_out
            # 未含目录分隔符时,默认放入项目根 reports/
            if os.path.dirname(out_path) == "":
                base_dir = os.path.dirname(os.path.abspath(__file__))
                out_dir = os.path.join(base_dir, "reports")
                os.makedirs(out_dir, exist_ok=True)
                out_path = os.path.join(out_dir, out_path)

            def _conv(o):
                if dataclasses.is_dataclass(o):
                    return {k: _conv(v) for k, v in dataclasses.asdict(o).items()}
                if isinstance(o, (list, tuple)):
                    return [_conv(x) for x in o]
                if isinstance(o, dict):
                    return {k: _conv(v) for k, v in o.items()}
                return o

            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(_conv(report), f, ensure_ascii=False, indent=2)
            print(f"[+] 报告已写入 {out_path}")
        except Exception as exc:
            print(f"[错误] 写入 JSON 失败: {exc}", file=sys.stderr)
            return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())