from __future__ import annotations

import json

from loader import Program

from .schema import JSON_SCHEMA, VULN_TYPES

SYSTEM_PROMPT = """你是资深 CTF Pwn 漏洞分析专家，擅长二进制逆向与漏洞利用。
你会收到一个二进制程序的反编译伪代码、函数调用关系与相关上下文。
请分析其中是否存在可利用的安全漏洞，并严格按给定 JSON schema 输出结论。

铁律：

1. 只输出一个 JSON 对象，不要输出任何解释性文字或 markdown 围栏。

2. vulnerability_type 必须是枚举值之一：{types}。

3. 没有漏洞时 vulnerability_type 必须为 "none"，并在 false_positive_reason 中说明原因。

4. 宁漏报不误报：无法确认时输出 "none"。

5. call_chain 描述漏洞从入口函数到触发点的调用链；无漏洞时为空数组。"""

TASK_SECTION = """[任务]
分析上述函数及其调用关系，判断是否存在可利用漏洞。
重点关注：栈溢出（危险拷贝函数+用户可控输入）、格式化字符串、堆利用、整数溢出、命令注入、逻辑漏洞。
跨函数漏洞务必在 call_chain 中描述清楚完整调用链。
按以下 JSON schema 输出结论（不要输出其他任何内容）：
{schema}"""

def build_prog_info(prog: Program) -> str:
    return "\n".join([
        "[程序信息]",
        f"架构: {prog.arch}   位数: {prog.bits}   入口: 0x{prog.entry:x}",
    ])

def build_graph_text(graph, nodes) -> str:
    return graph.format_graph(nodes)

def build_function_section(nodes) -> str:
    lines = ["[函数详情]"]
    for node in nodes:
        lines.append(f"## {node.name} @ 0x{node.addr:x}"
                     + (" (外部函数, 不展开)" if node.is_external else ""))
        if node.is_external:
            lines.append("")
            continue
        lines.append("```c")
        lines.append("void func() {")
        if node.c_code:
            lines.append(node.c_code)
        lines.append("}")
        lines.append("```")
        lines.append("")
    return "\n".join(lines)

def build_messages(prog_info: str, graph_text: str, nodes,
                   schema: dict = JSON_SCHEMA,
                   evidence_text: str | None = None) -> list[dict]:
    system = SYSTEM_PROMPT.format(types=" / ".join(VULN_TYPES))
    sections = [prog_info]
    if evidence_text:
        sections.append(evidence_text)
    sections += [
        "[调用关系图]\n" + (graph_text or "(无内部调用)"),
        build_function_section(nodes),
        TASK_SECTION.format(schema=json.dumps(schema, ensure_ascii=False, indent=2)),
    ]
    user = "\n\n".join(sections)
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
