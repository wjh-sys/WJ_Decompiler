from __future__ import annotations

import json

from loader import Program

from .schema import ANALYSIS_SCHEMA, JSON_SCHEMA, VULN_TYPES

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
        "",
        "[伪代码命名约定]",
        "- vN: 寄存器版本变量(同一寄存器每次赋值生成新版本), 映射见各函数行首"
        " `// 寄存器映射: v1=eax#1 ...`; 未编号的 eax/edx 等为跨块合并点取值",
        "- sp / fp: 分别表示栈指针 / 帧指针(即 esp / ebp)",
        "- var_xx / arg_n / stk_xx: 栈槽(局部变量 / 栈传参 / 按 esp 计偏移的栈槽); "
        "`char name[N]` 为被写入的栈缓冲区",
        "- 未实现的间接跳转会保留为 `// 尾调用 -> ...` 或 `(*reg)(...)` 注释",
        "- 占位提示: `char xxx[N]` 的 N 为按栈槽间距估算的启发式大小, "
        "**溢出偏移必须以[静态污点证据]中的实测 offset 为准**, 不要用 N 自行推算",
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

def _report_json(report) -> str:
    import dataclasses
    if dataclasses.is_dataclass(report):
        return json.dumps(dataclasses.asdict(report), ensure_ascii=False, indent=2)
    return json.dumps(report, ensure_ascii=False, indent=2)

def _taint_text(taint) -> str:
    if isinstance(taint, (list, tuple)):
        return "\n\n".join(str(t) for t in taint)
    return str(taint or "")

def format_feedback(feedback) -> str:
    lines = ["[验证反馈 RunVerify]",
             f"stage: {getattr(feedback, 'stage', '?')}",
             f"ok: {getattr(feedback, 'ok', False)}"]
    tb = getattr(feedback, "exp_traceback", "") or ""
    if tb:
        lines += ["[exp traceback]", tb]
    diag = getattr(feedback, "diagnosis", "") or ""
    if diag:
        lines += ["[泄漏自检/关键变量]", diag]
    out = getattr(feedback, "stdout_tail", "") or ""
    if out:
        lines += ["[进程回显尾部]", out]
    return "\n".join(lines)

EXP_RULES = """[EXP 编写规范](必须遵守)
- 多阶段泄漏: 先用 recvuntil(已知提示串) 对齐, 再用 recv(4) 精确读取地址; 禁止对 recvline 结果直接 u32
- 硬编码地址必须来自静态证据; 由泄漏算出的基址必须校验页对齐(base & 0xfff == 0)
- 若运行时 libc 可能与题目 libc 不一致, 在脚本中用注释标出"需用户替换为运行环境 libc"的偏移
- 二次返回同一函数再溢出时, 注意栈对齐可能使偏移平移(参考静态证据的 reentry 提示)"""

ANALYZE_SYSTEM = """你是二进制漏洞利用(EXP)调试专家。
你会收到上一轮生成的结构化报告 JSON、当前累积的 Taint/静态证据、以及一次真实沙箱验证的结构化反馈。
你的唯一职责: 把客观证据翻译成\"结构化问题清单\", 不决定是否重试、不生成 EXP。
评分与问题都必须引用证据: score 需在 evidence 字段逐条引用证据原文片段(含地址/偏移/阶段等);
每个 problem 需在 evidence 字段引用支撑它的具体证据或地址。
未引用证据的评分按 0 分计; 未引用证据的问题不计入扣分。禁止凭空推断(如无证据支持的偏移偏移假设)。
只输出一个 JSON 对象, 不要输出任何解释性文字或 markdown 围栏。"""

def build_analyze_messages(report, taint, feedback_text: str,
                           schema: dict = ANALYSIS_SCHEMA) -> list[dict]:
    user = "\n\n".join([
        "[上一轮报告 J]", _report_json(report),
        "[累积 Taint/静态证据 T]", _taint_text(taint),
        feedback_text,
        "[归因任务] 依据上述客观证据定位 EXP 卡点。problems[].kind 必须取自 schema 枚举; "
        "problems[].evidence 必须引用支撑该问题的证据原文或地址, score 的 evidence 必须逐条引用证据片段; "
        "未引用证据的评分按 0 分计, 未引用证据的问题不计入扣分; "
        "locked 列出本轮确凿、下一轮禁止改动的字段路径(如 exploit_plan.offset)。",
        "按以下 JSON schema 输出(不要输出其他任何内容):",
        json.dumps(schema, ensure_ascii=False, indent=2),
    ])
    return [{"role": "system", "content": ANALYZE_SYSTEM},
            {"role": "user", "content": user}]

def build_regenerate_messages(report, taint, analysis,
                              schema: dict = JSON_SCHEMA) -> list[dict]:
    problems = getattr(analysis, "problems", None)
    if problems is None and isinstance(analysis, dict):
        problems = analysis.get("problems") or []
    lines = []
    for p in problems or []:
        if isinstance(p, dict):
            lines.append(f"- {p.get('kind','?')}: {p.get('detail','')}  target={p.get('target','')}")
        else:
            lines.append(f"- {p.kind}: {p.detail}  target={p.target}")
    locked = getattr(analysis, "locked", None) or []
    system = SYSTEM_PROMPT.format(types=" / ".join(VULN_TYPES))
    user = "\n\n".join([
        "[上一轮报告 J]", _report_json(report),
        "[累积 Taint/静态证据 T]", _taint_text(taint),
        "[本轮必须修复的问题]", "\n".join(lines) or "(无)",
        "[禁止改动的字段(locked)]", ", ".join(locked) or "(无)",
        EXP_RULES,
        TASK_SECTION.format(schema=json.dumps(schema, ensure_ascii=False, indent=2)),
    ])
    return [{"role": "system", "content": system},
            {"role": "user", "content": user}]

EXPLAIN_SYSTEM = """你是 CTF Pwn 教学专家。你会收到一份已生成的 EXP、静态证据与缺口清单。
请用中文讲解该 EXP 的构造原理, 并指出用户需自行补充/适配的部分。
只输出一个 JSON 对象, 不要输出任何解释性文字或 markdown 围栏。"""

EXPLAIN_SCHEMA = {
    "type": "object",
    "properties": {
        "rationale": {"type": "string",
                      "description": "该 EXP 的构造原理讲解(为何这样布局/为何选这个泄漏点/分几阶段)"},
        "manual_steps": {"type": "array", "items": {"type": "string"},
                         "description": "用户需自行完成/适配的步骤(如替换为运行环境 libc 偏移)"},
        "env_note": {"type": "string",
                     "description": "环境差异说明(为何本机验证不通过/地址不可移植)"},
    },
    "required": ["rationale", "manual_steps", "env_note"],
}

def build_explain_messages(deliverable: dict, evidence_text: str = "",
                           schema: dict = EXPLAIN_SCHEMA) -> list[dict]:
    user = "\n\n".join([
        "[可交付 EXP]",
        json.dumps(deliverable, ensure_ascii=False, indent=2),
        "[静态证据]", evidence_text or "(无)",
        "[任务] 讲解该 EXP 的构造原理、需用户自行补充的步骤、以及环境差异说明。"
        "按以下 JSON schema 输出(不要输出其他任何内容):",
        json.dumps(schema, ensure_ascii=False, indent=2),
    ])
    return [{"role": "system", "content": EXPLAIN_SYSTEM},
            {"role": "user", "content": user}]
