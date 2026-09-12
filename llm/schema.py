from __future__ import annotations

from dataclasses import dataclass, field

VULN_TYPES = [
    "stack_overflow",
    "format_string",
    "heap",
    "integer_overflow",
    "command_injection",
    "logic",
    "none",
]

@dataclass
class DangerPoint:
    addr: str = ""
    call: str = ""
    args: str = ""
    note: str = ""

@dataclass
class VulnDetails:
    buffer_size: int | None = None
    overflow_length: str = ""
    overwritten_target: str = ""
    protection: list = field(default_factory=list)

@dataclass
class ExploitPlan:
    offset: str = ""
    payload_layout: list = field(default_factory=list)
    exp_code: str = ""
    verification: str = ""

@dataclass
class VulnReport:
    entry_function: str = ""
    involved_functions: list = field(default_factory=list)
    vulnerable_function: str = ""
    call_chain: list = field(default_factory=list)
    vulnerability_type: str = "none"
    confidence: float = 0.0
    summary: str = ""
    danger_points: list = field(default_factory=list)
    details: VulnDetails = field(default_factory=VulnDetails)
    exploitation: str = ""
    false_positive_reason: str = ""
    exploit_plan: ExploitPlan = field(default_factory=ExploitPlan)
    raw: str = ""

JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "entry_function": {"type": "string", "description": "本次分析的入口函数地址", "example": "0x8048648"},
        "involved_functions": {"type": "array", "items": {"type": "string"},
                               "description": "参与分析的所有函数地址列表"},
        "vulnerable_function": {"type": "string",
                                "description": "存在漏洞的函数地址；无漏洞时为空字符串"},
        "call_chain": {"type": "array", "items": {"type": "string"},
                       "description": "从入口到漏洞点的调用链函数名列表，如 [\"main\", \"vuln\"]；无漏洞时为空数组"},
        "vulnerability_type": {"type": "string", "enum": VULN_TYPES,
                               "description": "漏洞类型；无漏洞时必须为 none"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1,
                       "description": "对结论的确信度(0.0~1.0)"},
        "summary": {"type": "string", "description": "漏洞概述"},
        "danger_points": {"type": "array", "items": {"type": "object", "properties": {
            "addr": {"type": "string"},
            "call": {"type": "string"},
            "args": {"type": "string"},
            "note": {"type": "string"},
        }}},
        "details": {"type": "object", "properties": {
            "buffer_size": {"type": ["integer", "null"]},
            "overflow_length": {"type": "string"},
            "overwritten_target": {"type": "string"},
            "protection": {"type": "array", "items": {"type": "string"}},
        }},
        "exploitation": {"type": "string", "description": "利用思路"},
        "false_positive_reason": {"type": "string",
                                  "description": "确认为漏洞时填\"无\"；判定无漏洞时说明原因"},
        "exploit_plan": {"type": "object", "properties": {
            "offset": {"type": "string", "description": "溢出偏移量，如 0x70；必须采用静态污点证据中的实测值，禁止自行估算"},
            "payload_layout": {"type": "array", "items": {"type": "string"},
                                "description": "payload 布局逐条描述，如 [\"填充112个'A'\", \"p32(0x8048490) 即 system@plt\"]。每条必须是普通字符串；禁止使用 \"A\"*112 等需要求值的表达式，否则整个 JSON 将无法解析"},
            "exp_code": {"type": "string",
                          "description": "完整可运行的 pwntools 利用脚本(Python 代码)；地址/偏移必须硬编码自静态证据"},
            "verification": {"type": "string", "description": "如何验证 EXP 成功(如交互后发送 cat flag、预期输出等)"},
        }},
    },
    "required": ["entry_function", "involved_functions", "vulnerable_function",
                 "call_chain", "vulnerability_type", "confidence", "summary",
                 "danger_points", "details", "exploitation", "false_positive_reason",
                 "exploit_plan"],
}

PROBLEM_KINDS = [
    "addr_missing", "gadget_missing", "need_leak", "string_missing",
    "offset_wrong", "payload_fix", "stage_runtime", "misread",
]

@dataclass
class Problem:
    kind: str = ""
    detail: str = ""
    target: str = ""

@dataclass
class FailureAnalysis:
    score: float = 0.0
    actually_passed: bool = False
    problems: list = field(default_factory=list)
    locked: list = field(default_factory=list)
    reasoning: str = ""

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "score": {"type": "number", "minimum": 0, "maximum": 1,
                  "description": "对当前 EXP 完成度的评估(0~1),达到阈值即收敛"},
        "actually_passed": {"type": "boolean",
                            "description": "若证据表明 EXP 其实已打通(仅探活误判),置 true"},
        "problems": {"type": "array", "items": {"type": "object", "properties": {
            "kind": {"type": "string", "enum": PROBLEM_KINDS},
            "detail": {"type": "string"},
            "target": {"type": "string"},
        }}, "description": "把客观证据翻译成的结构化问题清单"},
        "locked": {"type": "array", "items": {"type": "string"},
                   "description": "本轮确凿、下一轮禁止改动的字段路径,如 exploit_plan.offset"},
        "reasoning": {"type": "string", "description": "归因简述"},
    },
    "required": ["score", "actually_passed", "problems", "locked", "reasoning"],
}
