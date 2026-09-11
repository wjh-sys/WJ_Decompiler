# 二进制反编译器（Decompiler）

一个从零实现的简单二进制反编译器：输入 ELF 可执行文件，支持自动函数发现、控制流建模与 LLM 漏洞分析（后续会添加其他功能）。
基于 Capstone 反汇编 + 自研三地址码（TAC）中间表示，端到端流水线完整可跑；反汇编支持 x86 / x86-64 / arm / aarch64，指令提升与污点分析聚焦 x86 / x86-64。

## 功能特性

- **ELF 解析**：提取节区、入口点、函数符号、字符串表等信息
- **多架构反汇编**：基于 Capstone，支持 x86 / x86-64 / arm / aarch64
- **TAC 中间表示**：指令提升（lift）+ 栈参数聚合，把 `mov [esp+X], v; call f` 还原成 `f(args)`
- **控制流建模**：`cmp/test` → `CMP`，`jmp/jcc` → 条件分支 `BRANCH`，伪代码输出 `L_xxx:` 标签 + `if(...) goto`；间接调用（`call eax`、`call [ebx+edi*4-0xf8]`）建模为 `(*eax)()` 形式
- **自动函数发现**：扫描 `call` 目标 + 序言字节模式，能挖出**未被调用的隐藏函数**
- **objdump 风格 CLI（wjdump）**：`-f/-h/-d/-D/-s/-t/-C/-j/--start-address/--stop-address/-M`，带 `<name@plt>` 符号标注，排版对齐 objdump；`-C` 生成函数 C 伪代码(调用点还原真实符号名)
- **静态污点证据**：source(gets/read)→栈溢出点、溢出偏移实测、后门/ROP gadget 扫描，喂给 LLM 生成可直接运行的 EXP
- **LLM 漏洞分析**：反编译产物 + 调用图展开组装 Prompt，接入大模型产出结构化 CTF 漏洞报告

## 安装

```bash
pip install -r requirements.txt # pyelftools, capstone, openai
```

### LLM 漏洞分析

使用前先配置大模型 API（默认对接 DeepSeek，其他 OpenAI 兼容厂商只需改 `LLM_BASE_URL`）：

```cmd
set LLM_API_KEY=sk-xxxx
set LLM_BASE_URL=https://api.deepseek.com
set LLM_MODEL=deepseek-chat
```

```bash
从 main 符号/入口点展开调用图（深度≤3、节点≤20，可自行调整）并交给大模型研判
# python analyze.py test/ret2text

指定根函数地址，或调整展开边界
# python analyze.py test/ret2text 0x8048648 --depth 3 --max-nodes 20
```

输出为结构化漏洞报告（漏洞类型、调用链、危险点、利用思路等），详见 `llm/schema.py`。

### objdump 风格命令行工具 wjdump

`wjdump.py` 是仿 GNU objdump 的 ELF 查看/反汇编 CLI，输出排版尽量对齐 objdump：

```bash
# 文件头 / 节区头 / 符号表
python wjdump.py -f <binary>
python wjdump.py -h <binary>
python wjdump.py -t <binary>

# 反汇编可执行节区(带 <name@plt> 符号标注) / 所有节区(含数据)
python wjdump.py -d <binary>
python wjdump.py -D <binary>

# 各函数 C 伪代码(调用点还原真实符号名,如 system/scanf)
python wjdump.py -C <binary>

# hex dump(可指定节区)
python wjdump.py -s <binary>
python wjdump.py -s -j .rodata <binary>

# 地址范围限定 + AT&T 语法
python wjdump.py -d --start-address=0x8048648 --stop-address=0x80486c8 <binary>
python wjdump.py -d -M att <binary>
```

对应的 objdump 选项：`-f -h -d -D -s -t -j --start-address --stop-address -M`；`-C` 为伪代码生成扩展选项。
当前仅支持 ELF（x86/x86-64/arm/aarch64）。

### 自动验证生成的 EXP（verify_exp）

`verify_exp.py` 读取 `analyze.py --json-out` 导出的报告，沙箱提取 `exploit_plan.exp_code`
中的 payload 构造逻辑，spawn 目标二进制并探活，判定 LLM 生成的 EXP 是否真的能打通：

```bash
# 1) 生成报告(自动存入 reports/, 需配好 LLM API)
python analyze.py test/ret2text --json-out ret2text.json

# 2) 在 WSL/Linux 中验证(目标是 Linux ELF, 需要 pwntools)
python3 verify_exp.py ./ret2text reports/ret2text.json
```

判定规则：打通后发送 `echo PWNED_<随机>`，输出回显标记即 PASS（拿到 shell/命令执行）；
若题目目录带 flag 文件，可加 `--flag flag` 自动 `cat` 探测。

> 注意：验证目标必须是可在本机运行的 Linux ELF（WSL 下路径前缀 `/mnt/d/...`）；
> 纯静态大体积二进制、需泄漏/多阶段的题（第二梯队）会被如实判定为 FAIL。

## 目录结构

```
├── analysis/    # 分析模块
│   ├── __init__.py
│   ├── callgraph.py
│   ├── function_finder.py
│   ├── taint.py          # 静态污点证据:source/sink/偏移/后门/gadget 扫描
├── codegen/    # 伪代码生成
│   ├── __init__.py
│   ├── c_generator.py
├── disasm/    # 反汇编
│   ├── __init__.py
│   ├── disassembler.py
├── ir/    # 中间表示
│   ├── __init__.py
│   ├── expressions.py     # Var/Const/Mem/BinOp 表达式
│   ├── instructions.py    # IRInst / Op(ASSIGN/CALL/RET/CMP/BRANCH/UNKN)
│   ├── lifter.py          # 汇编 → TAC + 控制流/标志位建模
├── llm/    # 大模型接口
│   ├── __init__.py
│   ├── client.py
│   ├── config.py
│   ├── parser.py
│   ├── prompt.py
│   ├── schema.py
├── loader/
│   ├── __init__.py
│   ├── base.py
│   ├── elf_loader.py
├── algorithm/    # 算法(伪代码/设计演示)
│   ├── Algorithm_1.py    # Taint 优化闭环伪代码
├── test/    # 测试样本(CTF pwn 题库)
│   ├── user-mode/        # stackoverflow / fmtstr / heap / arm / mips / ...
├── test_py/    # 实验/调试脚本
│   ├── demo_decompile.py
│   ├── demo_disasm.py
│   ├── demo_func.py
│   ├── demo_loader.py
│   ├── demo_lift.py
│   ├── demo_decompile_all.py
│   ├── test_api.py
├── analyze.py           # LLM 漏洞分析入口(根目录)
├── verify_exp.py        # EXP 自动验证器(需在 WSL/Linux 运行)
├── reports/             # analyze --json-out 报告输出目录(自动创建)
├── requirements.txt    # 依赖库
├── wjdump.py           # objdump 风格 CLI(仿 objdump)
├── README.md    # 项目说明

```


## 流水线架构（暂定）

```text
输入二进制 (ELF)
      │
      ▼
┌───────────────────────────────────────────────────────────────┐
│ loader ── guess_loader() → ElfLoader (当前仅 ELF; PE 预留)   │
│   解析节区 / 符号表 / 动态符号(.dynsym) / 字符串 / 入口点      │
│   产出: Program（含 section / symbol / strings）               │
└───────────────────────────────────────────────────────────────┘
      │  Program
      ▼
┌───────────────────────────────────────────────────────────────┐
│ disasm ── Disassembler (Capstone)                            │
│   按地址取节区字节解码                                         │
│   产出: Instruction[] (地址/机器码/助记符/操作数)             │
└───────────────────────────────────────────────────────────────┘
      │  Instruction[]
      ▼
┌───────────────────────────────────────────────────────────────┐
│ ir ── Lifter                                                │
│   汇编 → TAC: 栈参数聚合 mov[esp+X],v→CALL + cmp/jcc→BRANCH  │
│   产出: IRInst[] (ASSIGN / CALL / RET / CMP / BRANCH / UNKN)│
└───────────────────────────────────────────────────────────────┘
      │  IRInst[]
      ▼
┌───────────────────────────────────────────────────────────────┐
│ codegen ── CGenerator                                       │
│   IR → C 伪代码（序言/尾声折叠、字符串还原、负数识别）       │
│   产出: 伪代码文本 + 调用目标地址/参数                        │
└───────────────────────────────────────────────────────────────┘
      │  伪代码 + 地址信息
      ▼
┌───────────────────────────────────────────────────────────────┐
│ analysis ── FunctionFinder / CallGraph                       │
│   自动函数发现 + 调用图 BFS 展开 + PLT→动态符号名(gets/puts) │
│   产出: FunctionNode[] + 调用关系文本                         │
└───────────────────────────────────────────────────────────────┘
      │  调用关系 + 逐函数伪代码 + 真实符号名
      ▼
┌───────────────────────────────────────────────────────────────┐
│ llm ── prompt → client(OpenAI兼容) → parser                 │
│   组装[程序信息/调用图/函数详情] → 大模型研判 → VulnReport   │
└───────────────────────────────────────────────────────────────┘
      │
      ▼
   结构化漏洞报告（类型 / 调用链 / 危险点 / 利用思路）

CLI 入口:
  analyze.py <binary> [addr] [--json-out f]   → 完整 LLM 漏洞分析(+报告导出)
  verify_exp.py <binary> <report.json>       → 自动验证 EXP 是否打通(需 WSL/Linux)
  wjdump.py <-f|-h|-d|-D|-s|-t|-C> <binary> → objdump 风格查看/反汇编(-C 生成伪代码)
  demo_decompile_all.py <binary>             → 调用链反汇编 + C 伪代码
  demo_decompile.py <binary> addr n          → 指定地址反编译
```

**关键设计取舍**：

- **TAC 而非 VEX/P-code**：目标是可读性而非精确仿真，一条汇编通常对应一条 IR；控制流与标志位已建模（`cmp/test` 及算术/逻辑指令），栈指针副作用按需建模。
- **栈参数聚合**：32 位 x86 调用约定靠栈传参，lifter 把连续的 `mov [esp+X], v` 聚合进 `CALL(args=...)`。
- **统一内存模型**：寄存器/内存/常量统一为带位宽的表达式，下游分析不用区分访问对象。


## 已知限制
- 循环等结构化控制流未恢复（跳转已建模为平坦的 `label + if/goto`，尚未折叠成 `if/while`）
- 标志位已建模：`cmp/test` 及算术/逻辑指令（`sub/add/and/or/xor/shl/shr/sar`）后的条件跳转均可还原为真实条件（⚠ `ja/jae/jb/jbe` 暂按有符号比较处理）
- 间接调用目标为运行期值，伪代码显示为 `(*eax)()` / `(*(int*)(...))()`，静态分析不还原具体地址
- 变量未命名（暂用寄存器名 eax/esp），无类型恢复
- python wjdump后展示的代码字符结构不够美观，second edition着重强调将工具系统化正规化
- 仅支持 ELF（x86/x86-64/arm/aarch64），不支持 PE
- WJ_Decomplier对于漏洞查找能力以及对不同类型的PWN题目覆盖面太小
- 对污点路径Taint的算法创新性太弱，这个间接性体现在提交给LLM的污点传播相关信息以及LLM生成的json文件上
## 下一步规划
- [ ] CFG 构建 + 控制结构恢复（if/while，将平坦 `label + goto` 折叠为结构化语句）
- [x] 标志位建模（追踪算术指令置位的条件跳转，已消除 `// IF <flags from ...>` 注释）
- [ ] 栈参数抑制（清理 CALL 前的 `*(esp+X)=v` 噪声）
- [ ] 变量命名 + 类型恢复
- [x] 间接调用支持（`call reg` / `call [mem]`，伪代码渲染为 `(*reg)()`）
- [ ] 对于python wjdump后的每一个通道字功能（如-s，-c，etc）都一个一个实验，一个一个修改即可
- [ ] 着重提高Proj处理多类型pwn题目的能力，以及提高相关题目的解题exp解题率
- [ ] 自己研究一套有效算法进行Proj的性能提升
