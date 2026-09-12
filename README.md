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
- **静态污点证据**：source(gets/read)→栈溢出点、溢出偏移实测(含 ret 二次进入的栈对齐平移)、后门/ROP gadget 扫描(签名+滑窗双通道)、同目录 libc 符号偏移，喂给 LLM 生成可直接运行的 EXP
- **LLM 漏洞分析**：反编译产物 + 调用图展开组装 Prompt，接入大模型产出结构化 CTF 漏洞报告
- **Taint 引导的迭代 EXP 精炼闭环（Algorithm 1）**：`refine.py` 落地 生成 EXP → 真实验证 → 归因 → 反查静态语料补全 Taint → 重出报告，含 8 个终止条件与锁定字段回填(防漂移)
- **终端可视化**：每轮规范化展示验证反馈、大模型归因、缺口诊断(偏移/ gadget 核对)、反查材料与迭代时间线
- **可交付 EXP**：输出完成度评分 + 缺口清单(阻塞/待改) + LLM 构造原理讲解与待人工补充步骤，即便环境不匹配也能给出可改写的完整 EXP
- **自动化评测**：`test_py/run_stackoverflow_batch.py` 批量跑题并与官方 exp 对照(偏移/技术/端到端 PASS)

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
# 从 main 符号/入口点展开调用图（深度≤3、节点≤20，可自行调整）并交给大模型研判
# 注意: 项目内题目多为多层嵌套目录, 请填真实路径
python analyze.py test/user-mode/stackoverflow/ret2text/bamboofox-ret2text/ret2text

# 指定根函数地址，或调整展开边界
python analyze.py <binary> 0x8048648 --depth 3 --max-nodes 20
```

输出为结构化漏洞报告（漏洞类型、调用链、危险点、利用思路等），详见 `llm/schema.py`。

### Algorithm 1：Taint 引导的迭代 EXP 精炼闭环（refine.py）

`refine.py` 落地 `algorithm/Algorithm_1.py` 的完整闭环：
**生成 EXP → 真实验证 → 归因 → 反查静态语料补全 Taint → 重出报告**。
每轮把大模型反馈、归因思考、缺口诊断（偏移是否算对 / gadget 是否够用）规范化可视化到终端。

> 注意：验证环节依赖 pwntools 且目标为 Linux ELF，**须在 WSL/Linux 中运行**（Windows 只能跑 `analyze.py` 单轮分析）。

```bash
# 首次准备(WSL/Linux): 建虚拟环境并装依赖(系统 Python 受 PEP 668 保护, 勿直连 pip3)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 配置大模型 API(WSL 需单独 export, Windows 的 set 不会传入)
export LLM_API_KEY=sk-xxxx
export LLM_BASE_URL=https://api.deepseek.com
export LLM_MODEL=deepseek-chat

# 运行闭环: --rounds N 最大轮数, --theta 完成度收敛阈值
python3 refine.py <binary> --rounds 3 --theta 0.95

# 带 flag 探测 / 导出最终报告 / 单色输出
python3 refine.py <binary> --flag flag --json-out ret2text_final.json
python3 refine.py <binary> --no-color
```

终止状态: `PASS` / `PASS_SUSPECT` / `CONVERGED` / `NO_PROBLEM` / `STALLED` / `UNRESOLVABLE` / `LLM_FAILED` / `MAX_ROUNDS`。

### 栈溢出题库评测（第二版基线）

`test_py/run_stackoverflow_batch.py` 对题库中**可测的栈溢出题目**（动态链接 ELF + x86/x86-64）
批量跑 `refine.py`，并与**题目自带官方 exp** 对照（偏移 / 技术路线 / 端到端 PASS）。

```bash
python3 test_py/run_stackoverflow_batch.py --tier 1 --rounds 2   # 32 位 8 题
python3 test_py/run_stackoverflow_batch.py --tier 2 --rounds 3   # 64 位 3 题
python3 test_py/run_stackoverflow_batch.py --only ret2libc1      # 单题
```

**32 位（第一梯队，8 题）**

| 题目 | 状态 | 完成度 | 工具偏移 | 官方偏移 | 偏移 | 技术 | gaps |
|---|---|---|---|---|---|---|---|
| ret2text | MAX_ROUNDS | 42.5% | 0x70 | 0x70 | ✔ | ✔ | 4 |
| stack_example | MAX_ROUNDS | 45.0% | 0x18 | 0x18 | ✔ | ✔ | 4 |
| **ret2libc1** | **PASS** | **100%** | 0x70 | 0x70 | ✔ | ✔ | 0 |
| ret2libc2 | MAX_ROUNDS | 17.5% | 0x70 | 0x70 | ✔ | ✘ | 3 |
| ret2libc3 | MAX_ROUNDS | 37.5% | 0x70 | 0x70 | ✔ | ✔ | 3 |
| ret2shellcode | MAX_ROUNDS | 40.0% | 0x70 | 0x70 | ✔ | ✔ | 4 |
| train_ret2libc | MAX_ROUNDS | 37.5% | - | 0x20 | ✘ | ✔ | 4 |
| ropasaurusrex | MAX_ROUNDS | 37.5% | 0x8c | 0x8c | ✔ | ✔ | 4 |

`PASS 1/8 | 偏移符合 7/8 | 技术符合 7/8 | 平均完成度 44.7%`

**64 位（第二梯队，3 题）**

| 题目 | 状态 | 完成度 | 工具偏移 | 官方偏移 | 偏移 | 技术 | gaps |
|---|---|---|---|---|---|---|---|
| shellcode_x64 | MAX_ROUNDS | 32.5% | 0x18 | 0x18 | ✔ | ✔ | 4 |
| hitcon_level5 | MAX_ROUNDS | 35.0% | 0x88 | 0x88 | ✔ | ✔ | 1 |
| r0pbaby | MAX_ROUNDS | 5.0% | - | 0x8 | ✘ | ✘ | 7 |

`PASS 0/3 | 偏移符合 2/3 | 技术符合 2/3 | 平均完成度 24.2%`

> **结论（11 题合计）**：端到端 `PASS 1/11`；但**漏洞识别与溢出偏移定位**达 `9/11`，
> **技术路线与官方同构**达 `9/11`。即：工具能找准漏洞与偏移，瓶颈在**多阶段交互的运行时细节**
> （`stage_runtime` 在 11 题中全部命中，为首要卡点）。

> **指标口径**：`完成度` 为「端到端打通度」（0.5×验证阶段 + 0.5×LLM 归因），未 PASS 天然封顶 ~55%，
> 故 37.5%~45% 表示「流程跑通但未拿到 shell」，**不代表 EXP 质量差**；同一题重复运行因 LLM 非确定性可能小幅波动。

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
│   ├── resolver.py       # Resolve: 按问题 kind 反查静态语料(Algorithm 1)
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
│   ├── Algorithm_2.py    # 暂定为某优化算法，暂未想好
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
│   ├── run_stackoverflow_batch.py  # 栈溢出题库批量评测(对照官方 exp)
├── analyze.py           # LLM 漏洞分析入口(根目录, 单轮; 内含 round_zero)
├── refine.py            # Algorithm 1 迭代精炼闭环入口(需在 WSL/Linux 运行)
├── ui.py                # 终端可视化: 反馈/归因/缺口诊断/迭代时间线
├── verify_exp.py        # EXP 自动验证器(需在 WSL/Linux 运行; 含 run_verify)
├── reports/             # analyze --json-out 报告输出目录(自动创建)
├── requirements.txt    # 依赖库
├── wjdump.py           # objdump 风格 CLI(仿 objdump)
├── README.md    # 项目说明

```


## 漏洞挖掘流水线架构

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
  refine.py <binary> [--rounds N] [--theta t] → Algorithm 1 迭代精炼闭环(需 WSL/Linux)
  verify_exp.py <binary> <report.json>       → 自动验证 EXP 是否打通(需 WSL/Linux)
  wjdump.py <-f|-h|-d|-D|-s|-t|-C> <binary> → objdump 风格查看/反汇编(-C 生成伪代码)
  run_stackoverflow_batch.py [--tier 1|2|all] → 栈溢出题库批量评测(对照官方 exp)
  demo_decompile_all.py <binary>             → 调用链反汇编 + C 伪代码
  demo_decompile.py <binary> addr n          → 指定地址反编译
```

**关键设计取舍**：

- **TAC 而非 VEX/P-code**：目标是可读性而非精确仿真，一条汇编通常对应一条 IR；控制流与标志位已建模（`cmp/test` 及算术/逻辑指令），栈指针副作用按需建模。
- **栈参数聚合**：32 位 x86 调用约定靠栈传参，lifter 把连续的 `mov [esp+X], v` 聚合进 `CALL(args=...)`。
- **统一内存模型**：寄存器/内存/常量统一为带位宽的表达式，下游分析不用区分访问对象。


## 已知限制
<!-- - 循环等结构化控制流未恢复（跳转已建模为平坦的 `label + if/goto`，尚未折叠成 `if/while`）
- 标志位已建模：`cmp/test` 及算术/逻辑指令（`sub/add/and/or/xor/shl/shr/sar`）后的条件跳转均可还原为真实条件（⚠ `ja/jae/jb/jbe` 暂按有符号比较处理）
- 间接调用目标为运行期值，伪代码显示为 `(*eax)()` / `(*(int*)(...))()`，静态分析不还原具体地址
- 变量未命名（暂用寄存器名 eax/esp），无类型恢复
- python wjdump后展示的代码字符结构不够美观，second edition着重强调将工具系统化正规化 --> 此五类为第三版着重解决的问题，侧重于实用性，第二版着重于实现Algorithm_1的落地实现
<!-- - 仅支持 ELF（x86/x86-64/arm/aarch64），不支持 PE --> 这个是第四版需要解决的问题，着重于拓展分析程序边界
- **栈溢出能力** → **第二版已实现，但解题率有限**：已建立 11 题评测基线，**漏洞识别/偏移定位 9/11、技术路线同官方 9/11**，但**端到端 PASS 仅 1/11**；公共卡点为 `stage_runtime`（多阶段交互时序）
- **堆溢出 / 格式化字符串 / 整数溢出 / ROP 链高级技巧（ret2dlresolve、SROP、BROP、栈迁移）** → **第二版未覆盖**，当前分析聚焦栈溢出
- **全静态大体积二进制** → 仍被 `is_large_static` 跳过（无 PLT 符号可识别 source）

## 下一步规划
- [ ] CFG 构建 + 控制结构恢复（if/while，将平坦 `label + goto` 折叠为结构化语句）
- [ ] 栈参数抑制（清理 CALL 前的 `*(esp+X)=v` 噪声）
- [ ] 变量命名 + 类型恢复
- [ ] 对于python wjdump后的每一个通道字功能（如-s，-c，etc）都一个一个实验，一个一个修改即可
- [ ] **提升端到端解题率（最高优先）**：评测显示 `stage_runtime`（多阶段交互时序）在 11 题中全部命中，优先加固泄漏读取与交互建模
- [ ] 扩展 pwn 覆盖面：堆溢出 / 格式化字符串 / 整数溢出分析（第二版仅覆盖栈溢出）
- [ ] 新增「与官方 exp 相似度」指标（当前完成度衡量打通度，未直接反映与官方的接近程度）
- [ ] 提升 gadget/偏移精度：覆盖更多架构与编译选项下的栈对齐平移等边界情形