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
- **统一入口 analyze.py**：单文件内含「基础设施 + Algorithm 2 评分 + Algorithm 1 闭环」；`<bin>` 单轮分析、`--refine` 迭代精炼
- **Taint 引导的迭代 EXP 精炼闭环（Algorithm 1）**：`analyze.py --refine` 落地 生成 EXP → 真实验证 → 归因 → 反查静态语料补全 Taint → 重出报告，含 8 个终止条件与锁定字段回填(防漂移)
- **EXP 完成度评分与收敛策略（Algorithm 2）**：`score_exp` 四维加权(运行时/静态/语义/覆盖) + PASS 短路 + 单调包络 + 双阈值滞回；可测性与证据双重门控
- **List Table 与利用方向库**：十类证据归一为统一索引，`lookup` 四态反查；13 条经典栈溢出路线按证据判定可行性并给出首选方向
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

### Algorithm 1：Taint 引导的迭代 EXP 精炼闭环（analyze.py --refine）

`analyze.py --refine` 落地 `algorithm/Algorithm_1.py` 的完整闭环：
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
python3 analyze.py <binary> --refine --rounds 3 --theta 0.95

# 带 flag 探测 / 导出最终报告 / 单色输出
python3 analyze.py <binary> --refine --flag flag --json-out ret2text_final.json
python3 analyze.py <binary> --refine --no-color
```

终止状态: `PASS` / `PASS_SUSPECT` / `CONVERGED` / `NO_PROBLEM` / `STALLED` / `UNRESOLVABLE` / `LLM_FAILED` / `MAX_ROUNDS`。

### Algorithm 2：EXP 完成度评分与收敛策略（analyze.py 内）

落地 `algorithm/Algorithm_2.py` 的设计，作为**唯一评分入口**（`score_exp`），
消除「轮内一个尺、交付另一个尺」的量纲不一致。

**信度分层（高→低）**：

| 维度 | 权重 | 依据 |
|---|---|---|
| `run` 运行时 | 0.40 | `verify_exp` 阶段分（`marker_ok`…`no_exp_code`），真机可复现 |
| `static` 静态结构化 | 0.30 | 偏移命中实测值(0.5) + 路线成立(0.3) + 无阻塞项(0.2) |
| `llm` 语义评分 | 0.15 | LLM 自评 × 置信度折扣 × EMA 平滑（**必须引用证据**） |
| `cov` 工具覆盖 | 0.15 | 问题经 List Table 反查的命中率(HIT/DERIVED/SECTION/MISS) |

**四条不变量**：

1. **PASS 短路**：`F.ok` 直接 1.0，不参与加权折中（真打通不会被主观分拉低）
2. **非 PASS 不越阈**：权重设计使未打通时 `raw ≤ 0.82 < θ=0.95`
3. **单调包络**：`Score_k = max(Score_{k-1}, raw_k)`，跨轮只升不降，保证可比
4. **双阈值滞回**：收敛需连续 2 轮 `raw ≥ 0.85`，并诊断 `REGRESSION` / `STALLED`

**两个关键语义**：

- **可测性门控**：静态证据测不出偏移时(如手工循环读缓冲)，该维度**移出加权并重新归一化**，
  而非计 0 分——避免把工具盲区记到 EXP 账上（`breakdown.excluded` 可追溯）
- **证据门控**：LLM 的评分与问题都必须引用证据（`evidence` 字段）。
  **无据的评分不计分、无据的问题不扣分**（正负双向对称，防「无据刷分」与「假 blocker」）

### List Table 与利用方向库

- **统一行模型**（`analysis/listtable.py`）：把 taint 的十类证据归一为 `ToolEntry`，
  以 `类别:名字` 为键建索引，提供 `lookup(kind, target)` 四态反查：
  `HIT`(精确命中) / `DERIVED`(可推导) / `SECTION`(分区存在) / `MISS`(无分区)，
  评分映射 1.0 / 0.7 / 0.5 / 0.0。**单一数据源**同时服务 prompt 渲染、`resolver` 反查与覆盖度评分
- **利用方向库**（`analysis/techniques.py`）：13 条经典栈溢出路线
  （ret2text / ret2shellcode / ret2libc / ret2libc-leak / ret2csu / ret2syscall / srop /
  ret2dlresolve / ret2rop / stack-pivot / format-leak / canary-bypass / partial-overwrite）
  以 `requires` 声明前置能力(如 `exec:system`、`gadget:pop rdi`、`prot:nx_off`、`arch:bits64`)，
  可行性由 List Table **客观判定**为 `AVAILABLE` / `PARTIAL` / `BLOCKED`，并按策略优先级 `rank` 排序，
  在 prompt 中为首选路线标 `★首选`，引导模型不再只想到 `system@plt` + `/bin/sh`

### 离线校准（test_py/calibrate_weights.py）

以题库 11 道题的**官方 exp** 为 ground truth，纯静态校验（不需 LLM/网络）：

```bash
python3 test_py/calibrate_weights.py --verbose
```

当前结果：`偏移实测 10/11 | 路线反推 11/11 | 模型覆盖 10/11`；
11 道官方正解得分**全部为 0.820**（非 PASS 上限），证明权重自洽、
分数只反映 EXP 质量而不混杂工具识别率（未测出的 1 题标记为「证据缺失故不可判定」）。

### 栈溢出题库评测（第二版基线）

`test_py/run_stackoverflow_batch.py` 对题库中**可测的栈溢出题目**（动态链接 ELF + x86/x86-64）
批量跑 `analyze.py --refine`，并与**题目自带官方 exp** 对照（偏移 / 技术路线 / 端到端 PASS）。

```bash
python3 test_py/run_stackoverflow_batch.py --tier 1 --rounds 2   # 32 位 8 题
python3 test_py/run_stackoverflow_batch.py --tier 2 --rounds 3   # 64 位 3 题
python3 test_py/run_stackoverflow_batch.py --only ret2libc1      # 单题
```

**32 位（第一梯队，8 题）**

| 题目 | 状态 | 完成度 | 工具偏移 | 官方偏移 | 偏移 | 技术 | gaps |
|---|---|---|---|---|---|---|---|
| **ret2text** | **PASS** | **100%** | 0x70 | 0x70 | ✔ | ✘ | 0 |
| stack_example | STALLED | 55.5% | 0x18 | 0x18 | ✔ | ✔ | 4 |
| **ret2libc1** | **PASS** | **100%** | 0x70 | 0x70 | ✔ | ✔ | 0 |
| ret2libc2 | MAX_ROUNDS | 54.1% | 0x70 | 0x70 | ✔ | ✔ | 3 |
| ret2libc3 | MAX_ROUNDS | 58.9% | 0x70 | 0x70 | ✔ | ✔ | 3 |
| ret2shellcode | MAX_ROUNDS | 55.5% | 0x70 | 0x70 | ✔ | ✘ | 5 |
| train_ret2libc | MAX_ROUNDS | 59.2% | 0x20 | 0x20 | ✔ | ✔ | 4 |
| ropasaurusrex | MAX_ROUNDS | 59.9% | 0x8c | 0x8c | ✔ | ✔ | 3 |

`PASS 2/8 | 偏移符合 8/8 | 技术符合 6/8 | 平均完成度 67.9%`

**64 位（第二梯队，3 题）**

| 题目 | 状态 | 完成度 | 工具偏移 | 官方偏移 | 偏移 | 技术 | gaps |
|---|---|---|---|---|---|---|---|
| shellcode_x64 | STALLED | 52.1% | 0x18 | 0x18 | ✔ | ✔ | 4 |
| hitcon_level5 | MAX_ROUNDS | 56.3% | 0x88 | 0x88 | ✔ | ✔ | 3 |
| r0pbaby | MAX_ROUNDS | 16.1% | - | 0x8 | ✘ | ✘ | 7 |

`PASS 0/3 | 偏移符合 2/3 | 技术符合 2/3 | 平均完成度 41.5%`

> **结论（11 题合计）**：端到端 `PASS 2/11`；**漏洞识别与溢出偏移定位**达 `10/11`，
> **技术路线与官方同构**达 `8/11`。瓶颈仍是**多阶段交互的运行时细节**
> （`stage_runtime` 在 11 题中全部命中，为首要卡点）。

> **指标口径（Algorithm 2）**：`完成度` = 四维加权（运行时 0.40 / 静态 0.30 / 语义 0.15 / 覆盖 0.15），
> 未 PASS 天然封顶 `0.82`（= `0.40×0.55 + 0.30 + 0.15 + 0.15`），故 52%~60% 表示
> 「流程跑通但未拿到 shell」，**不代表 EXP 质量差**；重复运行因 LLM 非确定性可能小幅波动。
> `技术` 列以**官方路线**为基准：`ret2text` 实际是模型用另一条合法路线（system@plt 直调）打通（真机 PASS）而判 ✘。
> 上表为**修复前**批量跑的结果；其中 `ret2shellcode` 的 ✘ 源于当时交付物被空 EXP 覆盖（`no_exp_code`），
> 现已由「交付物单调性」修复解决（详见下节），该题路线反推已恢复正确为 `ret2shellcode`。


### 静态证据能力补强（近期修复）

针对 `ret2shellcode` 类题型的排查，补齐了四处**通用**证据能力；均已通过离线校准回归
（官方正解仍同为 0.820，未破坏评分体系）：

| 修复 | 内容 | 通用收益 |
|---|---|---|
| 全局落地缓冲 | 识别 `strcpy/strncpy/memcpy/memmove` 等拷贝**到 `.data/.bss` 固定地址**的目标，产出 `global_buf` 可利用目标（如 `buf2 @ 0x804a080`） | 一切"输入被拷入全局缓冲"的题型；避免模型去猜不可知的栈地址 |
| 对象符号采集 | 符号表同时收集 `STT_OBJECT`（此前仅 `STT_FUNC`） | 全局变量/缓冲显示真名(`buf2`)而非伪名(`sub_804a080`) |
| 可执行性判定 | 新增段级 `PT_LOAD` 的 `p_flags` 采集(`Section.seg_exec`)；配合 `PT_GNU_STACK` 推导的 `NX=off`，判定"可写内存是否可执行" | 代码跳转与栈迁移目标的可行性；此前**仅凭节标志**会把 `.bss` 误判为不可执行，**导致模型主动排除正解** |
| 交付物单调性 | `J`(EXP 产物) 与 `Score_k`(分数) 对齐：按验证阶段保留历史最优，空 `exp_code` 拒绝覆盖；`score_exp` 的 PASS 短路不再丢失路线信息 | 避免"分数记住峰值、交付的却是更差/空 EXP" |

> **复核**：`ret2shellcode` 修复后，模型已正确定位 `global_buf buf2 @ 0x804a080` 并采用
> `shellcode.ljust(112,'A') + p32(0x804a080)`（路线反推 `ret2shellcode` 正确）。但真机仍 `segv`，
> 经排查确认为**运行环境限制**而非工具缺陷（详见已知限制）：三方（官方 exp / 官方解法的 Py3 修正版 / 模型产出）均在同一点失败。

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

**与 objdump 的对齐**（第三版逐个通道对标，同一二进制左右对照可逐字符一致）：

| 选项 | 已对齐内容 |
|---|---|
| `-f` | `file format` 行、`architecture: …, flags 0x…:` 与标志名行(EXEC_P/HAS_SYMS/D_PAGED…)、`start address` 按位宽补零 |
| `-h` | 列宽/表头精确对齐、`Idx` 跳过 NULL 后从 0 编号、属性行缩进、`-j` 指定节区时索引不变 |
| `-s` | 每 4 字节一组、16 字节一行、十六进制列定宽、文件头行、节区间不空行、支持 `--start/--stop-address` |
| `-t` | 直读 `.symtab` 全量符号、7 字符 flags(`l    d`/`l     F`/`l    df`)、`*UND*` 全局符号不印绑定字母、`.hidden/.internal` 可见性前缀 |
| `-d`/`-D` | 文件头行、函数标签与节区符号(`<.plt>`)、跳转目标标注(含 `<_init+0x1e>` 函数内偏移)、超 7 字节指令换行续排、**连续零字节折叠为 `...`** |
| 选项 | `-j` 同时支持 `-d/-D/-h/-s`；`-j` 节区不存在时告警；`-M intel/att` |

> **语法取舍**：默认 **Intel** 语法（`-M att` 可切 AT&T）。故操作数书写与 objdump 的 AT&T 默认不同（如 `sub esp, 8` vs `sub $0x8,%esp`、`66 90` 显示为 `nop` 而非 `xchg %ax,%ax`），属显式取舍，非排版差异。

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
│   ├── listtable.py      # List Table: 十类证据归一为统一索引 + 四态反查
│   ├── techniques.py     # 13 条栈溢出技术路线(能力判定 + 策略优先级)
│   ├── resolver.py       # Resolve: 按问题 kind 反查静态语料(Algorithm 1)
├── codegen/    # 伪代码生成
│   ├── __init__.py
│   ├── c_generator.py
│
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
│   ├── Algorithm_1.py    # Taint 优化闭环伪代码(已落地于 analyze.py --refine)
│   ├── Algorithm_2.py    # EXP 完成度评分与收敛策略伪代码(已落地于 analyze.py 的 score_exp)
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
│   ├── calibrate_weights.py        # Algorithm 2 离线校准(官方 exp 作基准, 纯静态)
├── analyze.py           # 统一入口: 单轮分析(默认) / --refine 迭代精炼闭环
│                        # 内含 round_zero + Algorithm 2(score_exp) + Algorithm 1(refine)
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
  analyze.py <binary> [addr] [--json-out f]             → 单轮 LLM 漏洞分析(+报告导出)
  analyze.py <binary> --refine [--rounds N --theta t]   → Algorithm 1 闭环(需 WSL/Linux)
  calibrate_weights.py [--tier all] [--verbose]         → Algorithm 2 离线校准(官方 exp 基准)
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
- **栈溢出能力** → **第二版已实现，但解题率有限**：已建立 11 题评测基线，**漏洞识别/偏移定位 10/11、技术路线同官方 8/11**，但**端到端 PASS 仅 2/11**；公共卡点为 `stage_runtime`（多阶段交互时序） -->后期再进行优化，先不管
- **`ret2shellcode` 环境限制（已查明，非工具缺陷）** → 该题正解依赖"NX=off 时 `.bss` 可执行"，即需内核赋予 `READ_IMPLIES_EXEC`（老式 32 位行为）。
  实测该题在 WSL 上**三方均失败**：官方 `exploit.py`（本身为 **Py2 语法**，`'A'` 应作 `b'A'`，Py3 下直报 `TypeError`）、其 Py3 修正版、以及模型产出（与官方 payload 逐字等价）都在同一点 `segv`。
  结论：`NX=off` 仅保证**栈**可执行，**不等于 `.bss` 可执行**；现代内核多已收紧该行为。不影响评测口径——批量评测仅从官方 exp **源码文本**反推路线，不依赖其可运行性
- **堆溢出 / 格式化字符串 / 整数溢出 / ROP 链高级技巧（ret2dlresolve、SROP、BROP、栈迁移）** → **第二版未覆盖**，当前分析聚焦栈溢出 -->主要是算法的更新以及功能的完善
- **全静态大体积二进制** → 仍被 `is_large_static` 跳过（无 PLT 符号可识别 source）
- 仅支持 ELF（x86/x86-64/arm/aarch64），不支持 PE --> 这个是第四版需要解决的问题，着重于拓展分析程序边界

## 下一步规划
- [ ] **提升端到端解题率（最高优先）**：评测显示 `stage_runtime`（多阶段交互时序）在 11 题中全部命中，优先加固泄漏读取与交互建模
- [ ] **扩展 pwn 覆盖面**：堆溢出 / 格式化字符串 / 整数溢出分析（第二版仅覆盖栈溢出）
- [ ] **权重拟合（待补）**：`WEIGHTS` 目前为先验值(0.40/0.30/0.15/0.15)，已证明自洽但未做参数拟合（样本仅 11 题，不宜过度拟合）
- [ ] 提升 gadget/偏移精度：覆盖更多架构与编译选项下的栈对齐平移等边界情形
