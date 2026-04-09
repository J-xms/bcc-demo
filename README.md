# BPF Function Tracer

基于 Python3-bpfcc (BCC) 开发的通用函数追踪工具，支持内核函数和用户态函数的执行时延采集、入参采集和调用栈追踪。

## 依赖说明

### 系统依赖

```bash
# Ubuntu/Debian
apt-get install -y python3-bpfcc linux-headers-$(uname -r)

# CentOS/RHEL / openEuler
yum install -y python3-bcc kernel-headers
```

**说明：**
- `python3-bpfcc` / `python3-bcc`: 必须，Python `bcc` 模块（代码中 `from bcc import BPF`）
- `linux-headers` / `kernel-headers`: 通常需要，编译 eBPF 程序必需（如果报错再安装）
- `bpfcc-tools` / `bcc-tools`: 可选，BCC 命令行工具套件，我们代码不使用

### 内核要求

- Linux Kernel >= 4.1 (支持 eBPF)
- 需要 root 权限运行

## 使用说明

### 命令行参数

```bash
python3 function_tracer.py -r <规则文件> [-t <时长>] [-f <采样频率>]
```

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-r, --rules` | JSON 规则文件路径 | 必选 |
| `-t, --time` | 采集时长（秒） | 10 |
| `-f, --freq` | 采样频率 | 1 (100%) |

### 采样频率

| freq 值 | 采样率 | 说明 |
|---------|--------|------|
| 1 | 100% | 采集所有调用 |
| 10 | ~10% | 每 10 次采集 1 次 |
| 100 | ~1% | 每 100 次采集 1 次 |

### 配置文件格式

```json
{
  "targets": [
    {
      "name": "函数名",
      "type": "kernel|usdt|tracepoint",
      "lib": "库路径（usdt类型必选）",
      "trace_arg": true,
      "arg_types": ["参数类型列表"]
    }
  ]
}
```

**说明：** `duration` 和 `output` 已在代码中固定（分别为 10 秒和 `./results/` 目录）。

#### target 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `name` | string | 函数名 |
| `type` | string | 函数类型: `kernel`(内核函数), `usdt`(用户态函数), `tracepoint`(跟踪点) |
| `lib` | string | 库路径，usdt 类型必选，如 `c` 表示 libc |
| `trace_arg` | boolean | 是否采集入参 |
| `arg_types` | array | 参数类型列表，用于控制入参输出数量 |

### 示例

#### 1. 追踪 TCP 连接函数

```bash
sudo python3 function_tracer.py -r rules/tcp_trace_config.json -t 10 -f 10
```

配置文件 `rules/tcp_trace_config.json`:

```json
{
  "targets": [
    {
      "name": "tcp_connect",
      "type": "kernel",
      "trace_arg": true,
      "arg_types": ["struct sock*", "struct sockaddr*"]
    },
    {
      "name": "tcp_close",
      "type": "kernel",
      "trace_arg": true,
      "arg_types": ["struct sock*", "long"]
    }
  ]
}
```

#### 2. 追踪用户态内存分配函数

```bash
sudo python3 function_tracer.py -r rules/usdt_trace_config.json -f 100
```

配置文件 `rules/usdt_trace_config.json`:

```json
{
  "targets": [
    {
      "name": "malloc",
      "type": "usdt",
      "lib": "c",
      "trace_arg": true,
      "arg_types": ["size_t"]
    },
    {
      "name": "free",
      "type": "usdt",
      "lib": "c",
      "trace_arg": true,
      "arg_types": ["void*"]
    }
  ]
}
```

#### 3. 混合追踪（内核 + 用户态）

```bash
sudo python3 function_tracer.py -r rules/mixed_trace_config.json -t 5 -f 100
```

## 输出格式

```json
{
  "results": [
    {
      "timestamp": 657006789886,
      "latency_us": 26.716,
      "pid": 3207,
      "tid": 3207,
      "func": "tcp_connect",
      "args": ["0xffff8ed8042fd340", "0x0"],
      "kern_stack": ["tcp_v4_connect", "__inet_stream_connect", "inet_stream_connect", ...],
      "kern_stack_id": 126,
      "user_stack": ["__connect"],
      "user_stack_id": 195
    }
  ],
  "total_events": 100
}
```

#### 输出字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `timestamp` | integer | 微秒级 Unix 时间戳 |
| `latency_us` | float | 函数执行时延（微秒） |
| `pid` | integer | 进程 ID (tgid) |
| `tid` | integer | 线程 ID |
| `func` | string | 函数名 |
| `args` | array | 函数入参（十六进制） |
| `kern_stack` | array | 内核调用栈（函数符号列表） |
| `kern_stack_id` | integer | 内核栈 ID，用于关联同栈函数 |
| `user_stack` | array | 用户态调用栈 |
| `user_stack_id` | integer | 用户栈 ID |

## 实现架构

```
┌─────────────────────────────────────────────────────────────┐
│                    Python (function_tracer.py)                │
├─────────────────────────────────────────────────────────────┤
│  Config Loader  │  BPF Code Generator  │  Event Processor   │
└────────┬────────────────┬──────────────────────┬────────────┘
         │                │                      │
         ▼                ▼                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    BCC (libbpfcc)                           │
│  BPF.attach_kprobe() / attach_uprobe() / attach_tracepoint()│
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Linux Kernel (eBPF)                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ kern_stacks │  │ user_stacks │  │    events (perf)    │ │
│  │ (STACK_TRACE)│  │ (STACK_TRACE)│  │  (perf_buffer)      │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 实现原理

### 1. 双重采样机制

采用**计数器采样 + 最小间隔保护**策略：

```
采样逻辑:
1. 每次函数调用，计数器 +1
2. 如果计数器 % freq != 0，检查最小时间间隔
3. 如果距离上次采样 < 1秒，跳过（高频函数控速）
4. 否则采样（保证低频函数至少每秒采集一次）
```

### 2. 数据采集流程

```
                   ┌──────────────────┐
                   │  entry_<func>    │  (kprobe/uprobe)
                   │  1. 记录时间戳   │
                   │  2. 保存参数     │
                   │  3. 采样检查     │
                   └────────┬─────────┘
                            │
                            ▼
                   ┌──────────────────┐
                   │  exit_<func>    │  (kretprobe/uretprobe)
                   │  1. 计算时延    │
                   │  2. 采集栈      │
                   │  3. 输出事件    │
                   └────────┬─────────┘
                            │
                            ▼
                   ┌──────────────────┐
                   │  perf_buffer    │
                   │  Python 回调    │
                   │  符号解析       │
                   └──────────────────┘
```

### 3. 调用栈采集

使用两个独立的栈跟踪表：

| 表名 | 标志 | 用途 |
|------|------|------|
| `kern_stacks` | 0 | 采集内核调用栈 |
| `user_stacks` | 0x100 \| 0x200 | 采集用户态调用栈 |

栈 ID 关联：同一调用链中的所有函数共享相同的 `kern_stack_id` 或 `user_stack_id`。

### 4. 探针类型

| type | 探针类型 | 说明 |
|------|----------|------|
| `kernel` | kprobe/kretprobe | 内核函数 |
| `usdt` | uprobe/uretprobe | 用户态函数（需指定 lib） |
| `tracepoint` | tracepoint | 内核跟踪点 |

## 文件结构

```
.
├── function_tracer.py      # 主程序
├── rules/                  # 规则配置目录
│   ├── tcp_trace_config.json
│   ├── usdt_trace_config.json
│   └── mixed_trace_config.json
└── results/                # 输出目录
    └── *_*.json
```

## 注意事项

1. 需要 root 权限运行
2. 高频函数建议使用 `-f` 参数降低采样率
3. 混合模式下（同时追踪内核和用户态函数），调用栈会分别记录在 `kern_stack` 和 `user_stack`
4. `kern_stack_id` 和 `user_stack_id` 可用于关联同调用栈的函数

## 跨平台运行指南

### ARM64 芯片兼容性

#### 支持情况

BCC 库支持 ARM64 架构，主流 Linux 发行版的 bpfcc-tools 都有 ARM64 版本。

#### 架构差异

| 代码 | x86_64 | ARM64 |
|------|--------|-------|
| `bpf_get_current_pid_tgid()` | ✅ | ✅ |
| `bpf_ktime_get_ns()` | ✅ | ✅ |
| `PT_REGS_PARM1~6` | ✅ | ⚠️ 宏名可能不同 |
| `BPF_STACK_TRACE` | ✅ | ✅ |
| `__sync_fetch_and_add()` | ✅ | ✅ |

#### 主要风险点

`PT_REGS_PARM1~6` 宏在不同架构下名称可能不同：
- **x86_64**: `PT_REGS_PARM1(ctx)`
- **ARM64**: `PT_REGS_ARM64_PARM1(ctx)` 或相同

#### 验证方法

```bash
# 检查当前架构
uname -m

# 检查 BCC 支持
python3 -c "from bcc import BPF; print('BCC OK')"
```

#### 适配建议

如遇编译错误，可能需要根据架构选择正确的参数寄存器宏：

```python
# 在 BPF 代码模板中根据架构选择
import platform
arch = platform.machine()
if arch == 'aarch64':
    parm_macro = 'PT_REGS_ARM64_PARM'
else:
    parm_macro = 'PT_REGS_PARM'
```

---

### openEuler 24+ 系统兼容性

#### 支持情况

openEuler 24+ 完全支持运行，eBPF 已被内核默认支持（Linux 4.14+）。

#### 安装依赖

```bash
# openEuler 使用 dnf/yum
dnf install -y python3-bcc kernel-headers

# 或者
yum install -y python3-bcc kernel-headers
```

#### 可能遇到的问题

**1. 包名不同**

```bash
# 搜索可用包
dnf search bcc
dnf search ebpf
```

**2. 缺少内核头文件**

```bash
# 安装内核开发包
dnf install -y kernel-devel-$(uname -r)
```

**3. 权限问题**

```bash
# 需要 root 权限运行
sudo python3 function_tracer.py -r rules/tcp_trace_config.json -o results/ -t 5
```

#### 验证步骤

```bash
# 1. 检查 eBPF 支持
cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || echo "需要 root 查看"

# 2. 检查 BCC
python3 -c "from bcc import BPF; print('BCC OK')"

# 3. 检查内核版本
uname -r

# 4. 检查内核头文件
ls /usr/include/linux/ | grep bpf.h
```

#### 完整安装示例

```bash
# 更新系统
sudo dnf update -y

# 安装依赖
sudo dnf install -y python3-bcc kernel-devel

# 验证安装
python3 -c "from bcc import BPF; print('BCC OK')"

# 运行测试
sudo python3 function_tracer.py -r rules/tcp_trace_config.json -o results/ -t 5
```

---

### 常见问题排查

| 问题 | 可能原因 | 解决方法 |
|------|----------|----------|
| `ModuleNotFoundError: No module named 'bcc'` | 未安装 bcc | `pip3 install bcc` 或 `dnf install python3-bcc` |
| `Failed to compile BPF module` | 缺少内核头文件 | `dnf install kernel-devel-$(uname -r)` |
| `Permission denied` | 权限不足 | 使用 `sudo` 运行 |
| `func: [unknown]` | 符号解析失败 | 检查是否使用正确的 `-f freq` 参数，避免丢失采样 |
| `stack: []` | 栈跟踪被禁用 | 混合模式下内核/用户栈同时采集可能受限 |

### 内核配置检查

确保以下内核配置已启用：

```bash
# 检查 eBPF 相关配置
cat /boot/config-$(uname -r) | grep -E "CONFIG_BPF|CONFIG_BPF_SYSCALL|CONFIG_BPF_JIT"
```

预期输出应包含：
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_CGROUPS=y
CONFIG_KPROBES=y
```
