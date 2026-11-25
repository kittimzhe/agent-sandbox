# 给 AI Agent 进程套上 eBPF 沙箱：一个轻量运行时的设计笔记（草稿）

> 状态：草稿 v0.1，随 agent-sandbox 实现逐步修订。目标平台：个人技术博客。
> 素材边界：只写已实现并验证的内容；设计部分明确标注"计划"。

## 为什么是现在

2026 年的两件事让"agent 进程沙箱"从可选变成必需。一是 agent 在生产环境跑真实任务（改文件、调 API、执行 shell 工具）越来越常见；二是 OpenAI 和 Cisco 在 11 月开源了 shirudo——它证明了一件事：安全社区已经把"agent 驱动的安全"当成正式方向。但 shirudo 解决的是"谁能给内核加载 BPF"，它需要定制内核（5 个未进主线的补丁）和 TPM 2.0。跑 agent 的团队面对的问题更朴素：**这个 agent 进程树，允许它读什么、写什么、连哪里、执行什么？**

现有工具都不对口：Tetragon/KubeArmor 面向 K8s 集群和容器，部署面大；seccomp 太原始；RL 级别的"提示词约束"不是安全边界。缺一个单机、轻量、面向 agent 进程树的东西。这就是 agent-sandbox 的定位——也诚实地承认：shirudo 用内核持有信任状态（密封 keyring、TPM 测量寄存器），我们不做，边界差异在后文。

## 三个设计决策（已实现，可验证）

### 1. 作用域：cgroup v2，不跟踪 PID

跟踪 PID 树的经典竞态：`fork` 出的子进程在用户态记录它之前就 exec 了。cgroup v2 没有这个问题——进程一进 cgroup，它的所有后代自动在内，内核侧 O(1) 判断"这个 task 在不在沙箱里"（BPF 程序查 `bpf_get_current_cgroup_id()` 对不在 map 就放行/拒绝）。Tetragon 用同样的机制做 K8s pod 作用域。

用户态只做一件事：把根进程写进 cgroup（`mkdir` + `PROCESSES` 文件写 PID），进程退出后 cgroup 自动空、自动可删。

### 2. 模式必须"可强制"才允许解析

策略里的路径模式，`*` 只能出现在**末尾**：`/usr/bin/*`（一个组件）、`/root/.ssh/**`（任意层）。`/home/*/.ssh/**` 这种中间通配在编译期就拒绝，报错是 "a '*' the kernel side cannot enforce: it may only end a path"。

理由不是实现偷懒，而是语义诚实：BPF 里做 glob 需要在热路径逐组件解析，verifier 对循环的约束让这事又难又贵；而前缀匹配 O(1)。中间通配的"便利"换来的是用户以为在保护 `*所有用户*` 的 .ssh，实际下发的规则保护的是字面量 `*` 那一个目录——**策略读起来和强制执行的不一致，比不支持更危险**。（shirudo 的 AGENTS.md 有一句同精神的话：a policy that reads differently from what its author wrote is a sandbox that enforces the wrong rules。）

### 3. 默认值的不对称

- **exec / net 是 allow-list**：没点名的二进制不能执行、没点名的地址不能连。agent 场景里"做了策略没提的事"就是风险本身。
- **file 是 deny-list**：没点名的路径可读可写。没人写得出"允许读的每个文件"的策略——那种策略在第一次 `apt-get install` 时就碎了。

每个判定带规则溯源（`exec.allow[1]`、`net.deny_cidr[0]`、`default deny`），事件流原样携带，审计时能对回策略文件的具体行。`decide` 子命令把这个能力做成任何主机可跑的查询 CLI：

```console
$ agent-sandbox decide --policy policy.yaml net tcp 169.254.169.254 443
{"allowed":false,"rule":"net.deny_cidr[0]"}
```

## 与 shirudo 的边界（计划中的诚实章节）

shirudo 的信任链：签名 BPF loader → 内核密封 keyring → TPM 测量寄存器 → 离线可验证的 attestation。root 无法加载未签名 BPF、无法篡改记录。

agent-sandbox 不做这些，而且要写清楚后果：**root 可以卸载我们的 BPF 程序、改我们的策略**。它防的是"agent 进程越权"，不防"agent 拿到 root"。对这个威胁模型，这是正确的取舍——防 root 需要 shirudo 那样的内核补丁 + TPM + initrd 信任链，成本是另一个量级；而 agent 越权（提示词注入后 `curl` 内网、读 `~/.ssh`）是每天都在发生的风险。第三阶段计划加用户态签名校验（防误加载，明说防不了恶意 root），并在 README 里给出 shirudo 式威胁模型文档。

## 实现脚手架（已全部落地并测试）

```
internal/policy     严格子集 YAML 手写解析：未知 key / 缺必填 / 畸形值 = 带行号报错，绝无默认值
internal/match      模式编译：*（一个组件）**（任意层）只许在尾部，中间通配编译期拒绝
internal/decision   策略 → 决策引擎：exec/file/net 三判定，每个带规则溯源；将来 BPF 程序的 parity 基准
internal/event      事件模型 + NDJSON：显式 wire 格式、schema 版本、payload 一致性校验
cmd                 validate / decide 子命令，40+ 测试，任何主机可跑
```

依赖纪律学 shirudo：不引 YAML 库（手写子集解析器）、不引 cobra（子命令 switch）——一个安全运行时的依赖面本身就是攻击面。

## 待写（实现后补）

- verifier 拒绝实录（第一个 LSM 程序过 verifier 的过程，`-mcpu=v4`、`-fno-jump-tables` 的坑——shirudo 文档里都有，但自己踩一遍才有的说）
- ringbuf 消费与事件有序性（ktime_ns vs 墙钟）
- cgroup 生命周期的边界情况（进程自杀、cgroup 泄漏检测）
