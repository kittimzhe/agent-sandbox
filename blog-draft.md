# 给 AI Agent 进程套上 eBPF 沙箱：设计笔记与内核教我的七课（草稿 v0.2）

> 状态：随 agent-sandbox 实现修订。目标平台：个人技术博客。
> 素材纪律：只写已实现并验证的内容；设计部分明确标注"计划"。

## 为什么是现在

2026 年的两件事让"agent 进程沙箱"从可选变成必需。一是 agent 在生产环境跑真实任务（改文件、调 API、执行 shell 工具）越来越常见；二是 OpenAI 和 Cisco 在 11 月开源了 shirudo——它把"agent 驱动的安全"变成了正式方向。但 shirudo 解决的是"谁能给内核加载 BPF"，它需要定制内核（5 个未进主线的补丁）和 TPM 2.0。跑 agent 的团队面对的问题更朴素：**这个 agent 进程树，允许它读什么、写什么、连哪里、执行什么？**

现有工具都不对口：Tetragon/KubeArmor 面向 K8s 集群和容器，部署面大；seccomp 太原始；提示词层面的"约束"不是安全边界。缺一个单机、轻量、面向 agent 进程树的东西。这就是 agent-sandbox：一条命令挂 4 个 BPF 程序（观测 + exec/file/net 三向拦截），策略是一个手写解析的严格子集 YAML。

```console
$ sudo agent-sandbox run --policy agent-web.yaml -- /bin/sh -c 'ls /'
running /bin/sh -c ls / in /sys/fs/cgroup/agent-sandbox under agent-web
$ sudo agent-sandbox run --policy strict.yaml -- /bin/sh -c true
operation not permitted        # LSM 在内核里拒绝的
```

## 与 shirudo 的边界（诚实章节）

shirudo 的信任链：签名 BPF loader → 内核密封 keyring → TPM 测量寄存器 → 离线可验证的 attestation。root 无法加载未签名 BPF、无法篡改记录。

agent-sandbox 不做这些，而且要说清楚后果：**root 可以卸载我们的 BPF 程序、改我们的策略**。它防的是"agent 进程越权"，不防"agent 拿到 root"。对这个威胁模型，这是正确的取舍——防 root 需要 shirudo 那样的内核补丁 + TPM + initrd 信任链，成本是另一个量级；而 agent 越权（提示词注入后 `curl` 内网、读 `~/.ssh`）是每天都在发生的风险。shirudo 的 AGENTS.md 里有一句我抄进了自己的代码注释：a policy that reads differently from what its author wrote is a sandbox that enforces the wrong rules。

## 内核教我的七课

### 1. fentry 挂得上，不代表它活着（kernel 7.0 把 exec 路径内联了）

第一个程序挂 `fentry/do_execve`——加载成功，计数为零。查 kallsyms：`do_execve` 整个消失，`bprm_execve` 只剩一个**死副本**（编译器内联后的孤儿符号，ftrace 能挂、永远没人调）。基线计数器改用 tracepoint `sched/sched_process_exec`（稳定 ABI、任何内核都活着）；fentry 留给 M1 的 LSM hook——那里才需要精确函数。经验：**前沿内核上，"挂载成功"和"会触发"是两件事，kallsyms 和 BTF 各说各话。**

### 2. Verifier 的展开预算：100 万指令上限不是闹着玩的

exec 策略第一版用双层循环逐字节比对（64 规则 × 64 字节）——verifier 报 `Processed 1000001 insn` 拒载。解法是把匹配交给内核：**BPF_MAP_TYPE_LPM_TRIE** 的查找是内核内 O(前缀深度)，一次 map lookup 替掉整个外层循环，OneLevel 的深度检查剩一个有界小循环。经验：**verifier 会为每个可能路径付费，数据结构选型就是在给 verifier 算预算。**

### 3. LPM 的 bit 前缀说不了"相等"——一个安全级漏洞的诞生与修复

strict 策略只放行 `/bin/ls`，测试却发现 `/bin/lsx` 也被放行。根因：LPM 是 bit 前缀匹配，"/bin/ls" 作为前缀天然匹配 "/bin/lsx"；而且最长匹配会**遮蔽**本应生效的更短 OneLevel 规则。修复是双表架构：**Exact 规则走 HASH（全等 O(1)）、前缀规则走 LPM（目录前缀带尾斜杠）**。经验：**每种匹配语义用表达它的数据结构；让一种结构兼职两种语义，漏掉的洞一定是放行方向的。** 有趣的是，用户态 matcher 的 fuzz 早就抓过同类"过度匹配"（`Compile("/*")` 变成匹配一切的根规则）——同一个 bug 语义在内核表里又长了一遍。

### 4. `bpf_probe_read_kernel_str` 只保证 NUL，不保证清零

最诡异的一轮：**LPM 测试全过、exact hash 全 miss**，表内容 dump 出来明明正确。根因：`char path[64];` 未初始化——helper 只写入字符串和 NUL，**尾部 56 字节是栈上垃圾**，而 exact 键要比较全部 64 字节。`char path[MAX_PREFIX] = {};` 一行修复。这个 bug 同时是 file 程序的 **deny 方向安全漏洞**（该拒的放行了）。经验：**helper 的保证条款要逐字读；两种查找一好一坏时，先看它们语义的分界线（这里是 prefixlen 只数前缀位）。**

### 5. Verifier 知道 sockaddr 的 16 字节，不知道你想要 28 字节

net 程序逐字节读 `sin6_addr`——verifier：`access beyond struct sockaddr at off 17`。hook 的 ctx 指针按通用 `struct sockaddr`（16 字节）定界，读 in6 的字段天然越界。解法：`BPF_CORE_READ_INTO`——helper 调用按**字段真实尺寸**拷贝，verifier 对 helper 参数不做 ctx 定界检查。

### 6. kernel 7.0 的 verifier 新规：maybe-null 指针不许做算术

`BPF_CORE_READ(sock, sk->sk_protocol)` 直接拒：`pointer arithmetic on trusted_ptr_or_null_ prohibited, null-check it first`。拆两步、判空、再读。经验：**旧内核宽容的写法，新内核会精确地拒绝；报错信息本身就在教你怎么写。**

### 7. 地址族不是协议号——一次测试设计失误牵出的真 bug

net 允许表怎么查都不中。三层排查（禁用 net LSM 二分、绝对路径、直连探针）后发现我把 `family == AF_INET ? 1 : 2` 当成了 tcp/udp 编码——**v4 的 family 恰好是 2，全被当成 UDP 查表**。协议号在 `sock->sk->sk_protocol` 里，跟地址族是两个维度。经验：**"恰好能编译通过"的语义错误最难抓，测试矩阵要按语义维度（协议 × 地址族）而不是代码路径设计。**

## 已实现并验证的部分

- **作用域：cgroup v2 + shim 模式**——进程自己把自己写进 cgroup 再 exec，零竞态窗口（M0 就验证过：shim 自身的 exec 计数在 scope 外，语义正确）
- **exec 拦截**（`lsm/bprm_check_security`）：exact hash + LPM 双表，六项语义矩阵（允许/拒绝/前缀共串/一层命中/一层深度/递归）
- **file 拦截**（`lsm/file_open`）：deny_read/deny_write 双向，方向不对称性有测试锁定（deny_read 不拒写）
- **net 拦截**（`lsm/socket_connect`）：CIDR LPM（v4 走 v4mapped 形式防族混串）优先于 allow 表
- **默认值的不对称**：exec/net 是 allow-list（未列名拒绝），file 是 deny-list（未列名放行）——每个判定带规则溯源（`exec.allow[1]`、`net.deny_cidr[0]`）
- **用户态/内核态同源**：一个编译器（decision.Engine）产出两边的表，`decide` 子命令是引擎判定的人类可读接口，将来做 parity 测试的基准

## 待写（实现后补）

- 用户态签名校验（M2 简化版：防误加载，明说防不了恶意 root）
- OTLP 事件导出
- ringbuf 事件流（当前是计数 map，事件流是 agent-sandbox 的审计叙事收尾）
