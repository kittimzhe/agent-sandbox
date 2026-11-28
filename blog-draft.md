# 给 AI Agent 进程套上 eBPF 沙箱：设计笔记与内核教我的七课（草稿 v0.3）

> 状态：M0+M1+M2 完成后的完整稿。目标平台：个人技术博客。
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

- **作用域：cgroup v2 + shim 模式**——进程自己把自己写进 cgroup 再 exec，零竞态窗口（shim 自身的 exec 计数在 scope 外，语义正确）
- **exec 拦截**（`lsm/bprm_check_security`）：exact hash + LPM 双表，六项语义矩阵（允许/拒绝/前缀共串/一层命中/一层深度/递归）
- **file 拦截**（`lsm/file_open`）：deny_read/deny_write 双向，方向不对称性有测试锁定（deny_read 不拒写）
- **net 拦截**（`lsm/socket_connect`）：CIDR LPM（v4 走 v4mapped 形式防族混串）优先于 allow 表
- **默认值的不对称**：exec/net 是 allow-list（未列名拒绝），file 是 deny-list（未列名放行）——每个判定带规则溯源（`exec.allow[1]`、`net.deny_cidr[0]`）
- **签名层（诚实版）**：Ed25519 分离签名，`run` 强制 `--public` 验证后才把规则送进内核，未签名策略直接拒绝。包注释写明边界：防传输中篡改和误改，**防不了 root**（root 可改 runtime、密钥、内核）——shirudo 用内核补丁 + 密封 keyring + TPM 关闭那条边界，那是另一个产品
- **事件流**：ringbuf 逐 exec 记录（binary/pid/ktime），NDJSON 输出与计数 map 互相印证；drop 计数让部分流自己声明不完整。第一版 `Read` 在空 ring 上永久阻塞——超时 timer 关 reader 解锁，ringbuf 的经典坑
- **同源编译器 + parity 套件**：一个编译器产出引擎和内核两张表；parity 测试把三方锁死（引擎判定 ↔ 内核表镜像 ↔ 期望表），14 用例在真内核上全绿。写它时还验证了 parity 的价值：第一轮两处失败都是**测试作者错、代码对**——引擎和内核互相印证共同否决了测试表

## 与一个 30 万行 C 仓库的相处之道（贡献侧的七课之外）

这个项目的技术部分之外，我在 shirudo-dev/shirudo 里当了几天贡献者，那几天的密度不比写 BPF 低。三个转折值得记：

**第一个 PR 被维护者收编了。** 我修了 xtop 的一个混算 bug（by-image 的树位置把不同树的序列号 min/max 到一起），47 项 CI 全绿。然后 John Fastabend（维护者）关掉了我的 PR，留言"pushed some updates here"——他以我的改动为基底在自己的 PR 里继续，类型和注释原样保留，另加了一个 UNKNOWN_LAG 排序细化，随后合并进 main。这不是拒绝，是收编：我的修复进了主线，只是经由维护者的手。

**第二个 PR 输了一场 2 分钟的竞速。** 我在另一个 issue 上做了根因分析（upatch map --json 对无 decoder 的 map 失败），写了修复（BTF 回退），发 PR。后来翻 issue 时间线才发现：有人在我发出前 **2 分钟**贴出了同样的根因分析，社区据此走了另一条路（报告者自己加 decoder，报错信息的改进由另一个 commit 合入），维护者关闭了 issue。我的 PR 从"修 bug"变成了"在维护者明确留给自己的设计决策上的抢先实现"。我留下了一条评论：承认收敛、说明我的设计（带 format 标记的 BTF 回退）、明确接受关闭。竞速失败时，得体的表态比坚持更能说明你是谁。

**第三个是设计纪律救了我一次。** 一个跨层 schema 问题（xtop 的 drill-down 混入同 id 不同 build 的 findings），我写了一条设计评论：两条实现路径（加列 vs JOIN）、两词搜索语义、请维护者确认方向，然后**等**。次日有人发了实现 PR——走了我命名的备选路径，语义与我方案一致。如果我当时直接按首选方案动手，就是又一次正面撞车。三次教训收敛成一条规则：**在高速仓库，方案评论先行，实现等确认**——它不能赢竞速，但能让你不输第二次。

## 待写（实现后补）

- OTLP 事件导出（NDJSON 已够 demo，OTLP 是运维接入）
- fuzz 扩展到 match 与 event 的内核侧输入

## e2e 后记（2026-11-28）：把手动矩阵冻结成断言，第一跑就抓到三个

七课写完之后，我把所有手动验证矩阵冻结成 `scripts/e2e.sh`（17 个断言用例，拒绝只认 errno 文本——那是"策略拒的"和"网络拒的"的唯一分界）。**第一跑 11/17**，三个真 bug 浮出：

1. **net 强制执行被一轮调试的 bisect 留在了禁用态**——六轮"全绿"里没有任何手动检查发现它（parity 测试直接调加载函数，绕过了 run() 的装配路径）。教训：**被注释掉的一行，只有端到端断言能看见。**
2. **协议号用了我发明的 1/2**，而内核 `sk_protocol` 报的是 6/17——所有 allow 永远 miss。之前它被 bug 1 掩盖（禁用时什么都不拒，包括该拒的）。两个 bug 互相打掩护。
3. **`BPF_CORE_READ_INTO(&addr[12], …)` 只读 1 字节**（宏按目标存储定长），v4 对端读成 1.1.0.0，CIDR trie 永不命中。追它时被一个假线索绕了很久：e2e 的 self-build 每次把嵌旧对象的二进制写进测试路径——**"新鲜源码+陈旧对象"是比 bug 本身更隐蔽的故障模式**，最后靠计数器（比 printk 可靠，从不丢消息）分离出"键坏/表坏/二进制坏"三种可能。

八、九、十课。一个比七个多。
