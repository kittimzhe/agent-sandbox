# 给 AI Agent 进程套上 eBPF 沙箱：设计笔记，和内核教我的七课

仓库：[github.com/kittimzhe/agent-sandbox](https://github.com/kittimzhe/agent-sandbox)（37+ 提交，CI 全绿）。一条命令加载四个 BPF 程序：一个数 exec 的 tracepoint，三个 LSM hook（exec / file / net），全部由一个策略文件驱动。

## 为什么是现在

2026 年底的两件事，把"agent 进程沙箱"从可选变成了必需。一是 agent 在生产环境跑真实任务——改文件、调 API、执行 shell 工具——越来越常见；二是 11 月 OpenAI 和 Cisco 开源了 [shirudo](https://github.com/shirudo-dev/shirudo)，"agent 驱动的安全"成了正式方向。但 shirudo 回答的是另一个问题：**谁有权往内核加载 BPF**。它需要定制内核（5 个还没进主线的补丁）和 TPM 2.0。而跑 agent 的团队的问题朴素得多：

> 这个 agent 进程树，允许它读什么、写什么、连哪里、执行什么？

现有工具都不对口：Tetragon、KubeArmor 是集群和容器平台，部署面大；seccomp 太原始；提示词层面的"约束"不是安全边界。缺一个单机、轻量、形状为 agent 进程树设计的沙箱。这就是 agent-sandbox：策略是一个严格子集的 YAML，手写解析、带行号的报错、没有默认值。

```console
$ sudo agent-sandbox run --policy agent-web.yaml -- /bin/sh -c 'ls /'
running /bin/sh -c ls / in /sys/fs/cgroup/agent-sandbox under agent-web

$ sudo agent-sandbox run --policy strict.yaml -- /bin/sh -c true
operation not permitted        # 是 LSM 程序在内核里拒绝的
```

## 与 shirudo 的边界，说清楚

shirudo 的信任链：签名 BPF loader → 内核密封 keyring → TPM 测量寄存器 → 可离线验证的 attestation。root 无法加载未签名的 BPF，无法篡改记录。

agent-sandbox 这些都不做，后果写在代码旁边：**root 可以卸载我们的程序、改我们的策略**。它防的是 *agent 越权*——提示词注入之后 curl 内网、读 `~/.ssh`——这是每天都在发生的事；它不防 root 被拿下，那是另一个量级的成本。shirudo 的 AGENTS.md 里有一句话，我抄进了自己的代码注释：*策略读起来的意思和作者写的不一样，那这个沙箱执行的就是错误的规则。*

## 内核教我的七课

### 1. fentry 挂上了，不代表它跑

我的第一个计数器挂在 `fentry/do_execve`。加载成功。计数为零。查 kallsyms 才明白：`do_execve` 没了——kernel 7.0 把它内联了，`bprm_execve` 只剩一个死副本，ftrace 能挂上去，但永远不会有人调它。基线计数器改用 tracepoint `sched/sched_process_exec`——任何内核上它都活着；fentry 留给 M1 的 LSM hook，那里才需要精确函数，而且内核是钉死的。在滚动的前沿内核上，"挂载成功"和"会触发"是两个主张，kallsyms 和 BTF 不总是互相作证。

### 2. verifier 的预算：1000001 条指令是真限额

第一版 exec 策略逐规则逐字节比对（64 规则 × 64 字节），verifier 拒载：`Processed 1000001 insn`。修法是把匹配交给内核：`BPF_MAP_TYPE_LPM_TRIE` 的查找在内核里是 O(前缀深度)，一次 map lookup 替掉整个外层循环。verifier 为每条可能的路径付费——**选数据结构，就是在给 verifier 编预算**。

### 3. LPM 的 bit 前缀说不了"相等"——一个安全漏洞的诞生与修复

只放行 `/bin/ls` 的策略把 `/bin/lsx` 也放行了。LPM 按 bit 前缀匹配，而最长匹配会遮住本该生效的更短规则。修复是两张表：exact 规则进 hash（全等，O(1)），前缀规则进 trie，键里带上尾斜杠。让一种结构兼职两种语义，漏出来的洞一定在放行方向。有意思的是，我的用户态 matcher 的 fuzzer 早抓过同一个过度匹配的形状（`Compile("/*")` 返回了匹配一切的根规则）；这个 bug 在内核表里又长了一遍。

### 4. `bpf_probe_read_kernel_str` 只保证 NUL，不保证清零

最玄的一轮：LPM 测试全过，exact hash 全 miss，把 map dump 出来看字节又是对的。缓冲区声明是 `char path[64];`——没初始化。helper 只写入字符串和 NUL，剩下 56 字节是栈上的垃圾，而 exact 键要比较全部 64 字节。`char path[MAX_PREFIX] = {};` 一行修掉。在 file 程序里，同一个 bug 是 deny 方向的安全漏洞——该拒的放行了。helper 的保证条款要逐字读；两个查找一好一坏的时候，先看它们语义的分界线——这里是 prefixlen 只数前缀的位。

### 5. verifier 知道 sockaddr 是 16 字节，不知道你要读 28

逐字节读 `sin6_addr` 被拒：`access beyond struct sockaddr at off 17`。hook 的 ctx 指针按通用 `struct sockaddr` 定界。读字段走 `BPF_CORE_READ_INTO`——尺寸来自字段本身。

### 6. kernel 7.0 的新规：maybe-null 指针不许做算术

`BPF_CORE_READ(sock, sk->sk_protocol)` 被拒：trusted-or-null 指针上的指针运算，先判空。拆两步：读指针、判空、再读字段。旧内核宽容的写法，新内核精确地拒绝——报错信息本身就在教你怎么写。

### 7. 地址族不是协议号

net 的允许表怎么查都不中。把 net 程序禁掉做二分、换绝对路径、写直连探针，最后发现 bug 是我的：我把 `family == AF_INET ? 1 : 2` 当成了 tcp/udp 的编码——AF_INET 恰好是 2，于是所有 v4 连接都在查 UDP 表项。协议号在 `sock->sk->sk_protocol`，和地址族是两个维度。**恰好能编译通过的语义错误最难抓**；测试矩阵要按语义维度（协议 × 地址族）设计，而不是按代码路径。

## 做出来并验证过的

- **作用域**：cgroup v2 + shim——进程自己把自己写进 cgroup 再 exec。没有窗口，没有 PID 竞态。
- **exec**（`lsm/bprm_check_security`）：exact hash + LPM 双表，六项语义矩阵。
- **file**（`lsm/file_open`）：deny_read / deny_write，方向不对称性由测试锁定——读规则对写什么也不说。
- **net**（`lsm/socket_connect`）：CIDR 先拒（v4 以 mapped 形式进 trie，字节相同的 v6 地址不会误配），allow 表在后。
- **默认值的不对称**：exec 和 net 是 allow-list（没点名的拒绝——agent 做了策略没提的事，正是全部威胁所在）；file 是 deny-list（没人写得出一遍"允许读的每个文件"）。每个判定都带着它的规则：`exec.allow[1]`、`net.deny_cidr[0]`、`default deny`。
- **签名，诚实地划定范围**：Ed25519 分离签名，先对钉死的公钥验证，再让任何一条规则进内核；没有签名的策略直接拒绝。包注释里写了它诚实的一面：它拦的是传输中被改、或被误改的策略，对 root 什么也说不了。shirudo 用内核补丁、密封 keyring 和 TPM 关闭那条边界——那是另一个产品，这个不是。
- **事件流**：每个 exec 一条 ringbuf 记录，NDJSON 排空，带 drop 计数——不完整的流会自己说出来。第一版 `Read` 在空 ring 上永远阻塞——ringbuf 的 reader 是阻塞的，而没有人去解开它；修法是一个 timer，ring 安静下来就关掉 reader。
- **一个编译器，两张表，一套 parity**：引擎和内核表由同一批编译出的规则生成，parity 测试把三方锁在一起（引擎判定 ↔ 内核表镜像 ↔ 期望），14 个用例在真内核上全绿。写它们的时候，两处失败都是测试作者的不是——引擎和内核互相作证、和设计一致，反对的是我的用例表。这正是 parity 套件在工作。

## 另外七课：在一个 30 万行的 C 仓库里当贡献者

内核不是唯一的老师。我在 shirudo 里当了一周贡献者，那里的转折来得比 verifier 的拒绝还快。

**第一个 PR 被收编了。** 我修了 xtop 的一个汇总 bug（by-image 的树位置把不同树的序列号混算），47 项 CI 绿，然后 John Fastabend——一位维护者——关掉了我的 PR，留言"pushed some updates here"：他在自己的 PR 里接着我的改动继续，我的类型和注释原样保留，加了一个排序上的细化，随后合并进 main。不是拒绝，是收编——只是经过了维护者的手。

**第二个 PR 输了一场两分钟的竞速。** 我根因定位了另一个问题（`upatch map --json` 在没有 decoder 的 map 上失败），写了修复，开了 PR——然后才发现有人比我早**两分钟**贴出了同样的根因，社区据此收敛到了另一条路（报告者自己加 decoder，更清晰的报错由另一个 commit 单独合入），维护者关闭了 issue。我的 PR 变成了一次抢先实现，而那个设计维护者明确留给了自己。我留了一条评论，承认收敛、接受关闭。输了竞速的时候，那条得体的评论比代码更能说明你是谁。

**第三次，纪律救了我。** 一个跨层的 schema 问题（xtop 的 drill-down 混进同一镜像另一个 build 的 findings）——我写了一条设计评论：两条实现路径、搜索的语义、请维护者定方向。然后我等了。第二天，一个实现 PR 出现了，走的是我排在第二位的那条路径，语义和我写的一致。如果我直接按自己的首选方案动手，那就是又一次正面相撞。三个转折，一条规则：**在高速仓库里，先评论设计，等方向，再动手。** 它赢不了竞速，但能让你不输第二次。

## 还差的

- OTLP 导出（NDJSON 够 demo 用了；OTLP 是给运维的接入）
- match 和 event 的内核侧输入的 fuzz target
- 把 parity 用例发布成版本间的兼容契约

*以上每一件事都是实现过、测试过的；这篇文里没有一个主张是没有先通过一次测试的。仓库在 [github.com/kittimzhe/agent-sandbox](https://github.com/kittimzhe/agent-sandbox)——`sh scripts/demo.sh`，一分钟看完整个故事。*
