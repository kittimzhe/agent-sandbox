# agent-sandbox 设计文档（工作名）

> 状态：设计稿 v0.3（2026-11-26 更新）
> 目标：求职作品 + 真实可用的 AI Agent 运行时沙箱
> 参考系：shirudo（内核级信任链）、Tetragon（通用 eBPF 安全平台）、KubeArmor（容器策略）
> 进度：M0 ✅ + M1 ✅——run 一条命令挂 4 个 BPF 程序（exec 计数 tracepoint +
> exec/file/net 三个 LSM），语义矩阵全绿，同源编译器（引擎与内核表）。
> 待做：签名简化层（M2 简化版）、OTLP 导出、ringbuf 事件流、parity 测试。

## 1. 一句话定位

给执行不可信任务的 LLM Agent 进程套上 eBPF 沙箱：**进程/文件/网络三维度的策略拦截 + 全量审计事件流**，一个 Go 二进制 + 一组 C BPF 程序，单机部署，不需要内核补丁、不需要 TPM。

## 2. 为什么做、和谁比

| 项目 | 它是什么 | 我们的差异 |
|---|---|---|
| shirudo | 内核级签名 BPF 信任链，TPM 证明 | 它解决"谁能加载 BPF"；我们解决"agent 能做什么"。无 TPM/内核补丁，明说边界 |
| Tetragon | 通用 K8s 运行时安全平台 | 通用平台重、面向集群；我们面向单机 agent 场景，带默认策略包 |
| KubeArmor | 容器策略引擎（LSM） | 面向容器/主机；我们面向 agent 进程树，策略模型针对 agent 任务语义 |

**场景**：跑 agent 的团队需要限制 agent 子进程的能力（不许读 `~/.ssh`、不许访问白名单外网络、只许 exec 白名单命令），并保留完整审计流。目前没有轻量、单机、面向 agent 的现成方案。

**简历叙事**（诚实版）：研究了 shirudo 的设计并为其贡献代码（PR #325 等），理解了内核级信任链的完整形态；然后实现了轻量版，明确放弃 TPM/内核补丁/签名内核强制，并写清楚为什么——这个 tradeoff 分析本身就是面试深水区。

## 3. 架构

```
cmd/
  agent-sandbox         # 单二进制入口（子命令风格，学 shirudo/git）
    run --policy p.yaml -- ./agent.sh   # 前台运行：加载 BPF + 跟踪进程树 + 输出事件
    observe --policy p.yaml             # 只观测不拦截
bpf/
  exec.bpf.c            # fentry/fexit + LSM: bprm_creds_for_exec / task_alloc
  file.bpf.c            # LSM: file_open（写打开、读敏感路径）
  net.bpf.c             # LSM: socket_connect（v4/v6，cgroup 作用域）
  cgroup_scope.bpf.c    # cgroup 识别：只对加入沙箱 cgroup 的进程生效
internal/
  loader/               # cilium/ebpf 加载 + CO-RE + pin 管理
  policy/               # 策略解析(YAML) → BPF map 下发；校验与错误报告
  event/                # ringbuf 消费 → JSON 行输出 / OTLP(P3)
  scope/                # cgroup v2 管理：进程树加入/移出
policy/
  defaults/             # 默认策略包：agent-web、agent-dev、agent-ci
```

**技术栈**：Go 1.23+（cilium/ebpf v0.17+，Tetragon 同款组合）+ C BPF（CO-RE，vmlinux.h 从 BTF 生成）。策略 YAML 手写 parser 不引库——学 shirudo 的依赖纪律。

### 关键设计决策（面试考点）

1. **作用域用 cgroup v2**，不用 PID 跟踪：进程树 fork/exec 自动继承，无竞态。BPF 程序查当前 cgroup 是否在沙箱 map 里，O(1)。
2. **策略下发 = BPF map 更新**：LSM 程序读 map 决策，策略变更不重载程序。deny 优先、精确路径优先。
3. **事件流用 ringbuf**：保留/丢弃语义可配；观测模式全量，拦截模式附决策结果。
4. **拦截 vs 观测是同一个程序的两个模式**：`observe` 只发事件，`run` 额外返回 EPERM。避免两套代码路径。
5. **明确不做的**（README 必写）：无 TPM 测量、无签名内核强制（P3 只做用户态签名校验，防误加载不防 root）、无守护进程常驻（run 前台进程即管理面，退出即卸载—— tradeoff：牺牲"管理面独立于被管对象"，换取零部署面；shirudo 用内核持有状态解决这个矛盾，我们接受它并在文档里写明）。

## 4. 里程碑

| 阶段 | 周期 | 交付物 | 验收 |
|---|---|---|---|
| M0 骨架 | 1 周 | repo + CI + `observe` 跑通 exec 事件流 | 演示录屏：跑 `ls` 看到事件 |
| M1 拦截 | 2 周 | policy 引擎 + LSM 拦截（file/exec/net） | 策略拒绝读 ~/.ssh、拒绝白名单外 connect，EPERM + 事件 |
| M2 作用域 | 2 周 | cgroup 作用域 + 默认策略包 + demo agent | 给一个真实 agent（shell 工具型）套沙箱演示 |
| M3 收尾 | 2 周 | 用户态签名校验 + OTLP + README/架构图/博客 | 博客：CO-RE、verifier 拒绝案例、与 shirudo 对比 |

## 5. 环境依赖（当前缺）

- **Linux + eBPF 运行环境**：本机是 macOS（M2），必须 Lima VM（本地开发够用）或云 Linux 主机（跑真实内核 LSM hook；macOS 虚拟机的内核同样能跑 LSM，Lima 可满足 M0-M3）
- Go、clang/LLVM（BPF 目标）、`bpftool`（生成 vmlinux.h）
- ⚠️ 注意：Lima 安装约 10-15GB 磁盘，当前剩 52GB，可行

## 6. 风险与开放问题

- **命名**：工作名 agent-sandbox，正式名待定（避免与现有项目撞名，发布前查）
- **LSM hook 可用性**依赖内核配置（CONFIG_BPF_LSM、lsm= 启动参数含 bpf）——Lima 镜像需要定制，M0 里解决
- **BPF verifier 拒绝**是主要技术风险：M0 就用真实内核调试，不等到 M1
- 与 shirudo 的 PR 线时间冲突：PR 线优先（外部依赖有时效），mini 项目按里程碑推进
