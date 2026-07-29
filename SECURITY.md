# 安全、权限和威胁模型

VPS Sentinel 的目标是定位宿主机异常进程，而不是获得“不受限制的访问”。默认推荐原生 systemd 部署；Docker 仅为安装便利，完整宿主机取证需要较强容器权限。

## 权限分级

### 低危：基础监控模式

通常普通用户即可读取：

| 资源 | 用途 | 风险 |
|---|---|---|
| `/proc/stat`、`/proc/meminfo`、`/proc/diskstats`、PSI | CPU、内存、Swap、块设备 I/O、压力 | 只含整机统计，低危 |
| `/sys/class/block` | 区分整盘与分区 | 设备拓扑信息，低危 |
| `df`、`lsblk`、`findmnt` | 空间、inode、挂载 | 暴露卷名和挂载路径，低到中危 |
| 写入 `/var/lib/vps-monitor` 或 Docker `/data` | 保存指标及报告 | 只应写专用目录 |
| HTTPS 访问 `api.telegram.org:443` | 发送通知 | 出站网络；报告会离开服务器 |

仅看整机指标不需要 root、Docker socket、写宿主机系统目录或修改内核。

### 中危：进程归因

| 权限/数据 | 用途 | 风险 |
|---|---|---|
| `/proc/<pid>/stat`、`status`、`io`、`cmdline`、`cgroup` | PID、CPU、RSS、真实读写增量、命令、容器归属 | 暴露用户名、参数、业务名称；命令参数可能误含密码/Token |
| `ss -tunap` | PID 对应端口和远端连接 | 暴露网络拓扑、客户/后端地址 |
| 读取 Docker 容器列表和 stats | 容器归因 | 暴露容器名、镜像和资源情况 |

Linux 的 `hidepid`、不同 UID 和容器边界可能阻止普通用户读取这些数据。

### 高危：完整取证模式（必须明确输入 `YES`）

| 权限 | 为什么需要 | 主要风险 |
|---|---|---|
| 以 `root` 运行 | 读取其他 UID 进程的 `/proc/<pid>`、fd、连接、部分日志 | 若程序被篡改，理论上可读取/修改整机；这是最高风险 |
| 读取 `/proc/<pid>/fd`、`exe`、`cwd` | 定位程序和正在访问的文件 | 暴露业务文件路径、数据库路径、已删除文件；fd 访问不当可能触达敏感文件 |
| 读取 `journalctl`、`dmesg` | 判断 OOM、I/O 错误、内核故障 | 日志可能包含 IP、用户名、请求路径或应用误打出的秘密 |
| Docker `/var/run/docker.sock`（可选） | 获取容器归属和状态 | **等价宿主机 root**；被利用后可启动特权容器、挂载宿主机根目录 |
| Docker `pid: host` | 容器内看到宿主机 PID | 打破 PID 隔离，暴露所有进程元数据 |
| Docker `network_mode: host` | 看到宿主机端口/连接 | 打破网络隔离，可访问仅监听 localhost 的服务 |
| Docker `privileged: true`（完整模式） | 绕过 proc/ptrace/capability 限制完成 fd 与进程取证 | 获得几乎全部 capabilities 和设备访问，接近宿主机 root，风险最高 |
| 把取证报告发送到 Telegram | 远程及时告警 | PID、命令、路径、IP、日志会传输给 Telegram；Bot Token/群权限失守会泄露报告 |

## 明确不做的事情

- 不读取 `/proc/<pid>/environ`，避免采集 API Key、数据库密码等环境变量。
- 不读取文件内容，只记录 fd 指向的路径。
- 不扫描 `/root`、用户家目录、SSH 密钥、浏览器数据或数据库内容。
- 不执行自动 kill、暂停、限速、重启、封禁 IP、删除文件等破坏性动作。
- 当前版本默认 `AUTO_ACTION=none` 与 `AUTO_ACTION_CONSENT=NO`。自动处置必须先授权 FULL、配置 Telegram，再通过 `vps-monitorctl authorize-actions` 二次红色授权，并逐项选择 CPU、内存、磁盘读、磁盘写；未选择类别严格禁止。默认只 SIGTERM，SIGKILL 需第三层输入 `KILL` 授权。
- 不开放监听端口、不提供 Web 管理后台。
- 不将 Telegram Token 写入报告或日志。
- 不自动上传历史指标；只有异常报告和测试消息发送到配置的 Telegram。

命令行参数本身仍可能包含秘密，因此报告是敏感文件。应把 Bot 放在私有聊天/私有群，限制群成员，并定期轮换 Token。

## 自身不成为故障源的机制

### 外部强制约束（程序无法自行绕过配置）

systemd 默认：

- `MemoryHigh=64M`、`MemoryMax=96M`、`MemorySwapMax=32M`
- `CPUQuota=20%`：最多使用单个 CPU 核心的 20%
- `TasksMax=8`、`LimitNOFILE=1024`
- `Nice=10`、`IOSchedulingClass=idle`：让业务进程优先
- 只允许写 `/var/lib/vps-monitor`
- `NoNewPrivileges=yes`、只读系统目录、禁止改内核参数/模块/cgroup
- `Restart=on-failure` 且有重启等待，避免紧密崩溃循环

Docker 默认：96 MiB 内存、0.20 CPU、8 tasks，并设置 `no-new-privileges`。但 **privileged 容器会削弱部分安全选项**，所以安全性仍低于原生 systemd。

### 程序内部自审查

- 常驻阶段只读取小型 `/proc` 计数器；重型命令只在确认异常后执行。
- 每次读文件都有大小上限；子命令有超时；报告数量、保留天数、fd 数量均有限制。
- 排除自身 PID，避免把监控器误判为肇事程序。
- 不在内存中保存长期历史；历史指标逐行写 JSONL。
- 检查自身 RSS、采样耗时和报告大小；超过安全预算时记录审计事件并退出，由 systemd/Docker 按硬限制处理。
- Telegram 失败不会无限重试或堆积内存；报告先落盘，按冷却周期告警。

## 完整性与供应链

发布 GitHub Release 时应同时提供 SHA-256。建议用户下载固定版本而不是直接 `curl | sh`。安装前可执行：

```bash
sha256sum -c SHA256SUMS
python3 vps_monitor.py check
```

安装程序不会要求输入 Telegram Token；用户应在本机编辑权限为 `0600` 的配置文件。更新时保留配置和数据，并先备份旧程序。

## 授权撤回

```bash
sudo systemctl disable --now vps-monitor
sudo vps-monitorctl uninstall
```

卸载默认保留 `/etc/vps-monitor.env` 和 `/var/lib/vps-monitor`，防止误删证据；用户确认后可自行删除。Docker 用户执行 `docker compose down`，并按需删除 `data/`。
