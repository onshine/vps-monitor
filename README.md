# VPS Monitor / VPS Sentinel

面向小型 Linux VPS 的低开销磁盘 I/O、CPU、内存、Swap、空间和 inode 监控器。发生异常时即时归因到 PID，并将可审计的 TXT 取证报告发送到 Telegram。

- **零 Python 第三方依赖**：Python 3 标准库，直接读 Linux `/proc`、`/sys`
- **低开销**：常驻只采样计数器，重型取证仅在确认异常后运行
- **防止监控拖垮 2GB VPS**：systemd/Docker 96MiB 内存、0.20 CPU、32 PID 硬限制；内部 RSS/报告/超时自审查
- **权限透明**：默认 BASIC 低权限；FULL 必须阅读风险并手输大写 `YES`
- **Telegram**：摘要 + 完整 TXT 附件；冷却、恢复通知、论坛 Topic
- **证据可留存**：报告和 JSONL 指标保存在本地，有天数及文件数上限

## 解决的痛点

1. `top` 只能看到 CPU，却不知道谁在疯狂读盘。
2. 故障发生后进程已经退出，缺少当时 PID、命令、读写速率、路径、端口和日志。
3. 磁盘 `%util`、吞吐、IOPS 与“磁盘空间占满”经常被混为一谈。
4. 告警脚本自己无资源上限，可能雪上加霜。
5. 小白难以配置 systemd、Telegram、日志轮转和更新。

## 技术栈

- Python 3 标准库：采样、阈值、报告、Telegram HTTPS
- Linux `/proc`、`/sys`、PSI：CPU、内存、进程 I/O、块设备忙碌时间
- 可选系统工具：`procps`、`iproute2`、`sysstat`、`util-linux`
- systemd：推荐生产部署、资源 cgroup 限制、安全沙箱
- Docker / Compose：BASIC 便捷部署；FULL 需要显式高权限覆盖文件
- GitHub Actions：语法、基础测试、镜像构建

## 权限模式（安装前必读）

### BASIC（默认，低危）

监控整机 CPU、内存、Swap、磁盘 I/O、空间、inode 和 PSI。不读取其他进程的路径、fd、端口、日志；不需要完整 root 取证权限。

### FULL（高危，显式授权）

读取其他进程 PID、命令、`exe/cwd`、打开文件路径、端口，以及 journal/dmesg/Docker 状态。安装器逐项展示风险，只有手输大写 `YES` 才启用。程序不读取 `/proc/PID/environ` 或文件内容，不会自动 kill、删除或封禁。

**完整权限、数据泄露面、自我审计及撤权方式见 [SECURITY.md](SECURITY.md)。**

## 推荐：原生一键安装

安装和升级的下载目录始终固定为 `vps-monitor`，不会把版本号写进目录。程序安装到 `/opt/vps-monitor`，配置保存在 `/etc/vps-monitor.env`，数据保存在 `/var/lib/vps-monitor`；以后升级不会改变路径，也不会覆盖配置和历史数据。

### 方法一：使用 curl（完整复制到 VPS）

```bash
cd "$HOME" && \
rm -rf vps-monitor vps-monitor.zip SHA256SUMS && \
curl -fL --retry 3 -o vps-monitor.zip \
  https://github.com/onshine/vps-monitor/releases/latest/download/vps-monitor.zip && \
curl -fL --retry 3 -o SHA256SUMS \
  https://github.com/onshine/vps-monitor/releases/latest/download/SHA256SUMS && \
sha256sum -c SHA256SUMS && \
mkdir -p vps-monitor && \
unzip -q vps-monitor.zip -d vps-monitor && \
cd vps-monitor && \
sudo ./install.sh
```

若 VPS 没有 `curl` 或 `unzip`：

```bash
sudo apt-get update && sudo apt-get install -y curl unzip
```

### 方法二：使用 wget（完整复制到 VPS）

```bash
cd "$HOME" && \
rm -rf vps-monitor vps-monitor.zip SHA256SUMS && \
wget -O vps-monitor.zip \
  https://github.com/onshine/vps-monitor/releases/latest/download/vps-monitor.zip && \
wget -O SHA256SUMS \
  https://github.com/onshine/vps-monitor/releases/latest/download/SHA256SUMS && \
sha256sum -c SHA256SUMS && \
mkdir -p vps-monitor && \
unzip -q vps-monitor.zip -d vps-monitor && \
cd vps-monitor && \
sudo ./install.sh
```

若 VPS 没有 `wget` 或 `unzip`：

```bash
sudo apt-get update && sudo apt-get install -y wget unzip
```

安装器支持 Debian/Ubuntu、Alpine、RHEL/Fedora 系列。首次安装会询问 BASIC/FULL；FULL 必须输入大写 `YES`。安装完成后配置 Telegram：

```bash
sudo vps-monitorctl config
sudo vps-monitorctl test
sudo vps-monitorctl status
```

### 一条命令下载并安装

如果你接受直接执行仓库安装器，可使用：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/onshine/vps-monitor/main/quick-install.sh)
```

该引导脚本会把 Release 下载到用户家目录下固定的 `vps-monitor` 工作目录、验证 SHA-256，再调用交互式 `install.sh`。正式程序始终安装到 `/opt/vps-monitor`。生产服务器更推荐使用上面的完整 curl/wget 流程，以便先检查下载内容。

### 升级

升级时重新执行上面的 curl 或 wget 完整流程即可。下载工作目录始终是 `$HOME/vps-monitor`，正式程序目录始终是 `/opt/vps-monitor`；安装器检测到 `/etc/vps-monitor.env` 后自动进入升级模式：

- 保留 `/etc/vps-monitor.env` 和既有 BASIC/FULL 授权；
- 保留 `/var/lib/vps-monitor` 中的报告及指标；
- 替换程序、管理命令和 systemd 服务；
- 检查配置后重启服务。

版本号只用于 GitHub Tag/Release 和程序内部版本，不作为 VPS 的长期目录名。

## Docker（默认 BASIC）

```bash
cp vps-monitor.env.example .env
# 编辑 .env，至少填写 TG_BOT_TOKEN 与 TG_CHAT_ID
docker compose up -d --build
docker compose logs -f
```

默认容器：只读根文件系统、drop 全部 capabilities、no-new-privileges、96MiB/0.20 CPU/32 PID。由于容器看到的是自身 `/proc`，BASIC 适合整机 cgroup/挂载可见范围监控，宿主机完整 PID 归因不如原生方式。

Docker FULL 高危模式：

```bash
# 先阅读 SECURITY.md，再在 .env 设置：
# FORENSICS_MODE=full
# FORENSICS_CONSENT=YES
docker compose -f compose.yml -f compose.full.yml up -d
```

该模式使用 `privileged`、host PID/network 和 Docker socket，隔离显著减弱；**推荐改用原生 systemd**。

## Telegram 设置

1. 在 `@BotFather` 创建 Bot。
2. 私聊 Bot 发消息，或将其加入私有群后发消息。
3. 访问 `https://api.telegram.org/bot<TOKEN>/getUpdates`，读取 `message.chat.id`。
4. 填写本机 `/etc/vps-monitor.env`（权限 `0600`），不要把 Token 提交到 Git。
5. 执行 `sudo vps-monitorctl test`。

## 配置变量

| 变量 | 默认 | 说明 |
|---|---:|---|
| `FORENSICS_MODE` | `basic` | `basic` 或 `full` |
| `FORENSICS_CONSENT` | `NO` | FULL 仅接受明确的 `YES` |
| `MONITOR_INTERVAL` | `5` | 整机采样秒数 |
| `PROCESS_SCAN_INTERVAL` | `5` | FULL 进程 I/O 采样秒数 |
| `CPU_THRESHOLD` | `90` | CPU 百分比 |
| `MEMORY_THRESHOLD` | `90` | 基于 MemAvailable |
| `SWAP_THRESHOLD` | `90` | Swap 使用率 |
| `DISK_IO_THRESHOLD` | `90` | 块设备忙碌度，类似 iostat `%util` |
| `DISK_SPACE_THRESHOLD` | `90` | 文件系统容量 |
| `INODE_THRESHOLD` | `90` | inode 使用率 |
| `DISK_READ_MBPS` / `DISK_WRITE_MBPS` | `0` | 可选绝对吞吐阈值，0 禁用 |
| `ALERT_CONSECUTIVE` | `2` | 连续命中次数 |
| `ALERT_COOLDOWN` | `900` | 重复告警冷却秒数 |
| `REPORT_RETENTION_DAYS` | `14` | 报告保留天数 |
| `REPORT_MAX_FILES` | `100` | 报告数量上限 |
| `METRICS_INTERVAL` | `60` | JSONL 历史间隔，0 禁用 |
| `SELF_RSS_MAX_MB` | `80` | 内部 RSS 退出线；外部硬上限 96MiB |
| `MAX_REPORT_SIZE_MB` | `5` | 单报告最大值 |

更新单个变量并验证、重启：

```bash
sudo vps-monitorctl set CPU_THRESHOLD 85
sudo vps-monitorctl set ALERT_COOLDOWN 1800
```

也可运行 `sudo vps-monitorctl config`。旧配置自动备份为 `/etc/vps-monitor.env.bak`。

## 数据与维护

- 配置：`/etc/vps-monitor.env`（0600）
- 程序：`/opt/vps-monitor/`
- 报告：`/var/lib/vps-monitor/reports/`
- 指标：`/var/lib/vps-monitor/metrics/YYYY-MM-DD.jsonl`
- 服务日志：`journalctl -u vps-monitor`

```bash
sudo vps-monitorctl logs
sudo vps-monitorctl reports
sudo vps-monitorctl check
sudo vps-monitorctl restart
sudo vps-monitorctl uninstall
```

卸载默认保留配置和证据，避免误删；确认后自行删除。

## 常见问答（FAQ）

### 为什么程序、配置和数据不全部放在一个目录？

项目实际只有 3 个正式位置，分别遵循 Linux FHS（Filesystem Hierarchy Standard）的职责划分：

```text
/opt/vps-monitor/       可替换、只读的程序文件
/etc/vps-monitor.env    root 专属的私密配置（0600）
/var/lib/vps-monitor/   报告和指标等可变持久数据
```

安装时出现的 `$HOME/vps-monitor/` 只是固定的下载、解压工作目录，并非运行数据目录；安装完成后可以删除：

```bash
rm -rf "$HOME/vps-monitor" "$HOME/vps-monitor.zip" "$HOME/SHA256SUMS"
```

这样分离不是为了增加复杂度，而是为了安全和可靠升级：

1. **升级不丢配置和证据**：`/opt/vps-monitor` 可以整套替换，Telegram Token、阈值、权限授权和历史报告仍然保留。
2. **保护 Telegram Token**：配置位于 `/etc`，权限为 `root:root 0600`，不会被打进 Release、Docker 镜像或 Git 仓库。
3. **防止程序修改自身**：systemd 使用 `ProtectSystem=strict` 将程序和系统目录设为只读，仅通过 `ReadWritePaths=/var/lib/vps-monitor` 允许写专用数据目录。
4. **避免一次误删全部内容**：即使重装或删除程序目录，配置与故障证据仍在。
5. **便于分别备份和轮转**：程序可从 Release 恢复；配置应加密备份；报告和指标按保留策略自动清理。
6. **符合 Linux 运维惯例**：Nginx、Docker、Prometheus 等服务同样将程序、配置和可变数据分开管理。

如果把所有内容放进 `/opt/vps-monitor`，该目录必须同时容纳只读代码、root 私密 Token 和可写报告。一旦为了写报告而开放整个目录，运行中的程序也可能修改自己的代码或配置；执行 `rm -rf /opt/vps-monitor`、错误升级或 `chmod -R` 时，还可能同时删除或泄露所有内容。因此，单目录看起来简单，但安全边界、升级容错和备份策略都会更差。

用户日常不需要记住这些路径，统一使用管理命令即可：

```bash
sudo vps-monitorctl status
sudo vps-monitorctl config
sudo vps-monitorctl test
sudo vps-monitorctl logs
sudo vps-monitorctl reports
sudo vps-monitorctl restart
sudo vps-monitorctl uninstall
```

### 安装目录为什么不带版本号？

版本号只属于 GitHub Tag、Release 和程序自身。下载工作目录始终是 `$HOME/vps-monitor`，正式程序目录始终是 `/opt/vps-monitor`。升级到任何版本都复用相同路径，并保留 `/etc/vps-monitor.env` 与 `/var/lib/vps-monitor`。

### 可以把目录改到其他位置吗？

数据目录可通过 `MONITOR_DATA_DIR` 修改，但同时必须调整 systemd 的 `ReadWritePaths`，否则安全沙箱会阻止写入。私密配置和程序路径不建议随意更改；如确有统一目录、容器卷或特殊备份需求，应同步设计文件权限、只读边界、升级和卸载策略，而不是简单移动文件。

## 2GB 内存 + 1GB Swap 建议

默认设置通常 RSS 约 15–30MiB（进程数量和故障报告会影响），不是预留或持续占用 96MiB。96MiB 是 cgroup 硬上限；64MiB 开始施压，Swap 最多 32MiB，CPU 最多单核 20%。I/O 调度为 idle、nice=10。程序内部超过 80MiB 会主动退出，且报告、命令输出、fd 和历史都有上限。

## 局限

- Linux 不永久记录“过去哪个 PID 读过哪个文件”；本项目通过周期采样和越线即时抓取提高命中率，极短命进程仍可能消失。
- NVMe/RAID 可并发，`%util=100%` 不总等于绝对饱和，需结合 PSI、吞吐和延迟分析。
- 虚拟化平台可能不暴露真实宿主磁盘统计。
- Telegram 报告包含敏感运维信息，只应发往私聊或严格受控的私有群。

## 开源与安全

MIT License。贡献前阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题请使用 GitHub Security Advisory 私下报告，不要公开贴 Token 或真实报告。
