#!/bin/sh
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd); TTY=/dev/tty
[ "$(id -u)" = 0 ] || { echo '错误：请使用 sudo ./install.sh'; exit 1; }
if [ ! -r "$TTY" ] || [ ! -w "$TTY" ]; then echo '错误：需要交互式终端。'; exit 1; fi
if [ -t 1 ]; then B='\033[1;34m';Y='\033[1;33m';R='\033[1;31m';G='\033[1;32m';N='\033[0m';else B=;Y=;R=;G=;N=;fi
say(){ printf "%b%s%b\n" "$1" "$2" "$N"; }; ask(){ printf "%b%s%b" "$1" "$2" "$N" >"$TTY"; IFS= read -r REPLY <"$TTY" || REPLY=; }
MODE=basic;CONSENT=NO
say "$B" 'VPS Monitor 安装器'
say "$B" '常驻预算：1 个 Python 进程 / 1 个线程 / 日常采样不启动子进程'
say "$B" '硬限制：96MiB 内存 / 20% 单核 CPU / 32MiB Swap'
if [ -f /etc/vps-monitor.env ]; then
 say "$B" '检测到旧版本：保留配置、授权和历史数据，仅更新程序与服务。'
else
 printf '\n';say "$B" '[1] BASIC：整机 CPU、内存、Swap、磁盘 I/O/空间（低危，默认）'
 say "$Y" '[2] FULL：增加其他进程 PID、命令、路径、fd、端口和日志取证（中/高危）'
 ask "$B" '选择 [1/2，默认 1]：';choice=${REPLY:-1}
 case "$choice" in
  1) ;;
  2)
   printf '\n';say "$R" '高危：以 root 读取其他进程，并把路径、IP、日志发往 Telegram。'
   say "$Y" '中危：报告可能包含业务名称、命令参数和网络拓扑。'
   say "$B" '保护：不读环境变量/文件内容/SSH 密钥；不 kill、不删文件；有硬资源限制。'
   ask "$R" '同意请输入大写 YES：'
   [ "$REPLY" = YES ] || { say "$R" '未收到大写 YES，安装已取消。'; exit 2; }
   MODE=full;CONSENT=YES; say "$R" 'FULL 高危权限已明确授权。' ;;
  *) say "$R" '只能输入 1 或 2，安装已取消。';exit 2 ;;
 esac
fi
say "$B" '安装内容：1 个 systemd 服务；不创建 timer、Web 服务或后台任务。'

if command -v apt-get >/dev/null; then
 command -v python3 >/dev/null || { apt-get update; apt-get install -y --no-install-recommends python3 ca-certificates; }
 if [ "$MODE" = full ]; then apt-get install -y --no-install-recommends procps iproute2 util-linux; fi
elif command -v dnf >/dev/null; then dnf install -y python3 ca-certificates; [ "$MODE" = basic ] || dnf install -y procps-ng iproute util-linux
elif command -v yum >/dev/null; then yum install -y python3 ca-certificates; [ "$MODE" = basic ] || yum install -y procps-ng iproute util-linux
elif command -v apk >/dev/null; then apk add --no-cache python3 ca-certificates; [ "$MODE" = basic ] || apk add --no-cache procps iproute2 util-linux
else say "$R" '不支持的包管理器。';exit 1
fi
install -d -m 0755 /opt/vps-monitor /var/lib/vps-monitor/reports /var/lib/vps-monitor/metrics
install -m 0555 "$ROOT/vps_monitor.py" /opt/vps-monitor/vps_monitor.py
install -m 0444 "$ROOT/SECURITY.md" /opt/vps-monitor/SECURITY.md
install -m 0644 "$ROOT/vps-monitor.service" /etc/systemd/system/vps-monitor.service
install -m 0755 "$ROOT/vps-monitorctl" /usr/local/bin/vps-monitorctl
if [ ! -f /etc/vps-monitor.env ]; then
 install -m 0600 "$ROOT/vps-monitor.env.example" /etc/vps-monitor.env
 sed -i "s/^FORENSICS_MODE=.*/FORENSICS_MODE=$MODE/;s/^FORENSICS_CONSENT=.*/FORENSICS_CONSENT=$CONSENT/" /etc/vps-monitor.env
fi
chown -R root:root /opt/vps-monitor /var/lib/vps-monitor /etc/vps-monitor.env;chmod 0600 /etc/vps-monitor.env
systemctl daemon-reload;systemctl enable vps-monitor.service
set -a
# shellcheck disable=SC1091
. /etc/vps-monitor.env
set +a
/usr/bin/python3 /opt/vps-monitor/vps_monitor.py check
systemctl restart vps-monitor.service
printf '\n';say "$G" '安装成功'
say "$B" "模式：$MODE｜服务：1 个 vps-monitor.service"
say "$B" '下一步：sudo vps-monitorctl config；然后 sudo vps-monitorctl test'
