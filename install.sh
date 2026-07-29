#!/bin/sh
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd);TTY=/dev/tty;RESTART_CMD='bash <(curl -fsSL https://raw.githubusercontent.com/onshine/vps-monitor/main/quick-install.sh)'
[ "$(id -u)" = 0 ]||{ echo '错误：请使用 sudo ./install.sh';exit 1;}
if [ ! -r "$TTY" ]||[ ! -w "$TTY" ];then echo '错误：需要交互式终端。';exit 1;fi
if [ -t 1 ];then B='\033[1;34m';Y='\033[1;33m';R='\033[1;31m';G='\033[1;32m';N='\033[0m';else B=;Y=;R=;G=;N=;fi
say(){ printf '%b%s%b\n' "$1" "$2" "$N";};ask(){ printf '%b%s%b' "$1" "$2" "$N">"$TTY";IFS= read -r REPLY<"$TTY"||REPLY=;}
farewell(){ printf '\n';say "$G" '山水有相逢，道友，再见👋。';say "$B" '若要继续使用脚本，输入以下命令：';printf '%s\n' "$RESTART_CMD";exit "${1:-0}";}
security(){ printf '\n';say "$B" '【低危】读取整机 CPU、内存、Swap、磁盘统计；写专用数据目录。';say "$Y" '【中危】FULL 会读取进程命令、路径、fd、端口，可能暴露业务信息。';say "$R" '【高危】FULL 以 root 取证并向 Telegram 发送报告；自动处置须另行授权。';say "$B" '保护：不读环境变量/文件内容/SSH 密钥；默认不操作业务进程。';}
MODE=basic;CONSENT=NO
say "$B" 'VPS Monitor 安装器'
say "$B" '常驻：1 进程 / 1 线程 / 日常采样 0 子进程'
say "$B" '硬限制：96MiB 内存 / 20% 单核 CPU / 32MiB Swap / 8 tasks'
if [ -f /etc/vps-monitor.env ];then
 while :;do
  printf '\n';say "$B" '检测到已有安装，配置和历史数据不会覆盖。'
  say "$B" '1. 直接升级（不创建配置备份）'
  say "$B" '2. 备份配置后升级'
  say "$Y" '3. 查看权限与安全说明'
  say "$B" '0. 退出脚本'
  ask "$B" '请输入选项 [0-3]：'
  case "$REPLY" in
   1) say "$B" '已选择直接升级，不创建备份。';break;;
   2) BACKUP="/etc/vps-monitor.env.backup.$(date +%Y%m%d-%H%M%S)";cp -p /etc/vps-monitor.env "$BACKUP";say "$G" "已授权备份：$BACKUP";break;;
   3) security;;0) farewell 0;;*) say "$R" '无效选项，请输入 0、1、2 或 3。';;
  esac
 done
else
 while :;do
  printf '\n';say "$B" '1. BASIC 安装：整机资源监控（低危，默认推荐）'
  say "$Y" '2. FULL 安装：增加进程、路径、端口和日志取证（中/高危）'
  say "$Y" '3. 查看权限与安全说明'
  say "$B" '0. 退出脚本'
  ask "$B" '请输入选项 [0-3]：'
  case "$REPLY" in
   1) MODE=basic;CONSENT=NO;break;;
   2)
    security;ask "$R" '同意 FULL 高危权限请输入大写 YES；输入 0 退出：'
    [ "$REPLY" = 0 ]&&farewell 0
    if [ "$REPLY" = YES ];then MODE=full;CONSENT=YES;say "$R" 'FULL 权限已明确授权。';break;else say "$R" '未收到大写 YES，未授权 FULL。';fi;;
   3) security;;0) farewell 0;;*) say "$R" '无效选项，请输入 0、1、2 或 3。';;
  esac
 done
fi
say "$B" '将安装：1 个 systemd 服务；不创建 timer、Web 服务或额外后台任务。'
if command -v apt-get >/dev/null;then
 command -v python3 >/dev/null||{ apt-get update;apt-get install -y --no-install-recommends python3 ca-certificates;}
 [ "$MODE" = basic ]||apt-get install -y --no-install-recommends procps iproute2 util-linux
elif command -v dnf >/dev/null;then dnf install -y python3 ca-certificates;[ "$MODE" = basic ]||dnf install -y procps-ng iproute util-linux
elif command -v yum >/dev/null;then yum install -y python3 ca-certificates;[ "$MODE" = basic ]||yum install -y procps-ng iproute util-linux
elif command -v apk >/dev/null;then apk add --no-cache python3 ca-certificates;[ "$MODE" = basic ]||apk add --no-cache procps iproute2 util-linux
else say "$R" '不支持的包管理器。';farewell 1;fi
install -d -m 0755 /opt/vps-monitor /var/lib/vps-monitor/reports /var/lib/vps-monitor/metrics
install -m 0555 "$ROOT/vps_monitor.py" /opt/vps-monitor/vps_monitor.py;install -m 0444 "$ROOT/SECURITY.md" /opt/vps-monitor/SECURITY.md
install -m 0644 "$ROOT/vps-monitor.service" /etc/systemd/system/vps-monitor.service;install -m 0755 "$ROOT/vps-monitorctl" /usr/local/bin/vps-monitorctl
if [ ! -f /etc/vps-monitor.env ];then install -m 0600 "$ROOT/vps-monitor.env.example" /etc/vps-monitor.env;sed -i "s/^FORENSICS_MODE=.*/FORENSICS_MODE=$MODE/;s/^FORENSICS_CONSENT=.*/FORENSICS_CONSENT=$CONSENT/" /etc/vps-monitor.env;fi
chown -R root:root /opt/vps-monitor /var/lib/vps-monitor /etc/vps-monitor.env;chmod 0600 /etc/vps-monitor.env
systemctl daemon-reload;systemctl enable vps-monitor.service
set -a
# shellcheck disable=SC1091
. /etc/vps-monitor.env
set +a
/usr/bin/python3 /opt/vps-monitor/vps_monitor.py check;systemctl restart vps-monitor.service
printf '\n';say "$G" '安装/升级成功';say "$B" "模式：$MODE｜服务：vps-monitor.service";say "$B" '下一步：sudo vps-monitorctl config';say "$B" '通知测试：sudo vps-monitorctl test'
