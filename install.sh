#!/bin/sh
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")"&&pwd);TTY=/dev/tty;OP=${1:-install}
[ "$(id -u)" = 0 ]||{ echo '错误：请使用 sudo。';exit 1;}
if [ -t 1 ];then G='\033[1;32m';Y='\033[1;33m';R='\033[1;31m';N='\033[0m';else G=;Y=;R=;N=;fi
say(){ printf '%b%s%b\n' "$1" "$2" "$N";};ask(){ printf '%b%s%b' "$1" "$2" "$N">"$TTY";IFS= read -r REPLY<"$TTY"||REPLY=;}
MODE=basic;CONSENT=NO
if [ "$OP" = update ]&&[ -f /etc/vps-monitor.env ];then
 say "$G" '更新不会覆盖现有配置和历史数据。';say "$G" '1. 直接更新（不备份）';say "$G" '2. 备份配置后更新';say "$G" '0. 返回主菜单';ask "$G" '请选择 [0-2]：'
 case "$REPLY" in 1);;2)B="/etc/vps-monitor.env.backup.$(date +%Y%m%d-%H%M%S)";cp -p /etc/vps-monitor.env "$B";say "$G" "已授权备份：$B";;0)exit 0;;*)say "$R" '无效选项。';exit 2;;esac
else
 say "$G" '1. BASIC：整机监控（低危）';say "$Y" '2. FULL：增加进程路径、端口和日志取证（高危）';say "$G" '0. 返回主菜单';ask "$G" '请选择 [0-2]：'
 case "$REPLY" in 1);;2)say "$R" 'FULL 以 root 读取进程信息并发送 TG。';ask "$R" '同意请输入大写 YES：';[ "$REPLY" = YES ]||{ say "$R" '未授权。';exit 2;};MODE=full;CONSENT=YES;;0)exit 0;;*)say "$R" '无效选项。';exit 2;;esac
fi
say "$G" '安装内容：1 个 systemd 服务；日常采样 1 进程、1 线程、0 子进程。'
if command -v apt-get>/dev/null;then command -v python3>/dev/null||{ apt-get update;apt-get install -y --no-install-recommends python3 ca-certificates;};[ "$MODE" = basic ]||apt-get install -y --no-install-recommends procps iproute2 util-linux
elif command -v dnf>/dev/null;then dnf install -y python3 ca-certificates;[ "$MODE" = basic ]||dnf install -y procps-ng iproute util-linux
elif command -v yum>/dev/null;then yum install -y python3 ca-certificates;[ "$MODE" = basic ]||yum install -y procps-ng iproute util-linux
elif command -v apk>/dev/null;then apk add --no-cache python3 ca-certificates;[ "$MODE" = basic ]||apk add --no-cache procps iproute2 util-linux
else say "$R" '不支持的包管理器。';exit 1;fi
install -d -m 0755 /opt/vps-monitor /var/lib/vps-monitor/reports /var/lib/vps-monitor/metrics
install -m 0555 "$ROOT/vps_monitor.py" /opt/vps-monitor/vps_monitor.py;install -m 0444 "$ROOT/SECURITY.md" /opt/vps-monitor/SECURITY.md
install -m 0644 "$ROOT/vps-monitor.service" /etc/systemd/system/vps-monitor.service
install -m 0755 "$ROOT/vps-monitorctl" /usr/local/bin/vps-monitorctl
install -m 0755 "$ROOT/menu.sh" /usr/local/bin/vps
install -m 0755 "$ROOT/vps-build-mode" /usr/local/bin/vps-build-mode
install -m 0644 "$ROOT/vps-build-mode.path" /etc/systemd/system/vps-build-mode.path
install -m 0644 "$ROOT/vps-build-mode.service" /etc/systemd/system/vps-build-mode.service
if [ ! -f /etc/vps-monitor.env ];then install -m 0600 "$ROOT/vps-monitor.env.example" /etc/vps-monitor.env;sed -i "s/^FORENSICS_MODE=.*/FORENSICS_MODE=$MODE/;s/^FORENSICS_CONSENT=.*/FORENSICS_CONSENT=$CONSENT/" /etc/vps-monitor.env;fi
chown -R root:root /opt/vps-monitor /var/lib/vps-monitor /etc/vps-monitor.env;chmod 0600 /etc/vps-monitor.env
systemctl daemon-reload;systemctl enable vps-monitor.service;systemctl enable --now vps-build-mode.path >/dev/null 2>&1||true
if [ -x /usr/local/bin/vps-monitorctl ];then
 /usr/local/bin/vps-monitorctl repair >/dev/null 2>&1||true
 /usr/local/bin/vps-monitorctl migrate 2>/dev/null||true
fi
set -a
while IFS= read -r ln;do
 case "$ln" in ''|\#*) continue;; esac
 case "$ln" in *=*) ;; *) continue;; esac
 k=${ln%%=*};v=${ln#*=}
 case "$k" in [A-Z]*) ;; *) continue;; esac
 v=${v#\"};v=${v%\"}
 eval "$k=\$v"
done </etc/vps-monitor.env
set +a
/usr/bin/python3 /opt/vps-monitor/vps_monitor.py check;systemctl restart vps-monitor.service
say "$G" '安装/更新成功。'
say "$G" '以后直接输入下面的快捷命令即可唤醒菜单：'
say "$G" 'vps'
say "$G" '查看状态请复制：sudo vps-monitorctl status'
say "$G" '修改配置请复制：sudo vps-monitorctl configure'
say "$G" '测试 TG 请复制：sudo vps-monitorctl test'
