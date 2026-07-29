#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo '错误：请使用 sudo ./install.sh'; exit 1; }
cat <<'EOF'
VPS Sentinel 安装器

请选择权限模式：
  1) BASIC（低危，默认）：整机 CPU/内存/Swap/磁盘 I/O/空间/inode；不读取其他进程路径、fd、端口和敏感系统日志。
  2) FULL（高危，完整取证）：以 root 读取其他用户进程的 PID、cmdline、exe、cwd、fd 路径、端口，以及 journal/dmesg/Docker 状态；报告会发往 Telegram。

FULL 模式风险：root 程序若被篡改可危及整机；命令、文件路径、IP 和日志可能含业务敏感信息；Docker socket 等价宿主机 root。
脚本明确不会读取 /proc/PID/environ、文件内容、SSH 密钥，也不会自动 kill、删文件或封禁。
详见 SECURITY.md。
EOF
printf '选择 [1/2，默认 1]: '; read -r choice
MODE=basic; CONSENT=NO
if [ "${choice:-1}" = 2 ]; then
 cat "$ROOT/SECURITY.md" 2>/dev/null || true
 echo
 echo '若你已理解并接受以上高危权限，请输入大写 YES。其他输入均取消安装。'
 printf '确认: '; read -r answer
 [ "$answer" = YES ] || { echo '未授权，安装已取消。'; exit 2; }
 MODE=full; CONSENT=YES
fi
if command -v apt-get >/dev/null; then
 command -v python3 >/dev/null || { apt-get update; apt-get install -y python3; }
 apt-get install -y procps iproute2 sysstat util-linux ca-certificates
elif command -v dnf >/dev/null; then dnf install -y python3 procps-ng iproute sysstat util-linux ca-certificates
elif command -v yum >/dev/null; then yum install -y python3 procps-ng iproute sysstat util-linux ca-certificates
elif command -v apk >/dev/null; then apk add --no-cache python3 procps iproute2 sysstat util-linux coreutils ca-certificates
else echo '不支持的包管理器，请先安装 python3/procps/iproute2/sysstat/util-linux。'; exit 1
fi
install -d -m 0755 /opt/vps-monitor /var/lib/vps-monitor/reports /var/lib/vps-monitor/metrics
install -m 0555 "$ROOT/vps_monitor.py" /opt/vps-monitor/vps_monitor.py
install -m 0444 "$ROOT/SECURITY.md" /opt/vps-monitor/SECURITY.md
install -m 0644 "$ROOT/vps-monitor.service" /etc/systemd/system/vps-monitor.service
install -m 0755 "$ROOT/vps-monitorctl" /usr/local/bin/vps-monitorctl
if [ ! -f /etc/vps-monitor.env ]; then
 install -m 0600 "$ROOT/vps-monitor.env.example" /etc/vps-monitor.env
 sed -i "s/^FORENSICS_MODE=.*/FORENSICS_MODE=$MODE/;s/^FORENSICS_CONSENT=.*/FORENSICS_CONSENT=$CONSENT/" /etc/vps-monitor.env
else
 echo '保留现有 /etc/vps-monitor.env；不会静默提升权限。'
fi
chown -R root:root /opt/vps-monitor /var/lib/vps-monitor /etc/vps-monitor.env
chmod 0600 /etc/vps-monitor.env
systemctl daemon-reload
systemctl enable vps-monitor.service
set -a; . /etc/vps-monitor.env; set +a
/usr/bin/python3 /opt/vps-monitor/vps_monitor.py check
echo
echo '安装完成。请执行：sudo vps-monitorctl config，填写 Telegram 配置并自动重启。'
echo '测试通知：sudo vps-monitorctl test'
echo '状态：sudo vps-monitorctl status'
