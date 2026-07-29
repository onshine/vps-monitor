#!/bin/sh
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo '错误：请使用 sudo ./install.sh'; exit 1; }
TTY=/dev/tty
if [ ! -r "$TTY" ] || [ ! -w "$TTY" ]; then echo '错误：安装需要交互式终端（/dev/tty）。请 SSH 登录后重新执行。'; exit 1; fi
ask(){ printf '%s' "$1" >"$TTY"; IFS= read -r REPLY <"$TTY" || REPLY=; }
MODE=basic; CONSENT=NO
if [ -f /etc/vps-monitor.env ]; then
 echo '检测到已有安装：进入安全升级模式。'
 echo '将替换程序和服务文件，但保留配置、既有权限授权和历史数据。'
else
 cat <<'EOF'

════════════════════════════════════════════════════
 VPS Monitor 首次安装：请选择权限模式
════════════════════════════════════════════════════

[1] BASIC（低危，默认）
    监控整机 CPU、内存、Swap、磁盘 I/O、空间和 inode。
    不读取其他进程的文件路径、fd、端口和敏感系统日志。

[2] FULL（高危，完整取证）
    以 root 读取其他用户进程的 PID、命令、exe、cwd、fd 路径、
    TCP/UDP 端口，以及 journal/dmesg/Docker 状态，并把报告发往 Telegram。

EOF
 ask '请输入 1 或 2，然后按回车 [默认 1]：'
 choice=${REPLY:-1}
 case "$choice" in
  1) MODE=basic; CONSENT=NO ;;
  2)
   cat <<'EOF'

──────────────── FULL 模式授权确认 ────────────────
将授予以下高危能力：
  • root 身份读取其他用户进程的 /proc 信息；
  • 读取进程命令、程序路径、工作目录和打开的文件路径；
  • 读取端口、网络连接、内核及 systemd 日志；
  • 报告中的 PID、路径、IP 和日志将发送给你配置的 Telegram。

主要风险：被篡改的 root 程序可能危及整机；命令或日志可能误含敏感信息。
安全边界：不会读取 /proc/PID/environ、文件内容或 SSH 密钥；不会自动
kill 进程、删除文件或封禁 IP；systemd 另设 96MiB/20% CPU 硬限制。
完整说明：SECURITY.md
───────────────────────────────────────────────────

EOF
   ask '若你理解并同意，请输入大写 YES，然后按回车：'
   answer=$REPLY
   if [ "$answer" != YES ]; then
    echo "未启用 FULL：确认值不是大写 YES，安装已安全取消。" >&2
    echo '请重新运行安装器；如不需要进程级取证，可选择 1（BASIC）。' >&2
    exit 2
   fi
   MODE=full; CONSENT=YES
   echo 'FULL 高危权限已由用户明确授权。'
   ;;
  *) echo "无效选择：$choice。只能输入 1 或 2，安装已取消。" >&2; exit 2 ;;
 esac
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
 echo '保留已有 /etc/vps-monitor.env；不会静默提升或改变权限。'
fi
chown -R root:root /opt/vps-monitor /var/lib/vps-monitor /etc/vps-monitor.env
chmod 0600 /etc/vps-monitor.env
systemctl daemon-reload
systemctl enable vps-monitor.service
set -a
# shellcheck disable=SC1091
. /etc/vps-monitor.env
set +a
/usr/bin/python3 /opt/vps-monitor/vps_monitor.py check
systemctl restart vps-monitor.service
echo
echo '════════════════ 安装成功 ════════════════'
echo "权限模式：$MODE"
echo '下一步：sudo vps-monitorctl config（填写 Telegram）'
echo '通知测试：sudo vps-monitorctl test'
echo '服务状态：sudo vps-monitorctl status'
