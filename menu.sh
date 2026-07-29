#!/bin/sh
set -eu
TTY=/dev/tty;RESTART='bash <(curl -fsSL https://raw.githubusercontent.com/onshine/vps-monitor/main/quick-install.sh)'
if [ ! -r "$TTY" ]||[ ! -w "$TTY" ];then echo '错误：需要交互式终端。';exit 1;fi
if [ -t 1 ];then G='\033[1;32m';Y='\033[1;33m';R='\033[1;31m';N='\033[0m';else G=;Y=;R=;N=;fi
say(){ printf '%b%s%b\n' "$1" "$2" "$N";};ask(){ printf '%b%s%b' "$1" "$2" "$N">"$TTY";IFS= read -r REPLY<"$TTY"||REPLY=;}
bye(){ printf '\n';say "$G" '山水有相逢，道友，再见👋。';say "$G" '若要继续使用脚本，输入以下命令：';printf '%s\n' "$RESTART";exit 0;}
rootrun(){ if [ "$(id -u)" = 0 ];then "$@";else sudo "$@";fi;}
installed(){ [ -x /usr/local/bin/vps-monitorctl ]&&[ -f /etc/vps-monitor.env ];}
download(){ W="${HOME:-/root}/vps-monitor";rm -rf "$W";mkdir -p "$W";cd "$W";curl -fsSL --retry 3 -o vps-monitor.zip https://github.com/onshine/vps-monitor/releases/latest/download/vps-monitor.zip;curl -fsSL --retry 3 -o SHA256SUMS https://github.com/onshine/vps-monitor/releases/latest/download/SHA256SUMS;sha256sum -c SHA256SUMS;unzip -q vps-monitor.zip;chmod +x install.sh menu.sh vps-monitorctl;}
while :;do
 printf '\n';say "$G" 'VPS Monitor 管理菜单';say "$G" '1. 安装 vps-monitor 脚本';say "$G" '2. 更新 vps-monitor 脚本';say "$G" '3. 查看现有配置和权限';say "$G" '4. 修改现有配置和权限';say "$G" '5. 查看脚本进程日志（最近 10 条）';say "$R" '6. 删除脚本进程日志';say "$R" '7. 一键卸载';say "$G" '0. 退出脚本';ask "$G" '请输入选项 [0-7]：'
 case "$REPLY" in
  1) if installed;then say "$Y" '已检测到现有安装，请选择 2 更新。';else download;rootrun ./install.sh install;fi;;
  2) if installed;then download;rootrun ./install.sh update;else say "$Y" '尚未安装，请选择 1 安装。';fi;;
  3) if installed;then rootrun /usr/local/bin/vps-monitorctl show-config;ask "$G" '按回车或输入 F 返回主菜单；输入 0 退出：';[ "$REPLY" = 0 ]&&bye;else say "$Y" '尚未安装。';fi;;
  4) if installed;then if rootrun /usr/local/bin/vps-monitorctl configure;then :;else rc=$?;[ "$rc" = 20 ]&&bye;fi;else say "$Y" '尚未安装。';fi;;
  5) if installed;then rootrun /usr/local/bin/vps-monitorctl logs 10;ask "$G" '按回车或输入 F 返回主菜单；输入 0 退出：';[ "$REPLY" = 0 ]&&bye;else say "$Y" '尚未安装。';fi;;
  6) if installed;then rootrun /usr/local/bin/vps-monitorctl delete-log;else say "$Y" '尚未安装。';fi;;
  7) if installed;then rootrun /usr/local/bin/vps-monitorctl uninstall;else say "$Y" '尚未安装。';fi;;
  0)bye;;*)say "$R" '无效选项，请输入 0–7。';;
 esac
done
