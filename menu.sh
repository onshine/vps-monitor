#!/bin/sh
set -eu
TTY=/dev/tty;RELEASE='https://github.com/onshine/vps-monitor/releases/latest/download';BOOT='bash <(curl -fsSL https://raw.githubusercontent.com/onshine/vps-monitor/main/quick-install.sh)'
if [ ! -r "$TTY" ]||[ ! -w "$TTY" ];then echo '错误：需要交互式终端。';exit 1;fi
if [ -t 1 ];then G='\033[1;32m';Y='\033[1;33m';R='\033[1;31m';N='\033[0m';else G=;Y=;R=;N=;fi
say(){ printf '%b%s%b\n' "$1" "$2" "$N";};ask(){ printf '%b%s%b' "$1" "$2" "$N">"$TTY";IFS= read -r REPLY<"$TTY"||REPLY=;}
bye(){ printf '\n';say "$G" '山水有相逢，道友，再见👋。';say "$G" '若要继续使用脚本，输入以下命令：';say "$G" 'vps';exit 0;}
rootrun(){ if [ "$(id -u)" = 0 ];then "$@";else sudo "$@";fi;}
installed(){ [ -x /usr/local/bin/vps-monitorctl ]&&[ -f /etc/vps-monitor.env ];}
hold(){ ask "$G" '按回车或输入 F 返回主菜单；输入 0 退出：';[ "$REPLY" = 0 ]&&bye;return 0;}
fetch(){
 for c in curl unzip sha256sum;do command -v "$c" >/dev/null 2>&1||{ say "$R" "缺少 $c，请先安装。";return 1;};done
 W=$(mktemp -d);say "$G" '正在从 GitHub 下载最新版本…'
 curl -fsSL --retry 3 -o "$W/vps-monitor.zip" "$RELEASE/vps-monitor.zip"||{ say "$R" '下载失败，请检查网络。';rm -rf "$W";return 1;}
 curl -fsSL --retry 3 -o "$W/SHA256SUMS" "$RELEASE/SHA256SUMS"||{ say "$R" '校验文件下载失败。';rm -rf "$W";return 1;}
 ( cd "$W"&&sha256sum -c SHA256SUMS >/dev/null 2>&1 )||{ say "$R" '校验失败，已中止。';rm -rf "$W";return 1;}
 ( cd "$W"&&unzip -qo vps-monitor.zip >/dev/null 2>&1 )||{ say "$R" '解压失败。';rm -rf "$W";return 1;}
 chmod +x "$W/install.sh" "$W/menu.sh" "$W/vps-monitorctl" >/dev/null 2>&1||true
 say "$G" '下载和校验通过。';SRC="$W";return 0
}
while :;do
 printf '\n';say "$G" 'VPS Monitor 管理菜单'
 if installed;then say "$G" "当前版本：$(/usr/bin/python3 /opt/vps-monitor/vps_monitor.py version 2>/dev/null||echo 未知)";else say "$Y" '当前状态：未安装';fi
 say "$G" '1. 安装 vps-monitor 脚本'
 say "$G" '2. 更新 vps-monitor 脚本'
 say "$G" '3. 查看现有配置和权限'
 say "$G" '4. 修改现有配置和权限'
 say "$G" '5. 查看脚本进程日志（最近 10 条）'
 say "$R" '6. 删除脚本进程日志'
 say "$R" '7. 一键卸载'
 say "$G" '0. 退出脚本'
 ask "$G" '请输入选项 [0-7]：'
 case "$REPLY" in
  1) if installed;then
      say "$Y" '已安装，请选择 2 更新。'
     else
      if fetch;then rootrun "$SRC/install.sh" install;rm -rf "$SRC";fi
     fi;;
  2) if installed;then
      if fetch;then rootrun "$SRC/install.sh" update;rm -rf "$SRC";fi
     else
      say "$Y" '尚未安装，请选择 1 安装。'
     fi;;
  3) if installed;then rootrun /usr/local/bin/vps-monitorctl show-config;hold;else say "$Y" '尚未安装。';fi;;
  4) if installed;then if rootrun /usr/local/bin/vps-monitorctl configure;then :;else rc=$?;[ "$rc" = 20 ]&&bye;fi;else say "$Y" '尚未安装。';fi;;
  5) if installed;then rootrun /usr/local/bin/vps-monitorctl logs 10;hold;else say "$Y" '尚未安装。';fi;;
  6) if installed;then rootrun /usr/local/bin/vps-monitorctl delete-log;else say "$Y" '尚未安装。';fi;;
  7) if installed;then rootrun /usr/local/bin/vps-monitorctl uninstall;say "$Y" "如需重新安装，请运行：$BOOT";else say "$Y" '尚未安装。';fi;;
  0) bye;;
  *) say "$R" '无效选项，请输入 0–7。';;
 esac
done
