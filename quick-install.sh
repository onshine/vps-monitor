#!/usr/bin/env sh
set -eu
BASE_URL="https://github.com/onshine/vps-monitor/releases/latest/download"
WORKDIR="${HOME:-/root}/vps-monitor"
TTY=/dev/tty
need(){ command -v "$1" >/dev/null 2>&1; }
as_root(){ if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }

install_deps(){
 echo '检测到缺少下载或解压工具。'
 if [ ! -r "$TTY" ] || [ ! -w "$TTY" ]; then echo '请先手动安装 curl、unzip、coreutils。'; exit 1; fi
 printf '是否现在自动安装所需工具？输入 Y 继续 [Y/n]：' >"$TTY"
 IFS= read -r ans <"$TTY" || ans=
 case "${ans:-Y}" in Y|y) ;; *) echo '安装已取消。'; exit 2;; esac
 if need apt-get; then as_root apt-get update; as_root apt-get install -y curl unzip coreutils ca-certificates
 elif need dnf; then as_root dnf install -y curl unzip coreutils ca-certificates
 elif need yum; then as_root yum install -y curl unzip coreutils ca-certificates
 elif need apk; then as_root apk add --no-cache curl unzip coreutils ca-certificates
 else echo '不支持的包管理器，请手动安装 curl、unzip、coreutils。'; exit 1
 fi
}

if { ! need curl && ! need wget; } || ! need unzip || ! need sha256sum; then install_deps; fi
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
cd "$WORKDIR"
if need curl; then
 curl -fL --retry 3 -o vps-monitor.zip "$BASE_URL/vps-monitor.zip"
 curl -fL --retry 3 -o SHA256SUMS "$BASE_URL/SHA256SUMS"
else
 wget -O vps-monitor.zip "$BASE_URL/vps-monitor.zip"
 wget -O SHA256SUMS "$BASE_URL/SHA256SUMS"
fi
sha256sum -c SHA256SUMS
unzip -q vps-monitor.zip
chmod +x install.sh
printf '\n已下载并校验最新 Release。现在进入交互式安全安装。\n\n'
if [ "$(id -u)" = 0 ]; then exec ./install.sh; else exec sudo ./install.sh; fi
