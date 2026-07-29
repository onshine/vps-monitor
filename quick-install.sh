#!/usr/bin/env sh
set -eu
BASE_URL="https://github.com/onshine/vps-monitor/releases/latest/download"
WORKDIR="${HOME:-/root}/vps-monitor"
need(){ command -v "$1" >/dev/null 2>&1; }

if ! need curl && ! need wget; then
 echo '错误：需要 curl 或 wget。Debian/Ubuntu：sudo apt-get install -y curl'
 exit 1
fi
if ! need unzip; then
 echo '错误：需要 unzip。Debian/Ubuntu：sudo apt-get install -y unzip'
 exit 1
fi
need sha256sum || { echo '错误：需要 sha256sum（通常由 coreutils 提供）'; exit 1; }

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
