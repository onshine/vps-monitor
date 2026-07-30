#!/bin/sh
# 验证 vps-monitorctl 的配置解析：必须导出为环境变量，否则 Python 读不到 Telegram 配置
set -eu
D=$(mktemp -d);trap 'rm -rf "$D"' EXIT
printf 'TG_BOT_TOKEN="123:abc"\nTG_CHAT_ID="456"\nAUTO_ACTION_PROTECTED_CMDLINE="vite build,tar ,gcc "\n' >"$D/c.env"

# 提取 load() 到独立脚本，模拟真实调用路径
sed -n '/^load(){/,/^}/p' vps-monitorctl >"$D/load.sh"
cat >"$D/probe.sh" <<'EOS'
CONFIG="$1"
. "$2"
load
python3 -c 'import os;print("RESULT",os.getenv("TG_BOT_TOKEN",""),os.getenv("TG_CHAT_ID",""))'
EOS
out=$(sh "$D/probe.sh" "$D/c.env" "$D/load.sh" 2>&1)

case "$out" in
 *"RESULT 123:abc 456"*) echo 'config export to env: ok';;
 *) echo "config export to env: FAILED -> $out";exit 1;;
esac
case "$out" in
 *'not found'*) echo 'unquoted value executed: FAILED';exit 1;;
esac
echo 'ctl tests passed'
