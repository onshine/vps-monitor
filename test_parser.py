import importlib.util, os, subprocess, sys, tempfile, time
os.environ.update({"MONITOR_DATA_DIR":tempfile.mkdtemp(),"FORENSICS_MODE":"basic","FORENSICS_CONSENT":"NO"})
s=importlib.util.spec_from_file_location("monitor","vps_monitor.py");m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
t,i=m.cpu_raw();assert t>=i>=0
mem,swap,info=m.mem_raw();assert 0<=mem<=100 and 0<=swap<=100 and info["MemTotal"]>0
assert isinstance(m.disks_raw(),dict) and isinstance(m.procs_raw(),dict)
assert m.FULL is False and m.selected_processes({"rates":{}})==[]

def P(pid,comm,cmd,exe="",cgroup=""):return {"pid":pid,"comm":comm,"cmd":cmd,"exe":exe,"cgroup":cgroup}
# 收窄后的白名单：常用构建/维护命令仍豁免
for cmd in ("node /app/node_modules/.bin/vite build","npm run build","npm install","npm ci","docker build -t x .","mysqldump -u r db"):
    assert m.protected(P(9001,"node",cmd)), cmd
# 已移出白名单的通用命令不再豁免，缩小被绕过的面
for cmd in ("tar -czf a.tgz /data","rsync -a /a /b","gcc main.c","make -j4"):
    assert not m.protected(P(9101,"sh",cmd)), cmd
for comm in ("sshd","systemd","mysqld","dockerd","kworker/0:1"):
    assert m.protected(P(9002,comm,"/usr/sbin/"+comm)), comm
assert m.protected(P(1,"systemd","/sbin/init"))
assert m.protected(P(m.SELF,"python3","vps_monitor.py"))
assert not m.protected(P(9004,"xmrig","/tmp/.x/xmrig -o pool.example:3333"))

# 敏感信息必须脱敏，报告会经 Telegram 外发
for raw,leak in [
 ("python main.py -token 7633489399:AAGXsP6x8IKiAPuRCoUulTMFxy_YxT7vZGM","7633489399:AAGX"),
 ("app --api-key sk-abcdefghijklmnopqrstuvwx","sk-abcdefghijkl"),
 ("run --password Sup3rSecretValue","Sup3rSecretValue"),
 ("export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345","ghp_ABCDEFGH"),
]:
    out=m.redact(raw)
    assert leak not in out,(raw,out)
    assert "REDACTED" in out,(raw,out)
# 正常命令不应被破坏
assert m.redact("node dist/server.js")=="node dist/server.js"

# 内存瞬时冲高不告警，仅持续超限才计入
S={"cpu":10.0,"mem":95.0,"swap":5.0,"meminfo":{"MemTotal":2<<30,"SwapTotal":1<<30},"disks":[],"rates":{},"fs":[],"inodes":[]}
m.MEM_SUSTAIN=120;m._MEM_SINCE.clear()
assert not any("内存" in x for x in m.reasons(S,now=1000.0)),"瞬时高内存不应立即告警"
assert not any("内存" in x for x in m.reasons(S,now=1060.0)),"未达持续时间不应告警"
assert any("内存" in x for x in m.reasons(S,now=1130.0)),"持续超限应告警"
S2=dict(S,mem=50.0);m.reasons(S2,now=1140.0)
assert not any("内存" in x for x in m.reasons(S,now=1150.0)),"恢复后应重新计时"

# 容器归属解析
cg="0::/system.slice/docker-51dfeacc6fb4aadfc5de43a2ffa277b30e6c9f7400f4013c5bf05cc1e1badbd1.scope"
m.DOCKER_MAP["51dfeacc6fb4"]={"name":"bemby","image":"liveinaus/bemby:latest"}
c=m.container_of({"cgroup":cg});assert c["name"]=="bemby" and c["image"]=="liveinaus/bemby:latest",c
assert m.container_of({"cgroup":"0::/system.slice/sshd.service"})["name"]==""

S3={"cpu":100.0,"mem":80.0,"swap":10.0,"disks":[],"meminfo":{"MemTotal":2<<30}}
ok,why=m.act_on_process({**P(9005,"node","npm run build"),"starttime":1,"cpu_pct":99.0,"rss":1<<20,"rss_pct":50.0,"read_Bps":0,"write_Bps":0},"CPU",S3)
assert ok is False and "放行" in why, why

# 降级必须保住进程存活、可恢复
proc=subprocess.Popen([sys.executable,"-c","import time\nwhile True: time.sleep(0.05)"])
time.sleep(0.5)
try:
    st=m.proc_one(proc.pid)[0]
    tgt={**P(proc.pid,"python3","/tmp/runaway --busy"),"starttime":st,"cpu_pct":99.0,"rss":1<<20,"rss_pct":5.0,"read_Bps":0,"write_Bps":0}
    ok,why=m.act_on_process(tgt,"CPU",S3,stage="throttle")
    assert ok is True, why
    os.kill(proc.pid,18);time.sleep(0.3)
    assert m.proc_alive(proc.pid,st),"降级不得终止进程"
finally:
    try:os.kill(proc.pid,18)
    except Exception:pass
    proc.kill();proc.wait()
assert m.config_check()==0
print("all tests passed")
