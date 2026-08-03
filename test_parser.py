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
# 每次实际处置都必须留下 TXT 现场取证，不受告警冷却影响
before=len(list(m.REPORTS.glob("incident-*.txt")))
proc=subprocess.Popen([sys.executable,"-c","import time\nwhile True: time.sleep(0.05)"])
time.sleep(0.5)
try:
    st=m.proc_one(proc.pid)[0]
    tgt={**P(proc.pid,"python3","/tmp/runaway --busy"),"starttime":st,"cpu_pct":99.0,"rss":1<<20,"rss_pct":5.0,"read_Bps":0,"write_Bps":0}
    ok,_=m.act_on_process(tgt,"内存",S3,stage="throttle")
    assert ok is True
    assert len(list(m.REPORTS.glob("incident-*.txt")))>before,"处置必须生成取证报告"
finally:
    try:os.kill(proc.pid,18)
    except Exception:pass
    proc.kill();proc.wait()
# 早期取证：进程退出后仍须保留命令/容器/镜像等第一手证据
m.EVIDENCE_CPU=1.0;m.EVIDENCE_MEM=0.0001;m.EVIDENCE_IO=1
m.DOCKER_MAP["684ab02e4006"]={"name":"relaxed_aryabhata","image":"node:18-alpine"}
proc=subprocess.Popen([sys.executable,"-c","import time\nwhile True: time.sleep(0.05)"])
time.sleep(0.4)
try:
    st=m.proc_one(proc.pid)[0]
    snap={"meminfo":{"MemTotal":2<<30},
          "rates":{proc.pid:{"cpu_pct":95.0,"rss":1<<20,"rss_pct":5.0,"read_Bps":0,"write_Bps":0}}}
    store={}
    m.merge_evidence(store,m.capture_evidence(snap,1000.0),1000.0)
    assert proc.pid in store,"超限进程必须被即时取证"
finally:
    proc.kill();proc.wait()
time.sleep(0.3)
assert not m.proc_alive(proc.pid,st),"测试前提：进程已退出"
e=store[proc.pid]
assert e["cmd"] and "python" in e["cmd"].lower(),e
assert e["first_seen"]==1000.0
txt="\n".join(m.evidence_lines(store))
assert "已退出" in txt and str(proc.pid) in txt,txt
# 峰值需保留最高值，身份保留最早观测
m.merge_evidence(store,{proc.pid:{**e,"cpu_pct":20.0,"first_seen":1200.0}},1200.0)
assert store[proc.pid]["cpu_pct"]==95.0,"应保留峰值"
assert store[proc.pid]["first_seen"]==1000.0,"应保留最早观测时间"
# 容器与镜像解析
store2={};snap2={"meminfo":{"MemTotal":2<<30},"rates":{}}
assert m.capture_evidence(snap2,1.0)=={}
blk=m.evidence_block(store)
assert str(proc.pid) in blk and "首次观测" in blk,blk

# 监控处置需在证据中留痕，且不被后续采样覆盖
store3={};snapA={"meminfo":{"MemTotal":2<<30},
  "rates":{4242:{"cpu_pct":95.0,"rss":1<<20,"rss_pct":5.0,"read_Bps":0,"write_Bps":0}}}
m.merge_evidence(store3,{4242:{"first_seen":10.0,"pid":4242,"uid":"0","comm":"x","cmd":"x","exe":"","cwd":"",
  "container":"","image":"","cgroup":"","cpu_pct":95.0,"rss":1<<20,"rss_pct":5.0,
  "read_Bps":0,"write_Bps":0,"total_mem":2<<30,"acted_by_monitor":""}},10.0)
store3[4242]["acted_by_monitor"]="SIGTERM"
m.merge_evidence(store3,{4242:{**store3[4242],"acted_by_monitor":"","cpu_pct":10.0}},20.0)
assert store3[4242]["acted_by_monitor"]=="SIGTERM","处置标记不得被后续采样覆盖"
txt3="\n".join(m.evidence_lines(store3))
assert "监控处置：SIGTERM" in txt3,txt3
store3[4242]["acted_by_monitor"]=""
assert "非监控处置" in "\n".join(m.evidence_lines(store3))

# 按容器名/镜像豁免：java、python 等通用进程名无法靠命令行安全豁免
m.DOCKER_MAP["aaaaaaaaaaaa"]={"name":"alist-tvbox","image":"haroldli/alist-tvbox:latest"}
m.DOCKER_MAP["bbbbbbbbbbbb"]={"name":"xiaoya-tvbox","image":"haroldli/xiaoya-tvbox:latest"}
m.DOCKER_MAP["cccccccccccc"]={"name":"other-svc","image":"someone/other:latest"}
def CG(x):return "0::/system.slice/docker-%s.scope"%(x*1)
assert m.protected({"pid":7001,"comm":"java","cmd":"java -jar app.jar","exe":"/usr/bin/java","cgroup":CG("aaaaaaaaaaaa")}),"alist-tvbox 应豁免"
assert m.protected({"pid":7002,"comm":"python3","cmd":"python3 main.py","exe":"","cgroup":CG("bbbbbbbbbbbb")}),"xiaoya-tvbox 应豁免"
assert not m.protected({"pid":7003,"comm":"java","cmd":"java -jar evil.jar","exe":"","cgroup":CG("cccccccccccc")}),"未列入的容器不应豁免"
assert not m.protected({"pid":7004,"comm":"java","cmd":"java -jar app.jar","exe":"","cgroup":"0::/system.slice/sshd.service"}),"宿主机 java 不应因容器名单豁免"

assert m.config_check()==0
# 告警需说明受保护原因并给出可执行建议
m.DOCKER_MAP["dddd"]={"name":"1Panel-mysql-Cf2q","image":"mysql:8.4.10"}
e={"pid":999,"comm":"mysqld","uid":"999","cmd":"mysqld","exe":"/usr/sbin/mysqld",
   "cgroup":"0::/system.slice/docker-dddd.scope","container":"1Panel-mysql-Cf2q","image":"mysql:8.4.10",
   "rss":1<<20,"rss_pct":9.8,"read_Bps":0,"write_Bps":0,"cpu_pct":94.8,"total_mem":2<<30,
   "first_seen":1000.0,"acted_by_monitor":""}
assert m.why_protected(e)=="受保护程序名：mysqld",m.why_protected(e)
tips=m.advise(e,{"cpu":100.0})
assert any("docker update --cpus" in t for t in tips),tips
assert any("vps-build-mode enter" in t for t in tips),tips
blk=m.evidence_block({999:e},{"cpu":100.0,"mem":59.0,"swap":49.0})
assert "不会自动处置" in blk and "受保护程序名" in blk,blk
# 普通容器进程不应标记受保护
e2=dict(e,comm="node",cmd="node dist/server.js",exe="/usr/local/bin/node",
        container="myapp",image="node:20")
m.DOCKER_MAP["dddd"]={"name":"myapp","image":"node:20"}
assert m.why_protected(e2)=="",m.why_protected(e2)

print("all tests passed")
