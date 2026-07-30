import importlib.util, os, subprocess, sys, tempfile, time
os.environ.update({"MONITOR_DATA_DIR":tempfile.mkdtemp(),"FORENSICS_MODE":"basic","FORENSICS_CONSENT":"NO"})
s=importlib.util.spec_from_file_location("monitor","vps_monitor.py");m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
t,i=m.cpu_raw();assert t>=i>=0
mem,swap,info=m.mem_raw();assert 0<=mem<=100 and 0<=swap<=100 and info["MemTotal"]>0
assert isinstance(m.disks_raw(),dict) and isinstance(m.procs_raw(),dict)
assert m.FULL is False and m.selected_processes({"rates":{}})==[]

def P(pid,comm,cmd,exe=""):return {"pid":pid,"comm":comm,"cmd":cmd,"exe":exe}
for cmd in ("node /app/node_modules/.bin/vite build","npm run build","npm install","docker build -t x .","cargo build --release","tar -czf a.tgz /data","pip install -r r.txt","rsync -a /a /b"):
    assert m.protected(P(9001,"node",cmd)), cmd
for comm in ("sshd","systemd","mysqld","dockerd","kworker/0:1"):
    assert m.protected(P(9002,comm,"/usr/sbin/"+comm)), comm
assert m.protected(P(1,"systemd","/sbin/init"))
assert m.protected(P(9003,"kthreadd",""))
assert m.protected(P(m.SELF,"python3","vps_monitor.py"))
assert not m.protected(P(9004,"xmrig","/tmp/.x/xmrig -o pool.example:3333"))

S={"cpu":100.0,"mem":80.0,"swap":10.0,"disks":[]}
# 豁免进程即使被选为候选也必须在执行层拦截
ok,why=m.act_on_process({**P(9005,"node","npm run build"),"starttime":1,"cpu_pct":99.0,"rss_pct":50.0,"read_Bps":0,"write_Bps":0},"CPU",S)
assert ok is False and "放行" in why, why

# 降级模式必须保住进程存活，仅限速/冻结，可恢复
proc=subprocess.Popen([sys.executable,"-c","import time\nwhile True: time.sleep(0.05)"])
time.sleep(0.5)
try:
    st=m.proc_one(proc.pid)[0]
    tgt={**P(proc.pid,"python3","/tmp/runaway-loop --busy"),"starttime":st,"cpu_pct":99.0,"rss_pct":5.0,"read_Bps":0,"write_Bps":0}
    ok,why=m.act_on_process(tgt,"CPU",S,stage="throttle")
    assert ok is True, why
    os.kill(proc.pid,18)
    time.sleep(0.3)
    assert m.proc_alive(proc.pid,st), "降级不得终止进程"
finally:
    try:os.kill(proc.pid,18)
    except Exception:pass
    proc.kill();proc.wait()
assert m.config_check()==0
print("all tests passed")
