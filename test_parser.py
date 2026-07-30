import importlib.util, os, tempfile
os.environ.update({"MONITOR_DATA_DIR":tempfile.mkdtemp(),"FORENSICS_MODE":"basic","FORENSICS_CONSENT":"NO"})
s=importlib.util.spec_from_file_location("monitor","vps_monitor.py");m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
t,i=m.cpu_raw();assert t>=i>=0
mem,swap,info=m.mem_raw();assert 0<=mem<=100 and 0<=swap<=100 and info["MemTotal"]>0
assert isinstance(m.disks_raw(),dict) and isinstance(m.procs_raw(),dict)
assert m.FULL is False and m.selected_processes({"rates":{}})==[]

def P(pid,comm,cmd,exe=""):return {"pid":pid,"comm":comm,"cmd":cmd,"exe":exe}
# 构建/维护类任务必须被豁免，避免误杀用户自己的编译打包
for cmd in ("node /app/node_modules/.bin/vite build","npm run build","npm install","docker build -t x .","cargo build --release","tar -czf a.tgz /data","pip install -r r.txt","rsync -a /a /b"):
    assert m.protected(P(9001,"node",cmd)), cmd
# 系统与数据库关键进程必须被保护
for comm in ("sshd","systemd","mysqld","dockerd","kworker/0:1"):
    assert m.protected(P(9002,comm,"/usr/sbin/"+comm)), comm
# PID1、内核线程、监控器自身必须保护
assert m.protected(P(1,"systemd","/sbin/init"))
assert m.protected(P(9003,"kthreadd",""))
assert m.protected(P(m.SELF,"python3","vps_monitor.py"))
# 普通非白名单进程不应被豁免，否则自动处置将完全失效
assert not m.protected(P(9004,"xmrig","/tmp/.x/xmrig -o pool.example:3333"))
# 执行层必须二次拦截豁免进程，即使被误选为候选也不能处置
ok,why=m.act_on_process({**P(9005,"node","npm run build"),"starttime":1,"cpu_pct":99.0,"rss_pct":50.0,"read_Bps":0,"write_Bps":0},"CPU",
                        {"cpu":100.0,"mem":80.0,"swap":10.0,"disks":[]})
assert ok is False and "放行" in why, why
assert m.config_check()==0
print("all tests passed")
