#!/usr/bin/env python3
"""VPS Sentinel — dependency-free Linux resource monitor and incident collector."""
import argparse, html, json, os, re, resource, shutil, socket, subprocess, sys, time, traceback, urllib.parse, urllib.request, uuid
from collections import deque
from datetime import datetime
from pathlib import Path

VERSION="2.11.0"
def env(name,default,cast=str):
 try:return cast(os.getenv(name,str(default)))
 except:return default
INTERVAL=max(1.0,env("MONITOR_INTERVAL",5,float)); PROC_INTERVAL=max(INTERVAL,env("PROCESS_SCAN_INTERVAL",5,float))
CPU_LIMIT=env("CPU_THRESHOLD",90,float); MEM_LIMIT=env("MEMORY_THRESHOLD",90,float); SWAP_LIMIT=env("SWAP_THRESHOLD",90,float)
IO_LIMIT=env("DISK_IO_THRESHOLD",90,float); FS_LIMIT=env("DISK_SPACE_THRESHOLD",90,float); INODE_LIMIT=env("INODE_THRESHOLD",90,float)
READ_LIMIT=env("DISK_READ_MBPS",0,float)*1048576; WRITE_LIMIT=env("DISK_WRITE_MBPS",0,float)*1048576
CONSEC=max(1,env("ALERT_CONSECUTIVE",2,int)); RECOVERY=max(1,env("RECOVERY_CONSECUTIVE",3,int)); COOLDOWN=max(60,env("ALERT_COOLDOWN",900,int))
TOPN=min(50,max(5,env("TOP_PROCESSES",15,int))); MAX_FDS=min(500,max(20,env("MAX_FDS_PER_PROCESS",150,int)))
REPORT_DAYS=max(1,env("REPORT_RETENTION_DAYS",14,int)); REPORT_MAX=max(5,env("REPORT_MAX_FILES",100,int)); METRICS_INTERVAL=max(0,env("METRICS_INTERVAL",60,int)); METRICS_DAYS=max(1,env("METRICS_RETENTION_DAYS",7,int))
DATA=Path(os.getenv("MONITOR_DATA_DIR","/var/lib/vps-monitor")); REPORTS=DATA/"reports"; METRICS=DATA/"metrics"; HOST=os.getenv("MONITOR_HOSTNAME",socket.gethostname())
TOKEN=os.getenv("TG_BOT_TOKEN",""); CHAT=os.getenv("TG_CHAT_ID",""); THREAD=os.getenv("TG_MESSAGE_THREAD_ID",""); SILENT=os.getenv("TG_DISABLE_NOTIFICATION","false").lower() in ("1","true","yes")
AUTO_ACTION=os.getenv("AUTO_ACTION","none").lower(); AUTO_CONSENT=os.getenv("AUTO_ACTION_CONSENT","NO") == "YES"
AUTO_CPU=os.getenv("AUTO_ACTION_CPU","false").lower() in ("1","true","yes"); AUTO_MEM=os.getenv("AUTO_ACTION_MEMORY","false").lower() in ("1","true","yes")
AUTO_READ=os.getenv("AUTO_ACTION_DISK_READ","false").lower() in ("1","true","yes"); AUTO_WRITE=os.getenv("AUTO_ACTION_DISK_WRITE","false").lower() in ("1","true","yes")
AUTO_KILL=os.getenv("AUTO_ACTION_ALLOW_SIGKILL","false").lower() in ("1","true","yes"); AUTO_KILL_CONSENT=os.getenv("AUTO_ACTION_SIGKILL_CONSENT","NO") == "YES"
ACTION_CONSEC=max(2,env("AUTO_ACTION_CONSECUTIVE",3,int)); ACTION_GRACE=max(3,env("AUTO_ACTION_GRACE_SECONDS",10,int)); ACTION_HOURLY=max(1,env("AUTO_ACTION_MAX_PER_HOUR",3,int))
THROTTLE_FIRST=os.getenv("AUTO_ACTION_THROTTLE_FIRST","true").lower() in ("1","true","yes")
THROTTLE_FREEZE=os.getenv("AUTO_ACTION_THROTTLE_FREEZE","true").lower() in ("1","true","yes")
ESCALATE=max(0,env("AUTO_ACTION_ESCALATE_AFTER",6,int))
PROC_CPU_MIN=max(1,env("AUTO_ACTION_PROCESS_CPU_MIN",70,float)); PROC_MEM_MIN=max(1,env("AUTO_ACTION_PROCESS_MEMORY_MIN",25,float)); PROC_READ_MIN=max(1,env("AUTO_ACTION_PROCESS_READ_MBPS_MIN",10,float))*1048576; PROC_WRITE_MIN=max(1,env("AUTO_ACTION_PROCESS_WRITE_MBPS_MIN",10,float))*1048576
PROTECTED={x.strip() for x in os.getenv("AUTO_ACTION_PROTECTED_NAMES","systemd,sshd,ssh,init,kthreadd,kworker,rcu_sched,systemd-journal,systemd-udevd,dbus-daemon,cron,containerd,dockerd,mysqld,mariadbd,postgres,redis-server,mongod").split(",") if x.strip()}
PROTECTED_CMD=[x.strip().lower() for x in os.getenv("AUTO_ACTION_PROTECTED_CMDLINE","vite build,npm run build,npm install,npm ci,docker build,apt-get,dpkg,mysqldump").split(",") if x.strip()]
PROTECTED_CT={x.strip().lower() for x in os.getenv("AUTO_ACTION_PROTECTED_CONTAINERS","alist-tvbox,xiaoya-tvbox").split(",") if x.strip()}
ACTION_LOG=DATA/"actions.jsonl"; ACTION_LOG_WARN=100*1048576
PAGE=os.sysconf("SC_PAGE_SIZE"); CLK=os.sysconf(os.sysconf_names["SC_CLK_TCK"]); SELF=os.getpid()
MODE=os.getenv("FORENSICS_MODE","basic").lower(); CONSENT=os.getenv("FORENSICS_CONSENT","") == "YES"; FULL=MODE == "full" and CONSENT
SELF_RSS_MAX=max(32,env("SELF_RSS_MAX_MB",80,int))*1048576; MAX_REPORT=max(1,env("MAX_REPORT_SIZE_MB",5,int))*1048576; SAMPLE_TIMEOUT=max(5,env("SELF_SAMPLE_TIMEOUT",30,float))
for d in (DATA,REPORTS,METRICS): d.mkdir(parents=True,exist_ok=True)

def text(path,limit=1048576):
 try:
  with open(path,"r",errors="replace") as f:return f.read(limit)
 except:return ""
def command(args,timeout=8):
 try:
  p=subprocess.run(args,shell=isinstance(args,str),text=True,capture_output=True,timeout=timeout,env={**os.environ,"LC_ALL":"C"})
  return ((p.stdout or "")+(p.stderr or "")).strip()[:1048576]
 except Exception as e:return f"[unavailable: {e}]"
def cpu_raw():
 p=text("/proc/stat",4096).splitlines()[0].split()[1:]; a=[int(x) for x in p]; return sum(a),a[3]+(a[4] if len(a)>4 else 0)
def mem_raw():
 d={}
 for line in text("/proc/meminfo",65536).splitlines():
  try:k,v=line.split(":",1); d[k]=int(v.split()[0])*1024
  except:pass
 total=d.get("MemTotal",1); used=100*(1-d.get("MemAvailable",0)/total); st=d.get("SwapTotal",0); su=100*(1-d.get("SwapFree",0)/st) if st else 0
 return used,su,d
def disks_raw():
 out={}
 for line in text("/proc/diskstats",262144).splitlines():
  p=line.split()
  if len(p)<14:continue
  n=p[2]
  if n.startswith(("loop","ram","fd","sr")):continue
  # Whole devices only; partitions duplicate parent I/O. dm/md devices remain visible.
  if Path(f"/sys/class/block/{n}/partition").exists():continue
  try:out[n]=tuple(int(p[i]) for i in (3,5,7,9,12)) # reads,sectorsR,writes,sectorsW,io_ms
  except:pass
 return out
def proc_one(pid):
 try:
  raw=text(f"/proc/{pid}/stat",8192); tail=raw[raw.rfind(")")+2:].split(); io={}
  for line in text(f"/proc/{pid}/io",4096).splitlines():
   k,v=line.split(":",1); io[k]=int(v)
  # tail indexes: state=0, utime=11, stime=12, starttime=19, rss=21
  return (int(tail[19]),io.get("read_bytes",0),io.get("write_bytes",0),int(tail[11])+int(tail[12]),int(tail[21])*PAGE)
 except:return None
def procs_raw():
 out={}
 try:names=os.listdir("/proc")
 except:return out
 for name in names:
  if name.isdigit():
   v=proc_one(name)
   if v:out[int(name)]=v
 return out
def mounts():
 rows=[];seen=set()
 for line in text("/proc/self/mountinfo",1048576).splitlines():
  try:
   left,right=line.split(" - ",1); a=left.split(); b=right.split(); mount=a[4].replace("\\040"," "); fstype=b[0]; source=b[1]
   if mount in seen or fstype in ("tmpfs","devtmpfs","proc","sysfs","cgroup","cgroup2","overlay"):continue
   seen.add(mount);rows.append((source,fstype,mount))
  except:pass
 return rows
def fs_usage():
 rows=[]
 for source,fstype,mount in mounts():
  try:
   s=os.statvfs(mount); total=s.f_blocks*s.f_frsize; avail=s.f_bavail*s.f_frsize
   if total:rows.append({"source":source,"type":fstype,"used":100*(total-avail)/total,"mount":mount})
  except:pass
 return rows
def inode_usage():
 rows=[]
 for source,_,mount in mounts():
  try:
   s=os.statvfs(mount)
   if s.f_files:rows.append({"source":source,"used":100*(s.f_files-s.f_favail)/s.f_files,"mount":mount})
  except:pass
 return rows
REDACT_ON=os.getenv("REDACT_SECRETS","true").lower() in ("1","true","yes")
_RE_SECRET=[
 re.compile(r"\b\d{6,12}:AA[\w-]{30,}"),                                  # Telegram bot token
 re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}"),             # GitHub token
 re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_-]{16,}"),                           # OpenAI 类密钥
 re.compile(r"\bAKIA[0-9A-Z]{12,}"),                                      # AWS access key
 re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), # JWT
 re.compile(r"(?i)\b(?:-{1,2})?(?:token|api[_-]?key|apikey|secret|password|passwd|pwd|access[_-]?key|auth[_-]?token|bot[_-]?token|private[_-]?key)\b(\s*[=:]\s*|\s+)(\"[^\"]+\"|'[^']+'|\S+)"),
]
def redact(s):
 """从取证输出中移除疑似密钥，避免报告经 Telegram 外发时泄露凭据。"""
 if not REDACT_ON or not s:return s
 out=s
 for i,rx in enumerate(_RE_SECRET):
  if i==len(_RE_SECRET)-1:out=rx.sub(lambda m:m.group(0)[:m.start(1)-m.start(0)]+m.group(1)+"[REDACTED]",out)
  else:out=rx.sub("[REDACTED]",out)
 return out
def container_of(p):
 """从 cgroup 解析容器 ID，并映射为容器名与镜像，便于直接定位服务。"""
 cid=""
 for tok in re.findall(r"(?:docker[-/]|libpod-|cri-containerd[-:])([0-9a-f]{12,64})",p.get("cgroup","") or ""):
  cid=tok;break
 if not cid:return {"id":"","name":"","image":""}
 short=cid[:12];info=DOCKER_MAP.get(short)
 if info is None and shutil.which("docker"):
  for line in command(["docker","ps","--no-trunc","--format","{{.ID}}\t{{.Names}}\t{{.Image}}"],8).splitlines():
   f=line.split("\t")
   if len(f)==3:DOCKER_MAP[f[0][:12]]={"name":f[1],"image":f[2]}
  info=DOCKER_MAP.get(short)
 return {"id":short,"name":(info or {}).get("name",""),"image":(info or {}).get("image","")}
DOCKER_MAP={}
AUTO_BUILD_MODE=os.getenv("AUTO_BUILD_MODE","false").lower() in ("1","true","yes")
BUILD_PATTERNS=[x.strip().lower() for x in os.getenv("BUILD_DETECT_CMDLINE","vite build,npm run build,npm ci,yarn build,pnpm build,webpack,next build,nuxt build").split(",") if x.strip()]
BUILD_CPU_MIN=max(1,env("BUILD_DETECT_CPU_MIN",40,float))
BUILD_EXIT_GRACE=max(10,env("BUILD_EXIT_GRACE_SECONDS",60,int))
def detect_build(s):
 """识别正在进行的前端/后端构建：命令行匹配且 CPU 占用显著。"""
 if not s.get("rates"):return None
 for pid,r in s["rates"].items():
  if pid==SELF or r["cpu_pct"]<BUILD_CPU_MIN:continue
  try:
   cmd=text(f"/proc/{pid}/cmdline",65536).replace("\0"," ").strip().lower()
  except Exception:continue
  if not cmd:continue
  for pat in BUILD_PATTERNS:
   if pat in cmd:return {"pid":pid,"cmd":cmd[:200],"cpu_pct":r["cpu_pct"],"pattern":pat}
 return None
def build_mode_cmd(action):
 """调用外部 vps-build-mode，失败不影响监控主流程。"""
 exe=shutil.which("vps-build-mode") or "/usr/local/bin/vps-build-mode"
 if not os.path.exists(exe):return False,"vps-build-mode 未安装"
 try:
  p=subprocess.run([exe,action],capture_output=True,text=True,timeout=60)
  return p.returncode==0,(p.stdout or p.stderr or "").strip()[:300]
 except Exception as e:return False,str(e)[:200]
def human(n):
 for u in ("B","KiB","MiB","GiB","TiB"):
  if abs(n)<1024:return f"{n:.1f}{u}"
  n/=1024
 return f"{n:.1f}PiB"
def enrich(pid,rate):
 base=f"/proc/{pid}"; status=text(base+"/status",65536); uid="?"
 for line in status.splitlines():
  if line.startswith("Uid:"):uid=line.split()[1];break
 def link(name):
  if not FULL:return "[disabled: full forensics consent required]"
  try:return os.readlink(base+"/"+name)
  except:return "[unavailable]"
 return {**rate,"pid":pid,"uid":uid,"comm":text(base+"/comm",4096).strip(),"cmd":text(base+"/cmdline",65536).replace("\0"," ").strip(),"exe":link("exe"),"cwd":link("cwd"),"cgroup":text(base+"/cgroup",65536).strip(),"status":status,"io":text(base+"/io",8192).strip(),"limits":text(base+"/limits",65536).strip()}

def snapshot(pc,pd,pp,dt,scan_proc=True,proc_dt=None):
 proc_dt=proc_dt or dt
 c=cpu_raw(); mem,swap,mi=mem_raw(); ds=disks_raw(); ps=procs_raw() if scan_proc else pp
 cpu=max(0,min(100,100*((c[0]-pc[0])-(c[1]-pc[1]))/max(1,c[0]-pc[0]))); disks=[]
 for n,v in ds.items():
  if n in pd:
   q=pd[n]; disks.append({"dev":n,"util":max(0,100*(v[4]-q[4])/(dt*1000)),"read_Bps":max(0,(v[1]-q[1])*512/dt),"write_Bps":max(0,(v[3]-q[3])*512/dt),"read_iops":max(0,(v[0]-q[0])/dt),"write_iops":max(0,(v[2]-q[2])/dt)})
 rates={}
 if scan_proc:
  for pid,v in ps.items():
   q=pp.get(pid)
   if q and v[0]==q[0]:rates[pid]={"read_Bps":max(0,v[1]-q[1])/proc_dt,"write_Bps":max(0,v[2]-q[2])/proc_dt,"cpu_pct":max(0,v[3]-q[3])/CLK/proc_dt*100,"rss":v[4],"rss_pct":100*v[4]/max(1,mi.get("MemTotal",1))}
 fs=fs_usage(); ino=inode_usage()
 return c,ds,ps,{"time":datetime.now().astimezone().isoformat(),"cpu":cpu,"mem":mem,"swap":swap,"meminfo":mi,"disks":disks,"rates":rates,"fs":fs,"inodes":ino}
EVIDENCE_CPU=max(1,env("EVIDENCE_CPU_MIN",50,float)); EVIDENCE_MEM=max(1,env("EVIDENCE_MEMORY_MIN",15,float))
EVIDENCE_IO=max(1,env("EVIDENCE_IO_MBPS_MIN",20,float))*1048576; EVIDENCE_TTL=max(60,env("EVIDENCE_TTL_SECONDS",900,int))
MEM_SUSTAIN=max(0,env("MEMORY_SUSTAIN_SECONDS",120,int))
_MEM_SINCE={}
def sustained(key,hit,now,need):
 """瞬时冲高不告警：仅当同一指标连续超限达到指定秒数才计入。"""
 if not hit:_MEM_SINCE.pop(key,None);return False
 t=_MEM_SINCE.setdefault(key,now)
 return (now-t)>=need
def reasons(s,now=None):
 r=[];now=now if now is not None else time.monotonic()
 if s["cpu"]>=CPU_LIMIT:r.append(f"CPU {s['cpu']:.1f}% ≥ {CPU_LIMIT:g}%")
 if sustained("mem",s["mem"]>=MEM_LIMIT,now,MEM_SUSTAIN):r.append(f"内存 {s['mem']:.1f}% ≥ {MEM_LIMIT:g}%（已持续 ≥{MEM_SUSTAIN}s）")
 if sustained("swap",s["swap"]>=SWAP_LIMIT and bool(s["meminfo"].get("SwapTotal",0)),now,MEM_SUSTAIN):r.append(f"Swap {s['swap']:.1f}% ≥ {SWAP_LIMIT:g}%（已持续 ≥{MEM_SUSTAIN}s）")
 hot=[d for d in s["disks"] if d["util"]>=IO_LIMIT or (READ_LIMIT and d["read_Bps"]>=READ_LIMIT) or (WRITE_LIMIT and d["write_Bps"]>=WRITE_LIMIT)]
 if hot:r.append("磁盘 I/O "+", ".join(f"{d['dev']} util={d['util']:.1f}% R={human(d['read_Bps'])}/s W={human(d['write_Bps'])}/s" for d in hot))
 bad=[x for x in s["fs"] if x["used"]>=FS_LIMIT]
 if bad:r.append("磁盘空间 "+", ".join(f"{x['mount']} {x['used']:.0f}%" for x in bad))
 bad=[x for x in s["inodes"] if x["used"]>=INODE_LIMIT]
 if bad:r.append("inode "+", ".join(f"{x['mount']} {x['used']:.0f}%" for x in bad))
 return r
def selected_processes(s):
 if not FULL:return []
 ids=set()
 for key in ("read_Bps","write_Bps","cpu_pct","rss"):
  ids.update(pid for pid,_ in sorted(s["rates"].items(),key=lambda x:x[1][key],reverse=True)[:TOPN])
 return [enrich(pid,s["rates"][pid]) for pid in ids if pid!=SELF]
def fd_lines(pid):
 if not FULL:return ["[disabled: full forensics consent required]"]
 out=[]
 try:
  with os.scandir(f"/proc/{pid}/fd") as it:
   for i,e in enumerate(it):
    if i>=MAX_FDS:break
    try:
     v=os.readlink(e.path)
     if v.startswith(("/","socket:","pipe:","anon_inode:")):out.append(f"{e.name} -> {v}")
    except:pass
 except:pass
 return out
def capture_evidence(s,now):
 """瞬时超限即抓取进程身份，避免短命进程（如 --rm 构建容器）退出后无法取证。"""
 out={}
 if not s.get("rates"):return out
 total=max(1,s["meminfo"].get("MemTotal",1))
 for pid,r in s["rates"].items():
  if pid==SELF:continue
  if not (r["cpu_pct"]>=EVIDENCE_CPU or r["rss_pct"]>=EVIDENCE_MEM
          or r["read_Bps"]>=EVIDENCE_IO or r["write_Bps"]>=EVIDENCE_IO):continue
  try:
   p=enrich(pid,r);c=container_of(p)
   out[pid]={"first_seen":now,"pid":pid,"uid":p.get("uid","?"),"comm":p.get("comm",""),
             "cmd":" ".join(redact(p.get("cmd","") or "").split())[:500],"exe":p.get("exe",""),"cwd":p.get("cwd",""),
             "container":c.get("name",""),"image":c.get("image",""),"cgroup":p.get("cgroup",""),
             "cpu_pct":r["cpu_pct"],"rss":r["rss"],"rss_pct":r["rss_pct"],
             "read_Bps":r["read_Bps"],"write_Bps":r["write_Bps"],"total_mem":total,
             "acted_by_monitor":""}
  except Exception:pass
 return out
def merge_evidence(store,new,now):
 """保留最早一次观测（第一手证据），同时更新峰值。"""
 for pid,e in new.items():
  old=store.get(pid)
  if old is None:store[pid]=e
  else:
   for k in ("cpu_pct","rss","rss_pct","read_Bps","write_Bps"):
    if e[k]>old[k]:old[k]=e[k]
   old["last_seen"]=now
 for pid in list(store):
  if now-store[pid].get("last_seen",store[pid]["first_seen"])>EVIDENCE_TTL:store.pop(pid,None)
 return store
def evidence_lines(store):
 if not store:return []
 rows=["","EARLY EVIDENCE (瞬时超限即抓取，不等告警线):"]
 for e in sorted(store.values(),key=lambda x:max(x["cpu_pct"],x["rss_pct"]),reverse=True)[:TOPN]:
  cur=proc_one(e["pid"]);live=bool(cur and proc_alive(e["pid"],cur[0]))
  act=e.get("acted_by_monitor","")
  if live:alive="存活（已被监控降级：%s）"%act if act else "存活"
  elif act:alive="已退出（监控处置：%s）"%act
  else:alive="已退出（非监控处置，退因未知）"
  rows+=["",f"PID {e['pid']} | {e['comm']} | UID {e['uid']} | {alive}",
         f"首次观测: {datetime.fromtimestamp(e['first_seen']).astimezone().isoformat()}",
         f"峰值: CPU={e['cpu_pct']:.1f}% RSS={human(e['rss'])}({e['rss_pct']:.1f}%) R={human(e['read_Bps'])}/s W={human(e['write_Bps'])}/s",
         f"命令: {e['cmd'] or '[kernel thread]'}",f"程序: {e['exe']}",f"工作目录: {e['cwd']}"]
  if e["container"]:rows.append(f"容器: {e['container']}")
  if e["image"]:rows.append(f"镜像: {e['image']}")
 return rows
def make_report(rs,s,evidence=None):
 now=datetime.now().astimezone(); pids=selected_processes(s); ss=command(["ss","-tunap"],10) if FULL else ""; lines=["VPS SENTINEL INCIDENT REPORT",f"Version: {VERSION}",f"Forensics mode: {'FULL (explicitly authorized)' if FULL else 'BASIC (no sensitive PID/fd/log collection)'}",f"Time: {now.isoformat()}",f"Host: {HOST}","Reasons: "+"; ".join(rs),f"CPU {s['cpu']:.1f}% | Memory {s['mem']:.1f}% | Swap {s['swap']:.1f}%","","BLOCK DEVICE SAMPLE:"]
 for d in sorted(s["disks"],key=lambda x:x["util"],reverse=True):lines.append(f"{d['dev']}: util={d['util']:.1f}% read={human(d['read_Bps'])}/s write={human(d['write_Bps'])}/s rIOPS={d['read_iops']:.1f} wIOPS={d['write_iops']:.1f}")
 lines += ["","TOP PROCESS SAMPLE:"]
 for key in ("read_Bps","write_Bps","cpu_pct","rss"):
  lines.append(f"\n-- top by {key} --")
  for p in sorted(pids,key=lambda x:x[key],reverse=True)[:TOPN]:lines.append(f"PID={p['pid']} UID={p['uid']} {p['comm']} CPU={p['cpu_pct']:.1f}% RSS={human(p['rss'])} R={human(p['read_Bps'])}/s W={human(p['write_Bps'])}/s CMD={p['cmd'][:500]}")
 lines += evidence_lines(evidence or {})
 lines += ["","PROCESS FORENSICS:"]
 for p in sorted(pids,key=lambda x:max(x["read_Bps"],x["write_Bps"],x["cpu_pct"]*1048576),reverse=True)[:TOPN]:
  net="\n".join(x for x in ss.splitlines() if f"pid={p['pid']}," in x)[:65536] or "[none/unavailable]"
  lines += ["",f"PID {p['pid']} | {p['comm']} | UID {p['uid']}",f"CPU={p['cpu_pct']:.1f}% RSS={human(p['rss'])} READ={human(p['read_Bps'])}/s WRITE={human(p['write_Bps'])}/s",f"CMD: {p['cmd'] or '[kernel thread]'}",f"EXE: {p['exe']}",f"CWD: {p['cwd']}",f"CGROUP:\n{p['cgroup']}",f"IO:\n{p['io']}",f"LIMITS:\n{p['limits']}",f"OPEN FILES (max {MAX_FDS}):\n"+("\n".join(fd_lines(p['pid'])) or "[none/unavailable]"),f"NETWORK:\n{net}",f"STATUS:\n{p['status']}"]
 sections=[("UPTIME/LOAD",["uptime"]),("MEMORY",["free","-h"]),("VMSTAT",["vmstat","1","3"]),("IOSTAT",["iostat","-xz","1","2"]),("PSI","cat /proc/pressure/cpu /proc/pressure/io /proc/pressure/memory 2>/dev/null"),("FILESYSTEM",["df","-hT"]),("INODES",["df","-ih"]),("BLOCK DEVICES",["lsblk","-o","NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,ROTA,MODEL"]),("MOUNTS",["findmnt"])]
 if FULL:sections += [("NETWORK SUMMARY","ss -s; ss -tunap 2>/dev/null | head -300"),("KERNEL/SYSTEM WARNINGS","dmesg -T 2>/dev/null | tail -200; journalctl -p warning --since '-15 min' --no-pager 2>/dev/null | tail -300"),("CONTAINERS","docker stats --no-stream 2>/dev/null; docker ps --no-trunc 2>/dev/null"),("FAILED SERVICES","systemctl --failed --no-pager 2>/dev/null")]
 for title,cmd in sections:lines += ["",title+":",command(cmd,15)]
 payload=redact("\n".join(lines))
 if len(payload.encode(errors="replace"))>MAX_REPORT:payload=payload.encode(errors="replace")[:MAX_REPORT].decode(errors="replace")+"\n[TRUNCATED: report safety limit reached]"
 out=REPORTS/f"incident-{now.strftime('%Y%m%d-%H%M%S')}.txt"; out.write_text(payload,errors="replace"); return out

def telegram(method,fields,file=None):
 if not TOKEN or not CHAT:return False,"Telegram 未配置"
 url=f"https://api.telegram.org/bot{TOKEN}/{method}"
 try:
  if file:
   b="----vpssentinel"+uuid.uuid4().hex; body=b""
   for k,v in fields.items():body+=f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
   data=file.read_bytes(); body+=f'--{b}\r\nContent-Disposition: form-data; name="document"; filename="{file.name}"\r\nContent-Type: text/plain\r\n\r\n'.encode()+data+f"\r\n--{b}--\r\n".encode(); req=urllib.request.Request(url,body,{"Content-Type":f"multipart/form-data; boundary={b}"})
  else:req=urllib.request.Request(url,urllib.parse.urlencode(fields).encode())
  with urllib.request.urlopen(req,timeout=30) as resp:
   obj=json.loads(resp.read());return obj.get("ok",False),obj.get("description","")
 except Exception as e:return False,str(e)
def common_fields():
 f={"chat_id":CHAT}
 if THREAD:f["message_thread_id"]=THREAD
 if SILENT:f["disable_notification"]="true"
 return f
def send_message(message):
 f=common_fields();f.update({"text":message,"parse_mode":"HTML"});return telegram("sendMessage",f)
def offender_block(s):
 """挑出当次异常的主要来源进程，输出可直接判断服务归属的摘要。"""
 if not s.get("rates"):return ""
 total=max(1,s["meminfo"].get("MemTotal",1))
 best=None
 for pid,r in s["rates"].items():
  if pid==SELF:continue
  score=max(r["rss_pct"],r["cpu_pct"],r["read_Bps"]/1048576,r["write_Bps"]/1048576)
  if best is None or score>best[0]:best=(score,pid,r)
 if not best:return ""
 _,pid,r=best;p=enrich(pid,r);c=container_of(p)
 cmd=redact(p.get("cmd","") or "")[:200]
 rows=[f"PID：{pid}",f"程序：{p.get('comm','')}",f"用户：UID {p.get('uid','?')}",
       f"内存：{human(r['rss'])}（宿主机总共 {human(total)}，占 {r['rss_pct']:.1f}%）",
       f"CPU：{r['cpu_pct']:.1f}%",f"磁盘：读 {human(r['read_Bps'])}/s 写 {human(r['write_Bps'])}/s",
       f"命令：{cmd or '[内核线程]'}"]
 if c["name"]:rows.append(f"容器：{c['name']}")
 if c["image"]:rows.append(f"镜像：{c['image']}")
 return "\n".join(rows)
def why_protected(e):
 """说明该进程为何不会被自动处置，便于用户判断是否需要人工介入。"""
 p={"pid":e["pid"],"comm":e.get("comm",""),"cmd":e.get("cmd",""),"exe":e.get("exe",""),"cgroup":e.get("cgroup","")}
 if e["pid"] in (0,1,SELF):return "系统关键进程"
 name=e.get("comm","");cmd=(e.get("cmd","") or "").lower()
 hit=[k for k in PROTECTED_CMD if k in cmd]
 if hit:return "命令豁免名单：%s"%hit[0].strip()
 if PROTECTED_CT:
  cn=(e.get("container","") or "").lower();im=(e.get("image","") or "").lower()
  if cn and cn in PROTECTED_CT:return "容器豁免名单：%s"%e["container"]
  if im and any(i in im for i in PROTECTED_CT):return "镜像豁免名单：%s"%e["image"]
 exe=os.path.basename(e.get("exe","") or "").strip()
 if name in PROTECTED or exe in PROTECTED:return "受保护程序名：%s"%(name or exe)
 if any(name.startswith(x) for x in ("kworker","migration","watchdog","rcu_","ksoftirqd")):return "内核线程"
 return "" if not protected(p) else "保护规则命中"
def advise(e,s):
 """给出可执行建议，避免告警只报数字、无法行动。"""
 tips=[]
 ct=e.get("container","")
 if ct:
  if e["cpu_pct"]>=70:tips.append(f"限制 CPU：sudo docker update --cpus 1 {ct}")
  if e["rss_pct"]>=30:tips.append(f"限制内存：sudo docker update --memory 512m --memory-swap 512m {ct}")
  if not tips:tips.append(f"查看日志：sudo docker logs --tail 100 {ct}")
 else:
  tips.append("非容器进程，请人工确认用途后再处理")
 if s.get("cpu",0)>=95:tips.append("构建期可先让路：sudo vps-build-mode enter")
 return tips
def evidence_block(store,s=None):
 """优先用最早抓到的身份信息，短命进程退出后仍可展示。"""
 if not store:return ""
 e=max(store.values(),key=lambda x:max(x["cpu_pct"],x["rss_pct"],x["read_Bps"]/1048576,x["write_Bps"]/1048576))
 rows=[f"PID：{e['pid']}",f"程序：{e['comm']}",f"用户：UID {e['uid']}",
       f"内存：{human(e['rss'])}（宿主机总共 {human(e['total_mem'])}，占 {e['rss_pct']:.1f}%）",
       f"CPU：{e['cpu_pct']:.1f}%",f"磁盘：读 {human(e['read_Bps'])}/s 写 {human(e['write_Bps'])}/s",
       f"命令：{e['cmd'] or '[内核线程]'}"]
 if e["container"]:rows.append(f"容器：{e['container']}")
 if e["image"]:rows.append(f"镜像：{e['image']}")
 rows.append(f"首次观测：{datetime.fromtimestamp(e['first_seen']).astimezone().strftime('%H:%M:%S')}")
 wp=why_protected(e)
 if wp:rows.append(f"⚠️ 不会自动处置（{wp}），需人工判断")
 if s is not None:
  for t in advise(e,s):rows.append(f"建议：{t}")
 return "\n".join(rows)
def send_alert(rs,path,s,evidence=None):
 head=f"🚨 {HOST}\n"+"\n".join(rs)+f"\nCPU {s['cpu']:.1f}%｜内存 {s['mem']:.1f}%｜Swap {s['swap']:.1f}%"
 blk=evidence_block(evidence or {},s) or offender_block(s)
 caption=head+("\n\n主要来源\n"+blk if blk else "")+"\n\n完整取证见附件"
 f=common_fields();f["caption"]=caption[:1024];ok,why=telegram("sendDocument",f,path)
 if not ok:
  body=f"🚨 <b>VPS 异常告警</b>\n主机：<code>{html.escape(HOST)}</code>\n{html.escape('; '.join(rs))}"
  if blk:body+="\n\n<b>主要来源</b>\n<code>"+html.escape(blk)+"</code>"
  body+=f"\n报告保存在：<code>{html.escape(str(path))}</code>\n附件发送失败：{html.escape(why)}"
  send_message(body)
 return ok,why
def proc_alive(pid,start):
 v=proc_one(pid);return bool(v and v[0]==start)
def protected(p):
 if p["pid"] in (0,1,SELF) or not p.get("cmd"):return True
 name=p.get("comm","");exe=os.path.basename(p.get("exe","")).strip();cmd=p.get("cmd","").lower()
 if any(k in cmd for k in PROTECTED_CMD):return True
 if PROTECTED_CT:
  c=container_of(p)
  if c.get("name") and c["name"].lower() in PROTECTED_CT:return True
  if c.get("image") and any(i in c["image"].lower() for i in PROTECTED_CT):return True
 return name in PROTECTED or exe in PROTECTED or any(name.startswith(x) for x in ("kworker","migration","watchdog","rcu_","ksoftirqd"))
def action_candidate(s,rs):
 if AUTO_ACTION=="none" or not AUTO_CONSENT or not FULL:return None,None
 enabled=[]
 if AUTO_CPU and s["cpu"]>=CPU_LIMIT:enabled.append(("cpu_pct",PROC_CPU_MIN,"CPU"))
 if AUTO_MEM and s["mem"]>=MEM_LIMIT:enabled.append(("rss_pct",PROC_MEM_MIN,"内存"))
 disk_hot=any(d["util"]>=IO_LIMIT for d in s["disks"])
 if AUTO_READ and disk_hot:enabled.append(("read_Bps",PROC_READ_MIN,"磁盘读取"))
 if AUTO_WRITE and disk_hot:enabled.append(("write_Bps",PROC_WRITE_MIN,"磁盘写入"))
 best=None
 for key,minimum,kind in enabled:
  if not s["rates"]:continue
  pid,rate=max(s["rates"].items(),key=lambda x:x[1][key])
  if rate[key] < minimum:continue
  p=enrich(pid,rate);p["starttime"]=proc_one(pid)[0] if proc_one(pid) else -1
  if protected(p):continue
  score=rate[key]/max(minimum,1)
  if best is None or score>best[0]:best=(score,p,kind)
 return (best[1],best[2]) if best else (None,None)
def system_metrics(s):
 disks="; ".join(f"{d['dev']} util={d['util']:.1f}% R={human(d['read_Bps'])}/s W={human(d['write_Bps'])}/s" for d in sorted(s["disks"],key=lambda x:x["util"],reverse=True)[:4]) or "无块设备数据"
 return f"CPU={s['cpu']:.1f}% 内存={s['mem']:.1f}% Swap={s['swap']:.1f}% 磁盘=[{disks}]"
def log_action(row):
 with ACTION_LOG.open("a") as f:f.write(json.dumps(row,ensure_ascii=False,separators=(",",":"))+"\n")
def recent_actions(now):
 n=0
 try:
  with ACTION_LOG.open("rb") as f:
   f.seek(max(0,ACTION_LOG.stat().st_size-1048576));lines=f.read().decode(errors="replace").splitlines()
  for line in lines:
   try:
    if now-float(json.loads(line).get("epoch",0))<3600:n+=1
   except:pass
 except:pass
 return n
def post_metrics():
 c0=cpu_raw();d0=disks_raw();time.sleep(1);c1=cpu_raw();d1=disks_raw();mem,swap,_=mem_raw();cpu=max(0,min(100,100*((c1[0]-c0[0])-(c1[1]-c0[1]))/max(1,c1[0]-c0[0])));ds=[]
 for n,v in d1.items():
  if n in d0:
   q=d0[n];ds.append(f"{n} util={max(0,v[4]-q[4])/10:.1f}% R={human(max(0,v[1]-q[1])*512)}/s W={human(max(0,v[3]-q[3])*512)}/s")
 return f"CPU={cpu:.1f}% 内存={mem:.1f}% Swap={swap:.1f}% 磁盘=[{'; '.join(ds[:4]) or '无块设备数据'}]"
def throttle(p,kind):
 """对进程降级而非终止：降低 CPU/IO 优先级，必要时冻结。可恢复，不丢数据。"""
 pid=p["pid"];done=[]
 try:os.setpriority(os.PRIO_PROCESS,pid,19);done.append("nice=19")
 except Exception:pass
 if shutil.which("ionice"):
  r=command(["ionice","-c","3","-p",str(pid)],5)
  if not r.startswith("[unavailable"):done.append("ionice=idle")
 if THROTTLE_FREEZE:
  try:os.kill(pid,19);done.append("SIGSTOP冻结")
  except Exception as e:done.append(f"冻结失败:{e}")
 return ",".join(done) or "无可用降级手段"
def act_on_process(p,kind,s,stage="throttle",report=None,evidence=None):
 now=time.time();pid=p["pid"];start=p["starttime"]
 if protected(p):return False,"进程在保护/豁免名单中，已放行"
 if recent_actions(now)>=ACTION_HOURLY:return False,"每小时动作上限已触发"
 if not proc_alive(pid,start):return False,"PID 已退出或被复用"
 before=system_metrics(s);cmd=redact(p.get("cmd","") or "")[:500];cinfo=container_of(p);result=""
 if stage=="throttle":
  action="降级(限速)";result=throttle(p,kind)
 else:
  action="SIGTERM"
  try:
   os.kill(pid,18)
   os.kill(pid,15);deadline=time.monotonic()+ACTION_GRACE
   while time.monotonic()<deadline and proc_alive(pid,start):time.sleep(.5)
   if proc_alive(pid,start):
    if AUTO_KILL and AUTO_KILL_CONSENT:os.kill(pid,9);action="SIGTERM→SIGKILL";result="SIGKILL 已发送"
    else:result="宽限期后仍存活；未授权 SIGKILL，已停止处置"
   else:result="进程已退出"
  except Exception as e:result=f"操作失败：{e}"
 after=post_metrics()
 row={"epoch":now,"time":datetime.now().astimezone().isoformat(),"host":HOST,"trigger":kind,"stage":stage,"pid":pid,"starttime":start,"comm":p.get("comm"),"uid":p.get("uid"),"cmd":cmd,"exe":p.get("exe"),"container":cinfo.get("name",""),"image":cinfo.get("image",""),"action":action,"result":result,"before":before,"after":after,"process":{"cpu_pct":p["cpu_pct"],"rss":p["rss"],"rss_pct":p["rss_pct"],"read_Bps":p["read_Bps"],"write_Bps":p["write_Bps"]}}
 log_action(row)
 if evidence is not None and pid in evidence:evidence[pid]["acted_by_monitor"]=action
 if report is None:
  try:report=make_report([f"自动处置（{kind}）"],s)
  except Exception:report=None
 tip="\n提示：进程已被限速/冻结，未终止。恢复请执行 kill -CONT %d"%pid if stage=="throttle" else ""
 total=max(1,s["meminfo"].get("MemTotal",1)) if s.get("meminfo") else 1
 svc=f"\n容器：<code>{html.escape(cinfo['name'])}</code>" if cinfo.get("name") else ""
 svc+=f"\n镜像：<code>{html.escape(cinfo['image'])}</code>" if cinfo.get("image") else ""
 msg=(f"🔴 <b>VPS 自动处置记录</b>\n主机：<code>{html.escape(HOST)}</code>\n时间：{html.escape(row['time'])}\n触发：{kind}\n动作：<b>{action}</b>"
      f"\nPID：<code>{pid}</code>\n程序：<code>{html.escape(p.get('comm',''))}</code>\n用户：UID {html.escape(str(p.get('uid','?')))}"
      f"\n内存：{human(p['rss'])}（宿主机总共 {human(total)}，占 {p['rss_pct']:.1f}%）"
      f"\nCPU：{p['cpu_pct']:.1f}%\n磁盘：读 {human(p['read_Bps'])}/s 写 {human(p['write_Bps'])}/s"
      f"\n命令：<code>{html.escape(cmd[:300])}</code>{svc}"
      f"\n处置前：{html.escape(before)}\n结果：{html.escape(result)}\n处置后：{html.escape(after)}{tip}\n审计：<code>{ACTION_LOG}</code>")
 sent=False
 if report:
  plain=re.sub(r"<[^>]+>","",msg).replace("&lt;","<").replace("&gt;",">").replace("&amp;","&")
  f=common_fields();f["caption"]=plain[:1024];sent,_=telegram("sendDocument",f,report)
 if not sent:send_message(msg+("\n报告：<code>%s</code>"%report if report else ""))
 try:
  if ACTION_LOG.stat().st_size>ACTION_LOG_WARN:send_message(f"⚠️ 自动处置审计日志已超过 100MiB：<code>{ACTION_LOG}</code>。请人工决定是否归档或删除；程序不会自动清理。")
 except:pass
 return True,result

def cleanup():
 now=time.time()
 for d,days in ((REPORTS,REPORT_DAYS),(METRICS,METRICS_DAYS)):
  for f in d.glob("*"):
   try:
    if f.is_file() and now-f.stat().st_mtime>days*86400:f.unlink()
   except:pass
 files=sorted(REPORTS.glob("incident-*.txt"),key=lambda x:x.stat().st_mtime,reverse=True)
 for f in files[REPORT_MAX:]:
  try:f.unlink()
  except:pass
def metric(s):
 if not METRICS_INTERVAL:return
 p=METRICS/(datetime.now().strftime("%Y-%m-%d")+".jsonl")
 row={"time":s["time"],"host":HOST,"cpu":round(s["cpu"],2),"memory":round(s["mem"],2),"swap":round(s["swap"],2),"disks":s["disks"],"filesystems":s["fs"]}
 with p.open("a") as f:f.write(json.dumps(row,separators=(",",":"))+"\n")
def self_rss():
 try:
  for line in text("/proc/self/status",8192).splitlines():
   if line.startswith("VmRSS:"):return int(line.split()[1])*1024
 except:pass
 return 0
def audit_self(elapsed):
 rss=self_rss()
 if rss>SELF_RSS_MAX:
  print(f"SELF-AUDIT FATAL: RSS {human(rss)} exceeds {human(SELF_RSS_MAX)}; exiting for external supervisor",file=sys.stderr,flush=True);raise SystemExit(70)
 if elapsed>SAMPLE_TIMEOUT:print(f"SELF-AUDIT WARNING: sample took {elapsed:.1f}s > {SAMPLE_TIMEOUT:.1f}s",file=sys.stderr,flush=True)
def config_check():
 errors=[]
 for k,v in (("MONITOR_INTERVAL",INTERVAL),("CPU_THRESHOLD",CPU_LIMIT),("MEMORY_THRESHOLD",MEM_LIMIT),("DISK_IO_THRESHOLD",IO_LIMIT)):
  if v<=0:errors.append(f"{k} 必须大于 0")
 if bool(TOKEN)!=bool(CHAT):errors.append("TG_BOT_TOKEN 与 TG_CHAT_ID 必须同时配置")
 if MODE not in ("basic","full"):errors.append("FORENSICS_MODE 只能是 basic 或 full")
 if MODE=="full" and not CONSENT:errors.append("完整取证模式未获授权：必须由用户审阅 SECURITY.md 后明确设置 FORENSICS_CONSENT=YES")
 if os.geteuid()!=0 and FULL:errors.append("完整取证模式需要 root；否则无法可靠读取其他用户进程")
 if AUTO_ACTION not in ("none","terminate"):errors.append("AUTO_ACTION 只能是 none 或 terminate")
 if AUTO_ACTION=="terminate":
  if not AUTO_CONSENT:errors.append("自动处置未授权：AUTO_ACTION_CONSENT 必须由交互授权写为 YES")
  if not FULL:errors.append("自动处置需要先授权 FULL 进程取证模式")
  if not any((AUTO_CPU,AUTO_MEM,AUTO_READ,AUTO_WRITE)):errors.append("自动处置至少授权一种异常类别")
  if not TOKEN or not CHAT:errors.append("自动处置必须配置 Telegram，确保每次动作可通知")
 if AUTO_KILL and not AUTO_KILL_CONSENT:errors.append("启用 SIGKILL 必须单独设置 AUTO_ACTION_SIGKILL_CONSENT=YES")
 print(f"VPS Monitor {VERSION}")
 print(f"主机：{HOST}")
 print(f"数据目录：{DATA}")
 print(f"取证模式：{MODE}")
 print(f"FULL 授权：{'是' if CONSENT else '否'}")
 print(f"自动处置：{AUTO_ACTION}")
 print(f"自动处置授权：{'是' if AUTO_CONSENT else '否'}")
 print(f"CPU 自动处置：{'是' if AUTO_CPU else '否'}")
 print(f"内存自动处置：{'是' if AUTO_MEM else '否'}")
 print(f"磁盘读取自动处置：{'是' if AUTO_READ else '否'}")
 print(f"磁盘写入自动处置：{'是' if AUTO_WRITE else '否'}")
 print(f"SIGKILL：{'是' if AUTO_KILL and AUTO_KILL_CONSENT else '否'}")
 print(f"RSS 退出线：{human(SELF_RSS_MAX)}")
 print(f"报告上限：{human(MAX_REPORT)}")
 print(f"采样超时线：{SAMPLE_TIMEOUT} 秒")
 print(f"整机采样间隔：{INTERVAL} 秒")
 print(f"进程采样间隔：{PROC_INTERVAL} 秒")
 print(f"CPU 阈值：{CPU_LIMIT}%")
 print(f"内存阈值：{MEM_LIMIT}%")
 print(f"Swap 阈值：{SWAP_LIMIT}%")
 print(f"磁盘 I/O 阈值：{IO_LIMIT}%")
 print(f"磁盘空间阈值：{FS_LIMIT}%")
 print(f"Telegram：{'已配置' if TOKEN and CHAT else '未配置'}")
 if errors:
  print("ERROR: "+"; ".join(errors),file=sys.stderr);return 1
 return 0
def main():
 print(f"VPS Sentinel {VERSION} started host={HOST} pid={SELF} interval={INTERVAL}s",flush=True); cleanup(); pc=cpu_raw();pd=disks_raw();pp=procs_raw() if FULL else {};last=time.monotonic();last_proc=last;last_metric=0;bad=good=0;active=False;last_alert=0;candidate_key=None;candidate_hits=0;pending_report=None;evidence={};build_active=False;build_gone=0
 while True:
  target=last+INTERVAL;time.sleep(max(0,target-time.monotonic()));now=time.monotonic();dt=max(.1,now-last);scan=FULL and now-last_proc>=PROC_INTERVAL*.95
  try:
   nc,nd,np,s=snapshot(pc,pd,pp,dt,scan,now-last_proc if scan else dt);pc,pd=nc,nd
   audit_self(time.monotonic()-now)
   if scan:pp=np;last_proc=now
   rs=reasons(s,now);pending_report=None
   merge_evidence(evidence,capture_evidence(s,time.time()),time.time())
   if AUTO_BUILD_MODE:
    b=detect_build(s)
    if b and not build_active:
     ok,out=build_mode_cmd("enter")
     if ok:
      build_active=True;build_gone=0
      print(f"BUILD_MODE enter pattern={b['pattern']} pid={b['pid']} cpu={b['cpu_pct']:.1f}%",flush=True)
      send_message(f"🔧 <b>检测到构建，已自动让路</b>\n主机：<code>{html.escape(HOST)}</code>\n匹配：<code>{html.escape(b['pattern'])}</code>\nPID：{b['pid']}｜CPU {b['cpu_pct']:.1f}%\n已临时限速其他容器，构建结束后自动恢复。")
     else:print(f"BUILD_MODE enter failed: {out}",flush=True)
    elif build_active:
     if b:build_gone=0
     else:
      build_gone+=1
      if build_gone*INTERVAL>=BUILD_EXIT_GRACE:
       ok,out=build_mode_cmd("exit")
       build_active=False;build_gone=0
       print(f"BUILD_MODE exit ok={ok} {out}",flush=True)
       if ok:send_message(f"✅ <b>构建结束，已恢复原配额</b>\n主机：<code>{html.escape(HOST)}</code>")
   if METRICS_INTERVAL and now-last_metric>=METRICS_INTERVAL:metric(s);last_metric=now
   p,kind=action_candidate(s,rs)
   if p:
    key=(p["pid"],p["starttime"],kind)
    if key==candidate_key:candidate_hits+=1
    else:candidate_key=key;candidate_hits=1
    if candidate_hits>=ACTION_CONSEC:
     stage="throttle" if (THROTTLE_FIRST and candidate_hits<ACTION_CONSEC+ESCALATE) else "terminate"
     shared=make_report(rs or [f"自动处置（{kind}）"],s,evidence)
     acted,result=act_on_process(p,kind,s,stage,shared,evidence);print(f"AUTO_ACTION pid={p['pid']} kind={kind} stage={stage} acted={acted} result={result}",flush=True)
     if acted:pending_report=shared
     if stage=="terminate" or not acted:candidate_key=None;candidate_hits=0
   else:candidate_key=None;candidate_hits=0
   if rs:
    bad+=1;good=0
    if bad>=CONSEC and (not active or time.time()-last_alert>=COOLDOWN):
     path=pending_report or make_report(rs,s,evidence);ok,why=send_alert(rs,path,s,evidence);print(f"ALERT {'; '.join(rs)} report={path} telegram={ok} {why}",flush=True);active=True;last_alert=time.time();cleanup()
   else:
    bad=0;good+=1
    if active and good>=RECOVERY:send_message(f"✅ <b>VPS 已恢复</b>\n主机：<code>{html.escape(HOST)}</code>\nCPU {s['cpu']:.1f}%｜内存 {s['mem']:.1f}%｜Swap {s['swap']:.1f}%");active=False;print("RECOVERED",flush=True)
  except Exception:traceback.print_exc()
  last=now

def cli():
 p=argparse.ArgumentParser(description="VPS Sentinel resource monitor");p.add_argument("command",nargs="?",choices=("run","check","test-telegram","version"),default="run");a=p.parse_args()
 if a.command=="version":print(VERSION);return 0
 if a.command=="check":return config_check()
 if a.command=="test-telegram":
  ok,why=send_message(f"✅ <b>VPS Sentinel 通知测试成功</b>\n主机：<code>{html.escape(HOST)}</code>\n版本：<code>{VERSION}</code>");print("success" if ok else f"failed: {why}");return 0 if ok else 1
 main();return 0
if __name__=="__main__":raise SystemExit(cli())
