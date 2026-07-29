#!/usr/bin/env python3
"""VPS Sentinel — dependency-free Linux resource monitor and incident collector."""
import argparse, html, json, os, resource, shutil, socket, subprocess, sys, time, traceback, urllib.parse, urllib.request, uuid
from collections import deque
from datetime import datetime
from pathlib import Path

VERSION="2.0.2"
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
def fs_usage():
 rows=[]
 try:
  for line in command(["df","-PT","-x","tmpfs","-x","devtmpfs"]).splitlines()[1:]:
   p=line.split()
   if len(p)>=7:rows.append({"source":p[0],"type":p[1],"used":float(p[5][:-1]),"mount":" ".join(p[6:])})
 except:pass
 return rows
def inode_usage():
 rows=[]
 try:
  for line in command(["df","-Pi","-x","tmpfs","-x","devtmpfs"]).splitlines()[1:]:
   p=line.split()
   if len(p)>=6 and p[4]!="-":rows.append({"source":p[0],"used":float(p[4][:-1]),"mount":" ".join(p[5:])})
 except:pass
 return rows
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
def reasons(s):
 r=[]
 if s["cpu"]>=CPU_LIMIT:r.append(f"CPU {s['cpu']:.1f}% ≥ {CPU_LIMIT:g}%")
 if s["mem"]>=MEM_LIMIT:r.append(f"内存 {s['mem']:.1f}% ≥ {MEM_LIMIT:g}%")
 if s["swap"]>=SWAP_LIMIT and s["meminfo"].get("SwapTotal",0):r.append(f"Swap {s['swap']:.1f}% ≥ {SWAP_LIMIT:g}%")
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
def make_report(rs,s):
 now=datetime.now().astimezone(); pids=selected_processes(s); ss=command(["ss","-tunap"],10) if FULL else ""; lines=["VPS SENTINEL INCIDENT REPORT",f"Version: {VERSION}",f"Forensics mode: {'FULL (explicitly authorized)' if FULL else 'BASIC (no sensitive PID/fd/log collection)'}",f"Time: {now.isoformat()}",f"Host: {HOST}","Reasons: "+"; ".join(rs),f"CPU {s['cpu']:.1f}% | Memory {s['mem']:.1f}% | Swap {s['swap']:.1f}%","","BLOCK DEVICE SAMPLE:"]
 for d in sorted(s["disks"],key=lambda x:x["util"],reverse=True):lines.append(f"{d['dev']}: util={d['util']:.1f}% read={human(d['read_Bps'])}/s write={human(d['write_Bps'])}/s rIOPS={d['read_iops']:.1f} wIOPS={d['write_iops']:.1f}")
 lines += ["","TOP PROCESS SAMPLE:"]
 for key in ("read_Bps","write_Bps","cpu_pct","rss"):
  lines.append(f"\n-- top by {key} --")
  for p in sorted(pids,key=lambda x:x[key],reverse=True)[:TOPN]:lines.append(f"PID={p['pid']} UID={p['uid']} {p['comm']} CPU={p['cpu_pct']:.1f}% RSS={human(p['rss'])} R={human(p['read_Bps'])}/s W={human(p['write_Bps'])}/s CMD={p['cmd'][:500]}")
 lines += ["","PROCESS FORENSICS:"]
 for p in sorted(pids,key=lambda x:max(x["read_Bps"],x["write_Bps"],x["cpu_pct"]*1048576),reverse=True)[:TOPN]:
  net="\n".join(x for x in ss.splitlines() if f"pid={p['pid']}," in x)[:65536] or "[none/unavailable]"
  lines += ["",f"PID {p['pid']} | {p['comm']} | UID {p['uid']}",f"CPU={p['cpu_pct']:.1f}% RSS={human(p['rss'])} READ={human(p['read_Bps'])}/s WRITE={human(p['write_Bps'])}/s",f"CMD: {p['cmd'] or '[kernel thread]'}",f"EXE: {p['exe']}",f"CWD: {p['cwd']}",f"CGROUP:\n{p['cgroup']}",f"IO:\n{p['io']}",f"LIMITS:\n{p['limits']}",f"OPEN FILES (max {MAX_FDS}):\n"+("\n".join(fd_lines(p['pid'])) or "[none/unavailable]"),f"NETWORK:\n{net}",f"STATUS:\n{p['status']}"]
 sections=[("UPTIME/LOAD",["uptime"]),("MEMORY",["free","-h"]),("VMSTAT",["vmstat","1","3"]),("IOSTAT",["iostat","-xz","1","2"]),("PSI","cat /proc/pressure/cpu /proc/pressure/io /proc/pressure/memory 2>/dev/null"),("FILESYSTEM",["df","-hT"]),("INODES",["df","-ih"]),("BLOCK DEVICES",["lsblk","-o","NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,ROTA,MODEL"]),("MOUNTS",["findmnt"])]
 if FULL:sections += [("NETWORK SUMMARY","ss -s; ss -tunap 2>/dev/null | head -300"),("KERNEL/SYSTEM WARNINGS","dmesg -T 2>/dev/null | tail -200; journalctl -p warning --since '-15 min' --no-pager 2>/dev/null | tail -300"),("CONTAINERS","docker stats --no-stream 2>/dev/null; docker ps --no-trunc 2>/dev/null"),("FAILED SERVICES","systemctl --failed --no-pager 2>/dev/null")]
 for title,cmd in sections:lines += ["",title+":",command(cmd,15)]
 payload="\n".join(lines)
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
def send_alert(rs,path,s):
 caption=f"🚨 {HOST}\n"+"\n".join(rs)+f"\nCPU {s['cpu']:.1f}%｜内存 {s['mem']:.1f}%｜Swap {s['swap']:.1f}%\n完整取证见附件"
 f=common_fields();f["caption"]=caption[:1024];ok,why=telegram("sendDocument",f,path)
 if not ok:send_message(f"🚨 <b>VPS 异常告警</b>\n主机：<code>{html.escape(HOST)}</code>\n{html.escape('; '.join(rs))}\n报告保存在：<code>{html.escape(str(path))}</code>\n附件发送失败：{html.escape(why)}")
 return ok,why
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
 print(f"VPS Sentinel {VERSION}\nHost: {HOST}\nData: {DATA}\nMode: {MODE}; explicit consent: {'yes' if CONSENT else 'no'}\nSelf budget: RSS={human(SELF_RSS_MAX)} report={human(MAX_REPORT)} sample_timeout={SAMPLE_TIMEOUT}s\nInterval: {INTERVAL}s; process scan: {PROC_INTERVAL}s\nThresholds: CPU={CPU_LIMIT}% MEM={MEM_LIMIT}% SWAP={SWAP_LIMIT}% IO={IO_LIMIT}% FS={FS_LIMIT}%\nTelegram: {'configured' if TOKEN and CHAT else 'not configured'}")
 if errors:
  print("ERROR: "+"; ".join(errors),file=sys.stderr);return 1
 return 0
def main():
 print(f"VPS Sentinel {VERSION} started host={HOST} pid={SELF} interval={INTERVAL}s",flush=True); cleanup(); pc=cpu_raw();pd=disks_raw();pp=procs_raw() if FULL else {};last=time.monotonic();last_proc=last;last_metric=0;bad=good=0;active=False;last_alert=0
 while True:
  target=last+INTERVAL;time.sleep(max(0,target-time.monotonic()));now=time.monotonic();dt=max(.1,now-last);scan=FULL and now-last_proc>=PROC_INTERVAL*.95
  try:
   nc,nd,np,s=snapshot(pc,pd,pp,dt,scan,now-last_proc if scan else dt);pc,pd=nc,nd
   audit_self(time.monotonic()-now)
   if scan:pp=np;last_proc=now
   rs=reasons(s)
   if METRICS_INTERVAL and now-last_metric>=METRICS_INTERVAL:metric(s);last_metric=now
   if rs:
    bad+=1;good=0
    if bad>=CONSEC and (not active or time.time()-last_alert>=COOLDOWN):
     path=make_report(rs,s);ok,why=send_alert(rs,path,s);print(f"ALERT {'; '.join(rs)} report={path} telegram={ok} {why}",flush=True);active=True;last_alert=time.time();cleanup()
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
