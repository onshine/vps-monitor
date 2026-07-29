import importlib.util, os, tempfile
os.environ.update({"MONITOR_DATA_DIR":tempfile.mkdtemp(),"FORENSICS_MODE":"basic","FORENSICS_CONSENT":"NO"})
s=importlib.util.spec_from_file_location("monitor","vps_monitor.py");m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
t,i=m.cpu_raw();assert t>=i>=0
mem,swap,info=m.mem_raw();assert 0<=mem<=100 and 0<=swap<=100 and info["MemTotal"]>0
assert isinstance(m.disks_raw(),dict) and isinstance(m.procs_raw(),dict)
assert m.FULL is False and m.selected_processes({"rates":{}})==[]
assert m.config_check()==0
print("all tests passed")
