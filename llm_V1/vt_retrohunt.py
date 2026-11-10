"""vt_retrohunt.py - VT Retrohunt API client + FP analysis + IOC validation."""
from __future__ import annotations
import json,logging,os,re,shutil,subprocess,time
from dataclasses import dataclass
from datetime import datetime,timezone
from typing import Any,Dict,List,Optional,Tuple
import requests

_SD=os.path.dirname(os.path.abspath(__file__))
_VT="https://www.virustotal.com/api/v3"
def _now():return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

@dataclass
class VTKeyInfo:
    name:str;key:str;active_jobs:int=0

def load_all_premium_keys()->List[VTKeyInfo]:
    try:import yaml
    except ImportError:return[]
    p=os.path.join(os.path.dirname(_SD),"vt_apk_downloader","config.yaml")
    if not os.path.isfile(p):return[]
    try:
        with open(p,"r",encoding="utf-8") as f:cfg=yaml.safe_load(f)
        ks=[]
        for e in cfg.get("api",{}).get("keys",[]):
            if e.get("tier")=="premium" and e.get("key"):
                ks.append(VTKeyInfo(name=e.get("name",f"p{len(ks)+1}"),key=str(e["key"])))
        return ks
    except Exception:return[]

def pick_best_key(keys,max_jobs=3)->Optional[VTKeyInfo]:
    el=[k for k in keys if k.active_jobs<max_jobs]
    return min(el,key=lambda k:k.active_jobs) if el else None

def create_retrohunt_job(rule,key,log,*,corpus="main",days=90)->Optional[str]:
    now=int(time.time())
    body={"data":{"type":"retrohunt_job","attributes":{"rules":rule,"corpus":corpus,"time_range":{"start":now-days*86400,"end":now}}}}
    try:
        r=requests.post(f"{_VT}/intelligence/retrohunt_jobs",headers={"x-apikey":key,"Content-Type":"application/json"},json=body,timeout=30)
        if r.status_code==429:log.warning("[rh] rate-limited");return None
        if not r.ok:log.warning("[rh] create HTTP %d: %s",r.status_code,r.text[:200]);return None
        jid=r.json().get("data",{}).get("id","")
        log.info("[rh] job created: %s corpus=%s",jid,corpus);return jid or None
    except Exception as e:log.error("[rh] create err: %s",e);return None

def poll_retrohunt_job(jid,key,log,*,interval=120,timeout=14400)->Dict[str,Any]:
    t0=time.time()
    while True:
        if time.time()-t0>timeout:
            log.warning("[rh] poll timeout %s",jid)
            return{"status":"timeout","progress":0,"num_matches":0,"finished":False}
        try:
            r=requests.get(f"{_VT}/intelligence/retrohunt_jobs/{jid}",headers={"x-apikey":key},timeout=30)
            if r.status_code==429:time.sleep(interval);continue
            if not r.ok:time.sleep(interval);continue
            a=r.json().get("data",{}).get("attributes",{})
            s=a.get("status","");p=float(a.get("progress",0));n=int(a.get("num_matches",0))
            log.info("[rh] %s status=%s %.0f%% matches=%d",jid,s,p*100,n)
            if s in("finished","completed"):return{"status":"finished","progress":100.0,"num_matches":n,"finished":True}
            if s in("aborted","error"):return{"status":s,"progress":p*100,"num_matches":n,"finished":True}
        except Exception as e:log.warning("[rh] poll err: %s",e)
        time.sleep(interval)

def get_matching_files(jid,key,log,*,limit=300)->List[Dict[str,Any]]:
    ms=[];cur=None
    while True:
        pm={"limit":min(limit,40)}
        if cur:pm["cursor"]=cur
        try:
            r=requests.get(f"{_VT}/intelligence/retrohunt_jobs/{jid}/matching_files",headers={"x-apikey":key},params=pm,timeout=30)
            if r.status_code==429:time.sleep(15);continue
            if not r.ok:break
            d=r.json()
            for it in d.get("data",[]):
                a=it.get("attributes",{});st=a.get("last_analysis_stats",{})
                ms.append({"sha256":a.get("sha256") or it.get("id",""),"malicious":int(st.get("malicious",0)),
                    "suspicious":int(st.get("suspicious",0)),"type_tag":a.get("type_tag",""),
                    "meaningful_name":a.get("meaningful_name",""),"size":int(a.get("size",0)),
                    "popular_threat":a.get("popular_threat_classification",{}).get("suggested_threat_label","")})
            nx=d.get("links",{}).get("next")
            if not nx or len(ms)>=limit:break
            cur=str(nx).split("cursor=")[-1].split("&")[0] if "cursor=" in str(nx) else None
            if not cur:break
        except Exception as e:log.warning("[rh] match err: %s",e);break
    log.info("[rh] %d matches for %s",len(ms),jid);return ms

@dataclass
class FPClassification:
    sha256:str;malicious_count:int;is_potential_fp:bool;has_malicious_parent:bool
    is_suspicious_fp:bool;is_confirmed_fp:bool;reason:str=""

def _check_parents(sha,key,log)->bool:
    for rel in("compressed_parents","execution_parents"):
        try:
            r=requests.get(f"{_VT}/files/{sha}/{rel}",headers={"x-apikey":key},params={"limit":10},timeout=20)
            if r.status_code==429:time.sleep(15);continue
            if not r.ok:continue
            for it in r.json().get("data",[]):
                if int(it.get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0))>=5:return True
        except Exception:continue
    return False

def _check_relations_clean(sha,key,log)->Tuple[bool,str]:
    sigs=[]
    for rel in("contacted_domains","contacted_ips"):
        try:
            r=requests.get(f"{_VT}/files/{sha}/{rel}",headers={"x-apikey":key},params={"limit":20},timeout=20)
            if r.status_code==429:time.sleep(15);continue
            if not r.ok:continue
            for it in r.json().get("data",[]):
                mal=int(it.get("attributes",{}).get("last_analysis_stats",{}).get("malicious",0))
                if mal>=3:sigs.append(f"{rel}:{it.get('id','?')} mal={mal}")
        except Exception:continue
    return(True,"clean") if not sigs else(False,"; ".join(sigs))

def classify_matches(matches,key,log)->Tuple[List[FPClassification],int,int]:
    res=[];cfp=0;sfp=0
    for m in matches:
        sha=m["sha256"];mal=m.get("malicious",0)
        if mal>0:res.append(FPClassification(sha,mal,False,False,False,False,f"tp:{mal}"));continue
        log.info("[fp] potential FP: %s",sha[:16])
        if _check_parents(sha,key,log):
            sfp+=1;res.append(FPClassification(sha,0,True,True,True,False,"sus_fp:mal_parent"));continue
        clean,reason=_check_relations_clean(sha,key,log)
        if clean:
            cfp+=1;res.append(FPClassification(sha,0,True,False,False,True,f"confirmed_fp:{reason}"))
        else:
            sfp+=1;res.append(FPClassification(sha,0,True,False,True,False,f"sus_fp:{reason}"))
    log.info("[fp] %d total: %d TP, %d sus, %d confirmed",len(res),sum(1 for r in res if not r.is_potential_fp),sfp,cfp)
    return res,cfp,sfp

def download_sample(sha,key,dest_dir,log)->Optional[str]:
    os.makedirs(dest_dir,exist_ok=True);dest=os.path.join(dest_dir,sha)
    if os.path.isfile(dest):return dest
    try:
        r=requests.get(f"{_VT}/files/{sha}/download",headers={"x-apikey":key},timeout=120,stream=True)
        if not r.ok:log.warning("[rh] dl HTTP %d %s",r.status_code,sha[:16]);return None
        tmp=dest+".part"
        with open(tmp,"wb") as f:
            for ch in r.iter_content(512*1024):f.write(ch)
        os.replace(tmp,dest);log.info("[rh] dl %s %dKB",sha[:16],os.path.getsize(dest)//1024);return dest
    except Exception as e:log.warning("[rh] dl err %s: %s",sha[:16],e);return None

def _yara_exe()->Optional[str]:
    e=shutil.which("yara") or shutil.which("yara64")
    if e:return e
    for n in("yara64.exe","yara64","yara"):
        p=os.path.join(_SD,"yara-master-v4.5.4-win64",n)
        if os.path.isfile(p):return p
    return None

def identify_matched_strings(rule_path,sample_path,log)->List[str]:
    exe=_yara_exe()
    if not exe:log.warning("[rh] no yara exe");return[]
    try:
        r=subprocess.run([exe,"-s",rule_path,sample_path],capture_output=True,text=True,timeout=60)
        ms=[]
        for ln in r.stdout.splitlines():
            m=re.match(r"0x[0-9a-fA-F]+(:\$\w+):",ln)
            if m and m.group(1) not in ms:ms.append(m.group(1))
        log.info("[rh] yara -s %s: %d strings",os.path.basename(sample_path)[:16],len(ms));return ms
    except Exception as e:log.warning("[rh] scan err: %s",e);return[]

def analyze_fp_samples(fps,rule_path,key,log,*,max_dl=5)->List[Dict[str,Any]]:
    d=os.path.join(_SD,"generated_rules","_fp_samples");rs=[]
    for fp in fps[:max_dl]:
        lp=download_sample(fp.sha256,key,d,log)
        if not lp:continue
        ms=identify_matched_strings(rule_path,lp,log)
        rs.append({"sha256":fp.sha256,"matched_strings":ms,"reason":fp.reason})
    log.info("[rh] analyzed %d/%d FP",len(rs),len(fps));return rs

def validate_domain_reputation(dom,key,log)->Dict[str,Any]:
    try:
        r=requests.get(f"{_VT}/domains/{dom}",headers={"x-apikey":key},timeout=15)
        if r.status_code==429:time.sleep(15);return{"domain":dom,"status":"rate_limited"}
        if not r.ok:return{"domain":dom,"status":f"http_{r.status_code}"}
        a=r.json().get("data",{}).get("attributes",{});s=a.get("last_analysis_stats",{})
        return{"domain":dom,"status":"ok","malicious":int(s.get("malicious",0)),"suspicious":int(s.get("suspicious",0)),"popularity_ranks":a.get("popularity_ranks",{})}
    except Exception as e:return{"domain":dom,"status":f"err:{e}"}

def validate_ip_reputation(ip,key,log)->Dict[str,Any]:
    try:
        r=requests.get(f"{_VT}/ip_addresses/{ip}",headers={"x-apikey":key},timeout=15)
        if r.status_code==429:time.sleep(15);return{"ip":ip,"status":"rate_limited"}
        if not r.ok:return{"ip":ip,"status":f"http_{r.status_code}"}
        a=r.json().get("data",{}).get("attributes",{});s=a.get("last_analysis_stats",{})
        return{"ip":ip,"status":"ok","malicious":int(s.get("malicious",0)),"as_owner":a.get("as_owner",""),"country":a.get("country","")}
    except Exception as e:return{"ip":ip,"status":f"err:{e}"}
