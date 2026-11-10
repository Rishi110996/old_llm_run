"""yara_refiner.py - Refine YARA rules via VT Retrohunt FP testing."""
from __future__ import annotations
import argparse,json,logging,os,subprocess,sys,tempfile,time
from typing import Any,Dict,List,Optional
_SD=os.path.dirname(os.path.abspath(__file__))
from yara_rule_registry import YaraRuleRegistry,RuleRecord
import vt_retrohunt

def _load_cfg()->Dict[str,Any]:
    defs={"enabled":True,"max_refinement_rounds":3,"max_concurrent_retrohunt_jobs_per_key":3,
        "retrohunt_corpus":"main","goodware_prescreen":True,"retrohunt_time_range_days":90,
        "poll_interval_sec":120,"poll_timeout_sec":14400,"max_acceptable_clean_fps":0,
        "max_acceptable_suspicious_fps":5,"fp_sample_download_count":5}
    try:
        with open(os.path.join(_SD,"config.json"),"r",encoding="utf-8") as f:c=json.load(f)
        return{**defs,**c.get("yara_refinement",{})}
    except Exception:return defs

def _logger()->logging.Logger:
    lg=logging.getLogger("yara_refiner")
    if not lg.handlers:
        h=logging.StreamHandler(sys.stdout);h.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        lg.addHandler(h)
        lp=os.path.join(_SD,"generated_rules","yara_refiner.log");os.makedirs(os.path.dirname(lp),exist_ok=True)
        fh=logging.FileHandler(lp,encoding="utf-8");fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        lg.addHandler(fh)
    lg.setLevel(logging.INFO);return lg

def _strip_md(t):
    ls=t.strip().splitlines()
    if ls and ls[0].strip().startswith("```"):ls=ls[1:]
    if ls and ls[-1].strip().startswith("```"):ls=ls[:-1]
    return"\n".join(ls).strip()

def _validate_rule(txt,log)->bool:
    from rule_generator import _yara_exe
    exe=_yara_exe()
    if not exe:return True
    try:
        with tempfile.NamedTemporaryFile(mode="w",suffix=".yara",delete=False,encoding="utf-8") as f:
            f.write(txt);tp=f.name
        r=subprocess.run([exe,"-C",tp],capture_output=True,text=True,timeout=30)
        os.unlink(tp)
        if r.returncode!=0:log.warning("[ref] compile err: %s",r.stderr[:200]);return False
        return True
    except Exception:return True

def _tweak_prompt(rule,fp_info,family):
    fps=[]
    for fp in fp_info:
        fps.append(f"  - {fp['sha256'][:16]}... ({fp['reason']})\n    Triggered: {', '.join(fp['matched_strings']) or 'unknown'}")
    sy=("You are an expert YARA rule author for Android malware.\n"
        "I provide a rule with FALSE POSITIVES and which strings triggered each FP.\n"
        "Revise the rule to ELIMINATE FPs while keeping malware detection.\n"
        "Strategies: remove/narrow generic strings, add not conditions, tighten condition, "
        "replace generic with specific, add filesize constraints.\n"
        "Return ONLY the revised YARA rule. No markdown.\n")
    us=(f"FAMILY: {family}\n\nORIGINAL RULE:\n{rule}\n\n"
        f"FP ANALYSIS ({len(fp_info)} samples):\n"+"\n".join(fps)+"\n\nRevise the rule.\n")
    return[{"role":"system","content":sy},{"role":"user","content":us}]

def refine_one_rule(rule,reg,vt_keys,cfg,log,llm_client=None)->str:
    mx=min(rule.max_refinement_rounds,cfg.get("max_refinement_rounds",3))
    mcfp=cfg.get("max_acceptable_clean_fps",0);corpus=cfg.get("retrohunt_corpus","main")
    pi=cfg.get("poll_interval_sec",120);pt=cfg.get("poll_timeout_sec",14400)
    md=cfg.get("fp_sample_download_count",5);td=cfg.get("retrohunt_time_range_days",90)
    mjk=cfg.get("max_concurrent_retrohunt_jobs_per_key",3);gw=cfg.get("goodware_prescreen",True)
    txt=rule.rule_text;fp=rule.rule_file_path
    for rn in range(mx+1):
        log.info("="*50+"\n[ref] Rule %s (%s) round %d/%d",rule.rule_id,rule.family,rn,mx)
        vk=vt_retrohunt.pick_best_key(vt_keys,mjk)
        if not vk:
            log.warning("[ref] keys busy, wait 5m");time.sleep(300)
            vk=vt_retrohunt.pick_best_key(vt_keys,mjk)
            if not vk:log.error("[ref] no key");reg.update_status(rule.rule_id,"error");return"error"
        if gw and rn==0 and not rule.goodware_tested:
            log.info("[ref] goodware pre-screen...")
            gid=vt_retrohunt.create_retrohunt_job(txt,vk.key,log,corpus="goodware",days=td)
            if gid:
                vk.active_jobs+=1
                reg.record_retrohunt_job(rule_id=rule.rule_id,job_id=gid,vt_key_name=vk.name,corpus="goodware")
                gr=vt_retrohunt.poll_retrohunt_job(gid,vk.key,log,interval=30,timeout=300)
                vk.active_jobs=max(0,vk.active_jobs-1)
                reg.update_retrohunt_job(gid,status=gr["status"],num_matches=gr["num_matches"])
                if gr.get("num_matches",0)>0:log.warning("[ref] goodware matched %d!",gr["num_matches"])
                else:log.info("[ref] goodware clean")
            reg.update_status(rule.rule_id,"retrohunting",goodware_tested=1)
        reg.update_status(rule.rule_id,"retrohunting")
        jid=vt_retrohunt.create_retrohunt_job(txt,vk.key,log,corpus=corpus,days=td)
        if not jid:log.error("[ref] job fail");reg.update_status(rule.rule_id,"error");return"error"
        vk.active_jobs+=1
        reg.update_status(rule.rule_id,"retrohunting",retrohunt_job_id=jid)
        reg.record_retrohunt_job(rule_id=rule.rule_id,job_id=jid,vt_key_name=vk.name,corpus=corpus)
        pr=vt_retrohunt.poll_retrohunt_job(jid,vk.key,log,interval=pi,timeout=pt)
        vk.active_jobs=max(0,vk.active_jobs-1)
        reg.update_retrohunt_job(jid,status=pr["status"],num_matches=pr["num_matches"],
                                  finished_at=vt_retrohunt._now() if pr["finished"] else"")
        if not pr["finished"]:log.error("[ref] timeout");reg.update_status(rule.rule_id,"error");return"error"
        ms=vt_retrohunt.get_matching_files(jid,vk.key,log)
        if not ms:
            log.info("[ref] 0 matches-approved");reg.update_status(rule.rule_id,"approved",fp_count=0,suspicious_fp_count=0);return"approved"
        cls,cfp,sfp=vt_retrohunt.classify_matches(ms,vk.key,log)
        for c in cls:
            if c.is_potential_fp:
                reg.record_fp_sample(rule_id=rule.rule_id,retrohunt_job_id=jid,sha256=c.sha256,
                    classification=c.reason,malicious_count=c.malicious_count,has_malicious_parent=c.has_malicious_parent)
        reg.update_status(rule.rule_id,"refining",fp_count=cfp,suspicious_fp_count=sfp)
        if cfp<=mcfp:
            log.info("[ref] APPROVED: %d cfp(<=%d) %d sfp",cfp,mcfp,sfp);reg.update_status(rule.rule_id,"approved");return"approved"
        if rn>=mx:
            log.warning("[ref] max rounds(%d) %d FPs-rejected",mx,cfp);reg.update_status(rule.rule_id,"rejected");return"rejected"
        log.info("[ref] %d FPs-tweaking round %d/%d",cfp,rn+1,mx)
        cfp_list=[c for c in cls if c.is_confirmed_fp]
        fpi=vt_retrohunt.analyze_fp_samples(cfp_list,fp,vk.key,log,max_dl=md)
        if not fpi:log.warning("[ref] FP analysis fail");reg.update_status(rule.rule_id,"rejected");return"rejected"
        if not llm_client:log.warning("[ref] no LLM");reg.update_status(rule.rule_id,"rejected");return"rejected"
        from modified_trial8_multiple_models import call_llm
        raw=call_llm(_tweak_prompt(txt,fpi,rule.family),"claude-sonnet-4-6",log,llm_client)
        nr=_strip_md(raw.get("summary",str(raw)) if isinstance(raw,dict) else str(raw))
        if not _validate_rule(nr,log):log.warning("[ref] compile fail");reg.update_status(rule.rule_id,"rejected");return"rejected"
        nf=fp.replace(".yara",f"_v{rn+2}.yara");os.makedirs(os.path.dirname(nf),exist_ok=True)
        with open(nf,"w",encoding="utf-8") as f:f.write(nr)
        log.info("[ref] tweaked: %s",nf)
        reg.update_rule_text(rule.rule_id,nr,nf);reg.increment_refinement_round(rule.rule_id)
        txt=nr;fp=nf
    reg.update_status(rule.rule_id,"rejected");return"rejected"

def run_refiner(log,*,rule_id=None,llm_client=None)->Dict[str,int]:
    cfg=_load_cfg()
    if not cfg.get("enabled",True):log.info("[ref] disabled");return{"approved":0,"rejected":0,"error":0,"skipped":0}
    reg=YaraRuleRegistry()
    vks=vt_retrohunt.load_all_premium_keys()
    if not vks:log.error("[ref] no VT keys");return{"approved":0,"rejected":0,"error":0,"skipped":0}
    log.info("[ref] %d VT key(s)",len(vks))
    rules=[reg.get_rule(rule_id)] if rule_id else reg.get_rules_by_status("draft")
    rules=[r for r in rules if r]
    log.info("[ref] %d rule(s)",len(rules))
    ct={"approved":0,"rejected":0,"error":0,"skipped":0}
    for r in rules:
        if r.status not in("draft","refining","retrohunting"):ct["skipped"]+=1;continue
        try:
            res=refine_one_rule(r,reg,vks,cfg,log,llm_client=llm_client)
            ct[res]=ct.get(res,0)+1
        except Exception as e:
            log.error("[ref] %s failed: %s",r.rule_id,e);reg.update_status(r.rule_id,"error");ct["error"]+=1
    reg.close();log.info("[ref] done: %s",json.dumps(ct));return ct

def show_status(log):
    reg=YaraRuleRegistry();ct=reg.status_counts();ar=reg.get_all_rules();reg.close()
    print("\n=== YARA Rule Registry ===")
    print(f"Total: {sum(ct.values())}")
    for s,n in sorted(ct.items()):print(f"  {s}: {n}")
    print()
    for r in ar:
        print(f"  [{r.status:12s}] {r.rule_id} {r.family:15s} round={r.refinement_round}/{r.max_refinement_rounds} fp={r.fp_count} sus={r.suspicious_fp_count} {r.rule_name}")
    print()

def main()->int:
    ap=argparse.ArgumentParser(description="Refine YARA via VT Retrohunt.")
    ap.add_argument("--status",action="store_true",help="Show status.")
    ap.add_argument("--rule-id",default=None,help="Refine one rule.")
    args=ap.parse_args();log=_logger()
    if args.status:show_status(log);return 0
    llm=None
    try:
        from modified_trial8_multiple_models import (
            load_runtime_config, load_llm_key_configs, create_llm_client,
        )
        cfg=load_runtime_config()
        key_cfgs=load_llm_key_configs(cfg)
        if key_cfgs:
            kc=key_cfgs[0]
            llm=create_llm_client(kc)
            log.info("[ref] LLM ready: key=%s base_url=%s",kc.name,kc.base_url)
        else:
            log.error("[ref] no LLM keys in config.json — rule tweaking will fail")
    except Exception as e:
        log.error("[ref] LLM init failed: %s",e)
        log.error("[ref] ensure openai is installed: pip install openai>=1.40.0")
    ct=run_refiner(log,rule_id=args.rule_id,llm_client=llm)
    print(json.dumps(ct,indent=2));return 0 if ct.get("error",0)==0 else 1

if __name__=="__main__":sys.exit(main())
