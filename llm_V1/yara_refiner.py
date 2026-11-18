"""yara_refiner.py - Refine YARA rules via VT Retrohunt FP testing."""
from __future__ import annotations
import argparse,json,logging,os,subprocess,sys,tempfile,time
from typing import Any,Dict,List,Optional
_SD=os.path.dirname(os.path.abspath(__file__))
from yara_rule_registry import YaraRuleRegistry,RuleRecord,inject_round_into_rule_name
import vt_retrohunt

_MAX_CAP_ESCALATIONS=5  # max times we bump the cap before giving up

def _load_cfg()->Dict[str,Any]:
    defs={"enabled":True,"max_refinement_rounds":3,"max_concurrent_retrohunt_jobs_per_key":3,
        "retrohunt_corpus":"main","goodware_prescreen":True,"retrohunt_time_range_days":90,
        "poll_interval_sec":120,"poll_timeout_sec":14400,"max_acceptable_clean_fps":0,
        "max_acceptable_suspicious_fps":5,"fp_sample_download_count":5,
        "max_matches_before_abort":1000}
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
    if not exe:log.warning("[ref] yara exe not found");return True
    try:
        with tempfile.NamedTemporaryFile(mode="w",suffix=".yara",delete=False,encoding="utf-8") as f:
            f.write(txt);tp=f.name
        r=subprocess.run([exe,tp,tp],capture_output=True,text=True,timeout=30)
        os.unlink(tp)
        if r.returncode!=0:log.warning("[ref] compile err: %s",r.stderr[:300]);return False
        return True
    except Exception:return True

def _tweak_prompt(rule,fp_info,family,match_count=0,was_too_broad=False):
    fps=[]
    for fp in fp_info:
        fps.append(f"  - {fp['sha256'][:16]}... ({fp['reason']})\n    Triggered: {', '.join(fp['matched_strings']) or 'unknown'}")
    broad=""
    if was_too_broad:
        broad=(f"\nCRITICAL: This rule matched {match_count} files -- WAY too broad!\n"
            "Make it MUCH more specific: more required strings, stricter conditions, filesize limits.\n")
    sy=("You are an expert YARA rule author for Android malware.\n"
        "Revise the rule to ELIMINATE FPs while keeping malware detection.\n"
        "IMPORTANT: Keep filetype check: (uint32(0)==0x04034B50 or uint32(0)==0x6465780A)\n"
        +broad+"Return ONLY the revised YARA rule. No markdown.\n")
    us=(f"FAMILY: {family}\n\nORIGINAL RULE:\n{rule}\n\n"
        f"FP ANALYSIS ({len(fp_info)} samples):\n"+"\n".join(fps)+"\n\nRevise the rule.\n")
    return[{"role":"system","content":sy},{"role":"user","content":us}]

def _reject(reg,rid,reason,log):
    log.warning("[ref] REJECTED %s: %s",rid,reason)
    reg.update_status(rid,"rejected",rejection_reason=reason)
    return"rejected"
def refine_one_rule(rule,reg,vt_keys,cfg,log,llm_client=None)->str:
    mx=min(rule.max_refinement_rounds,cfg.get("max_refinement_rounds",3))
    mcfp=cfg.get("max_acceptable_clean_fps",0);corpus=cfg.get("retrohunt_corpus","main")
    pi=cfg.get("poll_interval_sec",120);pt=cfg.get("poll_timeout_sec",14400)
    md=cfg.get("fp_sample_download_count",5);td=cfg.get("retrohunt_time_range_days",90)
    mjk=cfg.get("max_concurrent_retrohunt_jobs_per_key",3);gw=cfg.get("goodware_prescreen",True)
    base_cap=cfg.get("max_matches_before_abort",1000)
    txt=rule.rule_text;fp=rule.rule_file_path

    yara_exe=vt_retrohunt._yara_exe()
    if not yara_exe:return _reject(reg,rule.rule_id,"yara_exe_not_found",log)
    if not llm_client:return _reject(reg,rule.rule_id,"no_llm_client",log)

    for rn in range(mx+1):
        log.info("="*50+"\n[ref] Rule %s (%s) ROUND %d/%d",rule.rule_id,rule.family,rn,mx)
        match_cap=base_cap  # reset cap each round (new rule text after tweak)

        vk=vt_retrohunt.pick_best_key(vt_keys,mjk)
        if not vk:
            log.warning("[ref] keys busy, wait 5m");time.sleep(300)
            vk=vt_retrohunt.pick_best_key(vt_keys,mjk)
            if not vk:return _reject(reg,rule.rule_id,"no_vt_key_available",log)

        import re as _re
        vt_rule=inject_round_into_rule_name(txt,rule.rule_id,rn)
        vt_name_m=_re.match(r"rule\s+(\w+)",vt_rule)
        vt_name=vt_name_m.group(1) if vt_name_m else f"{rule.rule_name}_R{rn}"

        # Goodware pre-screen (round 0 only)
        if gw and rn==0 and not rule.goodware_tested:
            log.info("[ref] goodware pre-screen...")
            gid=vt_retrohunt.create_retrohunt_job(vt_rule,vk.key,log,corpus="goodware",days=td)
            if gid:
                vk.active_jobs+=1
                reg.record_retrohunt_job(rule_id=rule.rule_id,job_id=gid,vt_key_name=vk.name,
                    corpus="goodware",round_number=rn,rule_name_on_vt=vt_name+"_GW")
                gr=vt_retrohunt.poll_retrohunt_job(gid,vk.key,log,interval=30,timeout=300,match_cap=999999)
                vk.active_jobs=max(0,vk.active_jobs-1)
                reg.update_retrohunt_job(gid,status=gr["status"],num_matches=gr["num_matches"])
                if gr.get("num_matches",0)>0:log.warning("[ref] goodware matched %d!",gr["num_matches"])
                else:log.info("[ref] goodware clean")
            reg.update_status(rule.rule_id,"retrohunting",goodware_tested=1)

        # Inner loop: cap escalation retries (does NOT consume a refinement round)
        cap_escalations=0
        while cap_escalations<=_MAX_CAP_ESCALATIONS:
            reg.update_status(rule.rule_id,"retrohunting")
            jid=vt_retrohunt.create_retrohunt_job(vt_rule,vk.key,log,corpus=corpus,days=td)
            if not jid:return _reject(reg,rule.rule_id,f"retrohunt_create_failed_R{rn}",log)
            vk.active_jobs+=1
            reg.update_status(rule.rule_id,"retrohunting",retrohunt_job_id=jid)
            reg.record_retrohunt_job(rule_id=rule.rule_id,job_id=jid,vt_key_name=vk.name,
                corpus=corpus,round_number=rn,rule_name_on_vt=f"{vt_name}_cap{match_cap}" if cap_escalations>0 else vt_name)

            log.info("[ref] R%d retrohunt submitted (cap=%d, escalation=%d/%d)",
                     rn,match_cap,cap_escalations,_MAX_CAP_ESCALATIONS)
            pr=vt_retrohunt.poll_retrohunt_job(jid,vk.key,log,interval=pi,timeout=pt,match_cap=match_cap)
            vk.active_jobs=max(0,vk.active_jobs-1)
            reg.update_retrohunt_job(jid,status=pr["status"],num_matches=pr["num_matches"],
                                      finished_at=vt_retrohunt._now() if pr["finished"] else"")
            if not pr["finished"]:return _reject(reg,rule.rule_id,f"retrohunt_timeout_R{rn}",log)

            was_aborted_cap=(pr["status"]=="aborted_cap")
            total_matches=pr["num_matches"]

            # Fetch matches for classification
            ms=vt_retrohunt.get_matching_files(jid,vk.key,log,limit=300)
            if not ms and not was_aborted_cap:
                log.info("[ref] R%d: 0 matches -- APPROVED",rn)
                reg.update_status(rule.rule_id,"approved",fp_count=0,suspicious_fp_count=0)
                reg.update_version_retrohunt(rule.rule_id,rn,job_id=jid,status="approved",fp_count=0)
                return"approved"

            cls,cfp,sfp=vt_retrohunt.classify_matches(ms,vk.key,log) if ms else([],0,0)
            for c in cls:
                if c.is_potential_fp:
                    reg.record_fp_sample(rule_id=rule.rule_id,retrohunt_job_id=jid,sha256=c.sha256,
                        classification=c.reason,malicious_count=c.malicious_count,
                        has_malicious_parent=c.has_malicious_parent)
            reg.update_version_retrohunt(rule.rule_id,rn,job_id=jid,
                status=f"matches:{total_matches} fp:{cfp}c/{sfp}s cap:{match_cap}",fp_count=cfp,sus_fp_count=sfp)

            if was_aborted_cap and cfp==0:
                # All matches are TPs -- rule is good, just popular. Escalate cap.
                new_cap=int(match_cap*1.2)
                log.info("[ref] R%d: %d matches (cap %d), 0 FPs -- escalating to %d (NOT a new round)",
                         rn,total_matches,match_cap,new_cap)
                match_cap=new_cap
                cap_escalations+=1
                continue  # retry SAME round with higher cap

            # Either finished normally or aborted with FPs -- break inner loop
            break

        # After inner loop: check results
        if cap_escalations>_MAX_CAP_ESCALATIONS:
            return _reject(reg,rule.rule_id,
                f"max_cap_escalations({_MAX_CAP_ESCALATIONS})_rule_matches_{total_matches}+_all_TPs",log)

        reg.update_status(rule.rule_id,"refining",fp_count=cfp,suspicious_fp_count=sfp)

        if cfp<=mcfp and not was_aborted_cap:
            log.info("[ref] APPROVED R%d: %d cfp, %d sfp, %d matches",rn,cfp,sfp,total_matches)
            reg.update_status(rule.rule_id,"approved");return"approved"

        # FPs found -- need to tweak
        if rn>=mx:
            return _reject(reg,rule.rule_id,
                f"max_rounds({mx})_with_{cfp}_FPs_and_{total_matches}_matches",log)

        log.info("[ref] R%d: %d FPs, %d matches -- TWEAKING for R%d...",rn,cfp,total_matches,rn+1)
        cfp_list=[c for c in cls if c.is_confirmed_fp]
        fpi=vt_retrohunt.analyze_fp_samples(cfp_list,fp,vk.key,log,max_dl=md)
        if not fpi:
            return _reject(reg,rule.rule_id,f"fp_analysis_failed_R{rn}",log)

        from modified_trial8_multiple_models import call_llm
        raw=call_llm(_tweak_prompt(txt,fpi,rule.family,total_matches,was_aborted_cap),
                     "claude-sonnet-4-6",log,llm_client)
        nr=_strip_md(raw.get("summary",str(raw)) if isinstance(raw,dict) else str(raw))
        if not _validate_rule(nr,log):
            return _reject(reg,rule.rule_id,f"tweaked_rule_compile_failed_R{rn+1}",log)

        nf=fp.replace(".yara",f"_R{rn+1}.yara");os.makedirs(os.path.dirname(nf),exist_ok=True)
        with open(nf,"w",encoding="utf-8") as f:f.write(nr)
        log.info("[ref] R%d->R%d tweaked rule saved: %s",rn,rn+1,nf)
        reg.update_rule_text(rule.rule_id,nr,nf,round_num=rn+1,job_id=jid,vt_name=vt_name)
        reg.increment_refinement_round(rule.rule_id)
        txt=nr;fp=nf

    return _reject(reg,rule.rule_id,"loop_exhausted",log)

def run_refiner(log,*,rule_id=None,llm_client=None)->Dict[str,int]:
    cfg=_load_cfg()
    if not cfg.get("enabled",True):log.info("[ref] disabled");return{"approved":0,"rejected":0,"error":0,"skipped":0}
    reg=YaraRuleRegistry()
    vks=vt_retrohunt.load_all_premium_keys()
    if not vks:log.error("[ref] no VT keys");return{"approved":0,"rejected":0,"error":0,"skipped":0}
    log.info("[ref] %d VT key(s)",len(vks))
    rules=[reg.get_rule(rule_id)] if rule_id else reg.get_rules_by_status("draft")
    rules=[r for r in rules if r and r.source!="zintel"]
    log.info("[ref] %d rule(s)",len(rules))
    ct={"approved":0,"rejected":0,"error":0,"skipped":0}
    for r in rules:
        if r.status not in("draft","refining","retrohunting"):ct["skipped"]+=1;continue
        try:
            res=refine_one_rule(r,reg,vks,cfg,log,llm_client=llm_client)
            ct[res]=ct.get(res,0)+1
        except Exception as e:
            log.error("[ref] %s failed: %s",r.rule_id,e)
            reg.update_status(r.rule_id,"error",rejection_reason=f"exception:{e}")
            ct["error"]+=1
    reg.close();log.info("[ref] done: %s",json.dumps(ct));return ct

def show_status(log):
    reg=YaraRuleRegistry()
    ct=reg.status_counts(source_filter="pipeline")
    ar=[r for r in reg.get_all_rules() if r.source not in("zintel",None)]
    reg.close()
    print("\n=== YARA Rule Registry (pipeline only) ===")
    print(f"Total: {sum(ct.values())}")
    for s,n in sorted(ct.items()):print(f"  {s}: {n}")
    print()
    for r in ar:
        reason=f" [{r.rejection_reason}]" if r.rejection_reason else ""
        print(f"  [{r.status:12s}] {r.rule_id} {r.family:15s} R{r.refinement_round}/{r.max_refinement_rounds} fp={r.fp_count} sus={r.suspicious_fp_count} src={r.source} {r.rule_name}{reason}")
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
            kc=key_cfgs[0];llm=create_llm_client(kc)
            log.info("[ref] LLM ready: key=%s base_url=%s",kc.name,kc.base_url)
        else:log.error("[ref] no LLM keys in config.json")
    except Exception as e:
        log.error("[ref] LLM init failed: %s",e)
    ct=run_refiner(log,rule_id=args.rule_id,llm_client=llm)
    print(json.dumps(ct,indent=2));return 0 if ct.get("error",0)==0 else 1

if __name__=="__main__":sys.exit(main())
