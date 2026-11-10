"""import_existing_yara.py - Import .yara files into the refinement registry.

Status modes:
  --status approved   yara_exports/ production rules (already vetted, skip retrohunt)
  --status draft      generated_rules/yara/ pipeline output (needs retrohunt FP testing)

Granularity:
  --dir <path>              all .yara files in a folder
  --file <path>             one specific .yara file
  --family <name>           only rules matching this family (e.g. Bankbot)
  --rule-name <pattern>     only rules whose name matches this regex
  --dry-run                 show what would be imported, don't write DB

Defaults (no --dir/--file given):
  yara_exports/           -> imported as approved
  generated_rules/yara/   -> imported as draft

Examples:
  python import_existing_yara.py                                     # defaults
  python import_existing_yara.py --dir yara_exports --status approved
  python import_existing_yara.py --dir generated_rules/yara --status draft
  python import_existing_yara.py --file bankbot-static-bridge.yara --status approved
  python import_existing_yara.py --file my_new_rule.yara --status draft
  python import_existing_yara.py --dir yara_exports --family Bankbot --status approved
  python import_existing_yara.py --dry-run
"""
from __future__ import annotations
import argparse,json,os,re,sys
from typing import List,Tuple

_SD=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,_SD)
from yara_rule_registry import YaraRuleRegistry

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def split_yara_rules(text:str)->List[Tuple[str,str]]:
    """Split a multi-rule .yara file into (rule_name, rule_text) pairs."""
    rules=[]
    pattern=re.compile(r"(rule\s+(\w+)[^{]*\{)",re.MULTILINE)
    for m in pattern.finditer(text):
        rule_name=m.group(2)
        start=m.start()
        depth=0;pos=m.end()-1
        for i in range(pos,len(text)):
            if text[i]=="{":depth+=1
            elif text[i]=="}":
                depth-=1
                if depth==0:
                    rules.append((rule_name,text[start:i+1].strip()))
                    break
    return rules

def guess_family(name:str,text:str)->str:
    parts=name.split("_")
    if len(parts)>=3:
        c=parts[2] if parts[0] in("Android","Win32","Win64","MSIL","Linux","IoT","PS","Python","OSX") else parts[1]
        if c.lower() not in("clean","app","staticbridge","pipeline","gen"):
            return c
    for fam in("Bankbot","SMSThief","SmsThief","Anubis","Cerberus","Spymax","SpyNote",
               "Ahmyth","Triada","Coper","Mamont","Anatsa","Ermac","FluBot","TsarBot","SoumniBot"):
        if fam.lower() in name.lower() or fam.lower() in text.lower():
            return fam
    return"Unknown"

def guess_category(name:str,text:str)->str:
    nl=name.lower()
    if "banker" in nl or "bank" in nl:return"Banker"
    if "trojan" in nl:return"Trojan"
    if "spyware" in nl or "spy" in nl:return"Spyware"
    if "dropper" in nl:return"Dropper"
    if "clean" in nl:return"Clean"
    if "ransom" in nl:return"Ransomware"
    if "backdoor" in nl:return"Backdoor"
    if "hacktool" in nl:return"HackTool"
    if "exploit" in nl:return"Exploit"
    return"Trojan"

def is_clean_rule(name:str,text:str)->bool:
    return"knownclean" in text.lower() or "_Clean_" in name or "risk = 0" in text

# ---------------------------------------------------------------------------
# Import logic
# ---------------------------------------------------------------------------

def import_file(filepath:str,reg:YaraRuleRegistry,*,
                target_status:str="draft",skip_clean:bool=True,
                family_filter:str="",name_pattern:str="",
                dry_run:bool=False)->dict:
    """Import rules from one .yara file. Returns counts dict."""
    ct={"imported":0,"duplicate":0,"superseded":0,"skipped_clean":0,"skipped_filter":0,"error":0}
    try:
        with open(filepath,"r",encoding="utf-8",errors="replace") as f:text=f.read()
    except Exception as e:
        print(f"  [!] Cannot read {filepath}: {e}");ct["error"]+=1;return ct

    rules=split_yara_rules(text)
    if not rules:
        print(f"  [!] No rules found in {os.path.basename(filepath)}");return ct

    name_re=re.compile(name_pattern,re.I) if name_pattern else None

    for rule_name,rule_text in rules:
        # --- filters ---
        if skip_clean and is_clean_rule(rule_name,rule_text):
            ct["skipped_clean"]+=1;continue
        family=guess_family(rule_name,rule_text)
        if family_filter and family.lower()!=family_filter.lower():
            ct["skipped_filter"]+=1;continue
        if name_re and not name_re.search(rule_name):
            ct["skipped_filter"]+=1;continue

        category=guess_category(rule_name,rule_text)
        label=f"{rule_name} (family={family}, cat={category})"

        if dry_run:
            print(f"  [dry] {label} -> would be {target_status}")
            ct["imported"]+=1;continue

        try:
            rid,action=reg.register_rule(
                rule_name=rule_name,family=family,category=category,
                sha256_source="imported",rule_text=rule_text,
                rule_file_path=os.path.abspath(filepath),
                runner_id="import_existing")
            if action=="registered":
                # If target is approved, immediately promote from draft
                if target_status!="draft":
                    reg.update_status(rid,target_status)
                ct["imported"]+=1
                print(f"  [+] {label} -> {target_status} (id={rid})")
            elif action=="duplicate":
                ct["duplicate"]+=1
                print(f"  [=] {label} -> duplicate (id={rid})")
            elif action=="superseded":
                ct["superseded"]+=1
                print(f"  [~] {label} -> superseded (id={rid})")
        except Exception as e:
            ct["error"]+=1
            print(f"  [!] {label} -> error: {e}")
    return ct

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main()->int:
    ap=argparse.ArgumentParser(
        description="Import .yara files into the refinement registry.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Status modes:\n"""
               """  approved  = production rules (yara_exports), skip retrohunt\n"""
               """  draft     = pipeline-generated, needs retrohunt FP testing\n"""
               """  rejected  = known-bad, archived only\n""")
    ap.add_argument("--dir",default=None,
        help="Directory with .yara files.")
    ap.add_argument("--file",default=None,
        help="Single .yara file to import.")
    ap.add_argument("--status",default=None,choices=["draft","approved","rejected"],
        help="Status to assign. Required when --dir or --file is used. "
             "Defaults: yara_exports->approved, generated_rules/yara->draft")
    ap.add_argument("--family",default="",
        help="Only import rules matching this family name (case-insensitive).")
    ap.add_argument("--rule-name",default="",
        help="Only import rules whose name matches this regex.")
    ap.add_argument("--include-clean",action="store_true",default=False,
        help="Include knownclean / risk=0 rules (skipped by default).")
    ap.add_argument("--dry-run",action="store_true",default=False,
        help="Preview what would be imported without writing to DB.")
    args=ap.parse_args()
    skip_clean=not args.include_clean

    reg=YaraRuleRegistry()
    totals={"imported":0,"duplicate":0,"superseded":0,"skipped_clean":0,"skipped_filter":0,"error":0}

    # Build file list with target statuses
    # Each entry: (filepath, target_status)
    jobs:List[Tuple[str,str]]=[]

    if args.file:
        if not args.status:
            print("ERROR: --status is required when using --file",file=sys.stderr);return 1
        jobs.append((os.path.abspath(args.file),args.status))
    elif args.dir:
        if not args.status:
            print("ERROR: --status is required when using --dir",file=sys.stderr);return 1
        d=os.path.abspath(args.dir)
        for f in sorted(os.listdir(d)):
            if f.endswith(".yara"):jobs.append((os.path.join(d,f),args.status))
    else:
        # Default: yara_exports -> approved, generated_rules/yara -> draft
        yd=os.path.join(_SD,"yara_exports")
        gd=os.path.join(_SD,"generated_rules","yara")
        if os.path.isdir(yd):
            for f in sorted(os.listdir(yd)):
                if f.endswith(".yara"):jobs.append((os.path.join(yd,f),"approved"))
        if os.path.isdir(gd):
            for f in sorted(os.listdir(gd)):
                if f.endswith(".yara"):jobs.append((os.path.join(gd,f),"draft"))

    if not jobs:
        print("No .yara files found.");return 0

    # Group by status for display
    by_status={}
    for fp,st in jobs:
        by_status.setdefault(st,[]).append(fp)
    for st,fps in sorted(by_status.items()):
        print(f"\n  {len(fps)} file(s) -> {st}")

    print(f"\nProcessing {len(jobs)} file(s)...{'  [DRY RUN]' if args.dry_run else ''}\n")

    for filepath,target_status in jobs:
        print(f"\n--- {os.path.basename(filepath)} -> {target_status} ---")
        ct=import_file(filepath,reg,target_status=target_status,
                       skip_clean=skip_clean,family_filter=args.family,
                       name_pattern=args.rule_name,dry_run=args.dry_run)
        for k,v in ct.items():totals[k]=totals.get(k,0)+v

    reg.close()
    print(f"\n=== Import Summary ===")
    for k,v in sorted(totals.items()):print(f"  {k}: {v}")
    print()

    if not args.dry_run:
        reg2=YaraRuleRegistry();ct2=reg2.status_counts();reg2.close()
        print("Registry status:")
        for s,n in sorted(ct2.items()):print(f"  {s}: {n}")
    return 0

if __name__=="__main__":sys.exit(main())
