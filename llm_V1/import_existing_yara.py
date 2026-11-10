"""import_existing_yara.py - Import existing .yara files into the refinement registry as drafts.

Usage:
    python import_existing_yara.py                          # import from generated_rules/yara/
    python import_existing_yara.py --dir yara_exports       # import from yara_exports/
    python import_existing_yara.py --file bankbot.yara       # import one file
    python import_existing_yara.py --dir yara_exports --skip-clean  # skip knownclean rules
"""
from __future__ import annotations
import argparse,json,os,re,sys
from typing import List,Tuple

_SD=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,_SD)
from yara_rule_registry import YaraRuleRegistry

def split_yara_rules(text:str)->List[Tuple[str,str]]:
    """Split a multi-rule .yara file into individual (rule_name, rule_text) pairs."""
    rules=[]
    # Match each rule block:  rule Name ... { ... }
    # Handle nested braces by counting
    pattern=re.compile(r"(rule\s+(\w+)[^{]*\{)",re.MULTILINE)
    for m in pattern.finditer(text):
        rule_name=m.group(2)
        start=m.start()
        # Find matching closing brace
        depth=0;pos=m.end()-1  # position of the opening {
        for i in range(pos,len(text)):
            if text[i]=="{":depth+=1
            elif text[i]=="}":
                depth-=1
                if depth==0:
                    rule_text=text[start:i+1].strip()
                    rules.append((rule_name,rule_text))
                    break
    return rules

def guess_family(rule_name:str,rule_text:str)->str:
    """Guess malware family from rule name."""
    # Pattern: Android_Category_Family_...
    parts=rule_name.split("_")
    if len(parts)>=3:
        # Skip Android, skip category (Banker/Trojan/Clean), take family
        candidate=parts[2] if parts[0]=="Android" else parts[1]
        if candidate.lower() not in("clean","app","staticbridge","pipeline"):
            return candidate
    # Fallback: search for known family names
    for fam in("Bankbot","SMSThief","SmsThief","Anubis","Cerberus","Spymax","SpyNote",
               "Ahmyth","Triada","Coper","Mamont","Anatsa","Ermac","FluBot","TsarBot","SoumniBot"):
        if fam.lower() in rule_name.lower() or fam.lower() in rule_text.lower():
            return fam
    return"Unknown"

def guess_category(rule_name:str,rule_text:str)->str:
    """Guess category from rule name."""
    name_lower=rule_name.lower()
    if "banker" in name_lower or "bank" in name_lower:return"Banker"
    if "trojan" in name_lower:return"Trojan"
    if "spyware" in name_lower or "spy" in name_lower:return"Spyware"
    if "dropper" in name_lower:return"Dropper"
    if "clean" in name_lower:return"Clean"
    return"Trojan"

def is_clean_rule(rule_name:str,rule_text:str)->bool:
    return"knownclean" in rule_text.lower() or"clean" in rule_name.lower() or "risk = 0" in rule_text

def import_file(filepath:str,reg:YaraRuleRegistry,skip_clean:bool=True)->dict:
    """Import all rules from one .yara file. Returns counts."""
    counts={"imported":0,"duplicate":0,"superseded":0,"skipped_clean":0,"error":0}
    try:
        with open(filepath,"r",encoding="utf-8",errors="replace") as f:
            text=f.read()
    except Exception as e:
        print(f"  [!] Cannot read {filepath}: {e}")
        counts["error"]+=1
        return counts

    rules=split_yara_rules(text)
    if not rules:
        print(f"  [!] No rules found in {filepath}")
        return counts

    for rule_name,rule_text in rules:
        if skip_clean and is_clean_rule(rule_name,rule_text):
            counts["skipped_clean"]+=1
            continue
        family=guess_family(rule_name,rule_text)
        category=guess_category(rule_name,rule_text)
        try:
            rid,action=reg.register_rule(
                rule_name=rule_name,
                family=family,
                category=category,
                sha256_source="imported",
                rule_text=rule_text,
                rule_file_path=os.path.abspath(filepath),
                runner_id="import_existing",
            )
            if action=="registered":
                counts["imported"]+=1
                print(f"  [+] {rule_name} -> draft (family={family}, id={rid})")
            elif action=="duplicate":
                counts["duplicate"]+=1
                print(f"  [=] {rule_name} -> duplicate (id={rid})")
            elif action=="superseded":
                counts["superseded"]+=1
                print(f"  [~] {rule_name} -> superseded (id={rid})")
        except Exception as e:
            counts["error"]+=1
            print(f"  [!] {rule_name} -> error: {e}")
    return counts

def main()->int:
    ap=argparse.ArgumentParser(description="Import existing .yara files into refinement registry.")
    ap.add_argument("--dir",default=None,help="Directory with .yara files. Default: generated_rules/yara/ and yara_exports/")
    ap.add_argument("--file",default=None,help="Single .yara file to import.")
    ap.add_argument("--skip-clean",action="store_true",default=True,help="Skip knownclean rules (default: True).")
    ap.add_argument("--include-clean",action="store_true",default=False,help="Also import knownclean rules.")
    args=ap.parse_args()
    skip_clean=not args.include_clean

    reg=YaraRuleRegistry()
    totals={"imported":0,"duplicate":0,"superseded":0,"skipped_clean":0,"error":0}

    if args.file:
        files=[os.path.abspath(args.file)]
    elif args.dir:
        d=os.path.abspath(args.dir)
        files=sorted(os.path.join(d,f) for f in os.listdir(d) if f.endswith(".yara"))
    else:
        # Default: both generated_rules/yara and yara_exports
        dirs=[os.path.join(_SD,"generated_rules","yara"),os.path.join(_SD,"yara_exports")]
        files=[]
        for d in dirs:
            if os.path.isdir(d):
                files.extend(sorted(os.path.join(d,f) for f in os.listdir(d) if f.endswith(".yara")))

    if not files:
        print("No .yara files found.");return 0

    print(f"\nImporting from {len(files)} file(s)...\n")
    for filepath in files:
        print(f"\n--- {os.path.basename(filepath)} ---")
        counts=import_file(filepath,reg,skip_clean=skip_clean)
        for k,v in counts.items():totals[k]=totals.get(k,0)+v

    reg.close()
    print(f"\n=== Import Summary ===")
    for k,v in sorted(totals.items()):print(f"  {k}: {v}")
    print()

    # Show registry status
    reg2=YaraRuleRegistry()
    ct=reg2.status_counts();reg2.close()
    print("Registry status:")
    for s,n in sorted(ct.items()):print(f"  {s}: {n}")
    return 0

if __name__=="__main__":sys.exit(main())
