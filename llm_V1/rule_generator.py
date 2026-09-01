"""rule_generator.py - Stage 6: YARA/Snort/CIF rule generation."""
from __future__ import annotations
import datetime as dt, hashlib, json, logging, os, re, shutil
import subprocess, tempfile, time as _time
from typing import Any, Dict, List, Optional, Set

_SD = os.path.dirname(os.path.abspath(__file__))
_GD = os.path.join(_SD, "generated_rules")
_YD = os.path.join(_GD, "yara")
_ND = os.path.join(_GD, "snort")
_CD = os.path.join(_GD, "cif")
_VCP = os.path.join(_GD, "vt_string_cache.json")
_VSU = "https://www.virustotal.com/api/v3/intelligence/search"
MODEL = "claude-sonnet-4-6"
MAX_VT = 12

_SDK_NOISE = re.compile(
    r"^(?:Landroid/|Ljava/|Ljavax/|Lkotlin/|Landroidx/|Ldalvik/"
    r"|Lokhttp3/|Lokio/|Lretrofit2/|Lcom/google/|Lcom/squareup/"
    r"|Lcom/fasterxml/|Lcom/facebook/|Lorg/apache/|Lorg/json/"
    r"|Lcn/jpush/|Lcn/jiguang/|Lcom/alibaba/|Lcom/tencent/"
    r"|Lcom/baidu/|Lcom/huawei/|Lcom/umeng/|Lcom/taobao/"
    r"|Lbolts/|Lcom/crashlytics/|Lcom/airbnb/|Lcom/github/)")

_GENERIC = {
    "true","false","null","name","value","type","class","field",
    "method","string","invoke","return","const","public","private",
    "protected","static","final","void","this","super","android",
    "intent","action","permission","provider","receiver","service",
    "activity","application","manifest","xmlns","layout","drawable",
    "fragment","adapter","handler","listener","context","content",
    "bundle","manager","system","process","runtime","message",
    "request","response","connection","accessibility","notification",
    "broadcast","callback","interface","implements","override",
}

def _ascii(data, n=8):
    r, c = [], []
    for b in data:
        if 0x20 <= b < 0x7F:
            c.append(b)
        else:
            if len(c) >= n:
                r.append(bytes(c).decode("ascii"))
            c = []
    if len(c) >= n:
        r.append(bytes(c).decode("ascii"))
    return r

def parse_bin_dump(path):
    empty = {"manifest_components": [], "manifest_permissions": [],
             "dex_strings": [], "asset_paths": [], "all_filenames": []}
    try:
        raw = open(path, "rb").read()
    except Exception:
        return empty
    text = raw.decode("utf-8", errors="replace")
    comps, perms, assets, fnames = [], [], [], []
    in_man, man_text = False, ""
    for line in text.split("\n"):
        if line.startswith("filename:"):
            fn = line.split("filename:", 1)[1].split(" filetype:")[0].strip()
            fnames.append(fn)
            in_man = "AndroidManifest.xml" in fn
            if re.search(r"\.(apk|dex|jar|so|bin|dat|php|zip)$", fn, re.I):
                if not fn.startswith("res/") and not fn.startswith("META-INF/"):
                    assets.append(fn)
            continue
        if in_man:
            man_text += line + "\n"
    for m in re.finditer(r'android:name="([^"]+)"', man_text):
        nm = m.group(1)
        if nm.startswith("android.permission."):
            perms.append(nm)
        elif "." in nm and not nm.startswith("android."):
            comps.append(nm)
    dex_raw = _ascii(raw, 8)
    seen = set()
    dex = []
    for s in dex_raw:
        s = s.strip()
        if len(s) < 8 or len(s) > 200 or s in seen:
            continue
        if s.lower() in _GENERIC:
            continue
        if s.startswith("L") and "/" in s and _SDK_NOISE.match(s):
            continue
        if s.startswith("filename:") or s.startswith("filetype:"):
            continue
        if s.startswith("<") or s.startswith("<?"):
            continue
        if re.match(r"^(?:\d+$|0x[0-9a-f]+$|[A-Za-z0-9+/]{80,}={0,2}$|[0-9a-f]{32,}$)", s, re.I):
            continue
        seen.add(s)
        dex.append(s)

def rank_strings(parsed, apk_facts, evidence_items, verdict):
    iocs = {s.lower() for s in (verdict.get("IOCs") or [])}
    evs = {ei.value.lower() for ei in evidence_items if ei.direction != "benign"}
    src_lits = set()
    for cls, src in apk_facts.classes.items():
        if src and apk_facts.class_api_scores.get(cls, 0) >= 0.30:
            for m in re.finditer(r'"([^"]{8,80})"', src):
                src_lits.add(m.group(1).lower())
    ranked = []
    for s in parsed["dex_strings"]:
        sl = s.lower()
        sc, r = 0.0, ""
        if sl in iocs: sc += 5.0; r = "IOC"
        if sl in src_lits: sc += 4.0; r = r or "src_lit"
        if re.match(r"https?://|/\w+\.php|api\.telegram\.org", s, re.I):
            sc += 3.5; r = r or "C2"
        if re.search(r"[/.](?:bot|inject|c2|exfil|steal|hook|socks|vnc|screencast)[/.]", sl):
            sc += 3.0; r = r or "bot_path"
        if re.match(r"[a-z]+_[a-z]+_[a-z]+", sl) and len(s) >= 12:
            if re.search(r"sms|upload|send|delete|record|capture|inject|install|command|task|kill", sl):
                sc += 3.0; r = r or "bot_cmd"
        if re.match(r"[A-Z][a-z]+[A-Z][a-z]+", s) and len(s) >= 12:
            if re.search(r"Service|Worker|Receiver|Exporter|Sender|Handler", s):
                sc += 2.5; r = r or "svc_name"
        if s.startswith("AMStrings:"): sc += 4.0; r = r or "AM"
        if s.startswith("L") and s.endswith(";") and "/" in s and not _SDK_NOISE.match(s):
            sc += 1.0; r = r or "dalvik"
        if sl in evs and not r: sc += 2.0; r = "evidence"
        if sc > 0:
            ranked.append({"value": s, "score": round(sc, 2), "reason": r, "type": "dex_string"})
    for comp in parsed["manifest_components"]:
        sl = comp.lower()
        sc, r = 0.0, ""
        if sl in iocs: sc += 4.0; r = "IOC"
        if re.search(r"bot|inject|sms|admin|helper|periodic|screencast|socks|vnc", sl):
            sc += 3.0; r = r or "bot_comp"
        if sc > 0:
            ranked.append({"value": comp, "score": round(sc, 2), "reason": r, "type": "manifest_component"})
    for p in parsed["asset_paths"]:
        sc = 3.5 if re.search(r"\.apk$|\.dex$|implant|payload|inject", p, re.I) else 2.5
        ranked.append({"value": p, "score": sc, "reason": "asset", "type": "asset_path"})
    ranked.sort(key=lambda x: -x["score"])

_vtc = {}
_vtl = False

def _vt_search(s, key, log):
    global _vtc, _vtl
    if not _vtl:
        _vtl = True
        if os.path.isfile(_VCP):
            try: _vtc.update(json.load(open(_VCP)))
            except Exception: pass
    if s in _vtc: return _vtc[s]
    try:
        import requests as _rq
        r = _rq.get(_VSU, params={"query": f'tag:apk and content:"{s}"',
                    "limit": 1, "descriptors_only": "true"},
                    headers={"x-apikey": key, "Accept": "application/json"}, timeout=15)
        if r.status_code == 429 or not r.ok: return -1
        d = r.json()
        c = len(d.get("data", [])) + (100 if d.get("links", {}).get("next") else 0)
        _vtc[s] = c
        os.makedirs(os.path.dirname(_VCP), exist_ok=True)
        json.dump(_vtc, open(_VCP, "w"), indent=2)
        _time.sleep(0.5)
        return c
    except Exception: return -1

def vt_validate(ranked, vt_key, log):
    if not vt_key:
        log.info("[vt] No VT key - skip")
        return ranked
    ck = 0
    for s in ranked:
        if ck >= MAX_VT: break
        v = s["value"]
        if s["score"] < 2.0 or len(v) < 10 or s["type"] != "dex_string": continue
        if re.match(r"https?://|^L[a-z]", v): continue
        h = _vt_search(v, vt_key, log)
        s["vt_hits"] = h
        if h < 0: continue
        ck += 1
        if h == 0: s["score"] += 2.0; s["reason"] += " +VT:unique"
        elif h <= 5: s["score"] += 1.0; s["reason"] += f" +VT:rare({h})"
        elif h <= 30: s["reason"] += f" VT:{h}"
        else: s["score"] = 0; s["reason"] += f" -VT:DROP({h})"
        log.info("[vt] '%s' -> %d hits", v[:50], h)
    ranked = [s for s in ranked if s["score"] > 0]
    ranked.sort(key=lambda x: -x["score"])
    log.info("[vt] Checked %d. %d remain.", ck, len(ranked))
    return ranked

def _get_examples(cat):
    p = os.path.join(_SD, "yara_exports", "zstatic-apk-sig.yara")
    if not os.path.isfile(p): return ""
    try:
        c = open(p, "r", encoding="utf-8", errors="replace").read()
    except Exception:
        return ""
    ms = re.findall(r"(rule\s+Android_\w*" + re.escape(cat) + r"\w*\s*:\s*knownmalware\s*\{[\s\S]*?\n\})", c, re.I)
    if not ms:
        ms = re.findall(r"(rule\s+Android_\w+\s*:\s*knownmalware\s*\{[\s\S]*?\n\})", c)
    return "\n\n".join(m.strip() for m in ms[:2] if len(m) < 3000)

def build_prompt(ranked, facts, asmt, verdict, examples, fam, sha):
    dex = [r for r in ranked if r["type"] == "dex_string"][:15]
    comp = [r for r in ranked if r["type"] == "manifest_component"][:5]
    ast = [r for r in ranked if r["type"] == "asset_path"][:3]
    dl = []
    for r in dex:
        vt = f" VT={r['vt_hits']}" if r.get("vt_hits", -1) >= 0 else ""
        dl.append(f'  [{r["score"]:.1f}{vt}] "{r["value"]}"  ({r["reason"]})')
    cl = [f'  {r["value"]}  ({r["reason"]})' for r in comp]
    al = [f'  {r["value"]}  ({r["reason"]})' for r in ast]
    sb = []
    if facts.classes and facts.class_api_scores:
        for cn, sc in sorted(facts.class_api_scores.items(), key=lambda x: -x[1])[:2]:
            src = facts.classes.get(cn, "")
            if src: sb.append(f"--- {cn} (score={sc:.2f}) ---\n{src[:2000]}")
    mc = [f"  {f}: {a.verdict} ({a.confidence:.2f})"
          for f, a in sorted(asmt.items(), key=lambda x: -x[1].confidence)
          if a.verdict == "malicious"]
    sys = (
        "You are an expert YARA rule author for Android malware.\n\n"
        "TARGET: APK dump .bin files with decoded AndroidManifest.xml and RAW DEX binary. "
        "String constants from code appear as plain ASCII in the DEX.\n\n"
        "GOOD STRINGS: bot commands, C2 paths, log messages, unique service names, AMStrings.\n"
        "BAD STRINGS: SDK refs (Jiguang, Bolts, Lottie), random package names, generic permissions.\n\n"
        "Use ONLY the VERIFIED strings I provide. "
        "Categorize: $cmd_*, $c2_*, $bot_*. Flexible conditions.\n"
        "Include meta: threatname, category, risk=127, date, author=pipeline-auto.\n"
        "Return ONLY the YARA rule. No markdown, no explanation.\n"
    )
    usr = f"SAMPLE: {fam} | SHA={sha[:16]}... | Risk={verdict.get('Risk-Score', 0)}\n"
    usr += f"Package: {facts.basic_info.get('package_name', '?')}\n"
    usr += f"Summary: {verdict.get('Summary', '')[:300]}\n\n"
    if mc: usr += "MALICIOUS BEHAVIORS:\n" + "\n".join(mc) + "\n\n"
    if dl: usr += "DEX STRINGS (highest quality):\n" + "\n".join(dl) + "\n\n"
    if cl: usr += "MANIFEST COMPONENTS:\n" + "\n".join(cl) + "\n\n"
    if al: usr += "SUSPICIOUS ASSETS:\n" + "\n".join(al) + "\n\n"
    if sb: usr += "DECOMPILED SOURCE:\n" + "\n".join(sb) + "\n\n"
    if examples: usr += "EXAMPLE RULES:\n" + examples[:3000] + "\n\n"
    usr += f"Write the YARA rule. Name: Android_{fam}_Pipeline_<date>\n"
    if len(sys) + len(usr) > 28000: usr = usr[:28000 - len(sys)]

def _yara_exe():
    f = shutil.which("yara") or shutil.which("yara64")
    if f: return f
    for n in ("yara64.exe", "yara64", "yara"):
        p = os.path.join(_SD, "yara-master-v4.5.4-win64", n)
        if os.path.isfile(p): return p
    return None

def _raw_text(resp):
    if isinstance(resp, str): return resp
    if isinstance(resp, dict):
        for k in ("summary", "rule", "yara", "snort", "content"):
            v = resp.get(k)
            if isinstance(v, str) and len(v) > 20: return v
        return str(resp)
    return str(resp)

def _strip_md(t):
    t = t.strip()
    if t.startswith("```"):
        t = "\n".join(l for l in t.split("\n") if not l.strip().startswith("```")).strip()
    return t

def _validate(rule, bf, log):
    r = {"valid": False, "compiles": False, "self_matches": False, "error": ""}
    ye = _yara_exe()
    if not ye:
        r["error"] = "No yara"
        r["valid"] = rule.startswith("rule ")
        return r
    d = tempfile.mkdtemp(prefix="yv_")
    rp = os.path.join(d, "r.yara")
    try:
        open(rp, "w").write(rule)
        p = subprocess.run([ye, rp, rp], capture_output=True, text=True, timeout=15)
        r["compiles"] = p.returncode == 0
        if not r["compiles"]:
            r["error"] = p.stderr.strip()[:300]
            return r
        if bf and os.path.isfile(bf):
            p = subprocess.run([ye, rp, bf], capture_output=True, text=True, timeout=30)
            r["self_matches"] = bool(p.stdout.strip())
        r["valid"] = r["compiles"]
    except Exception as e:
        r["error"] = str(e)[:200]
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return r

def _relax(rule):
    n = len(re.findall(r"\$\w+\s*=", rule))
    if n < 2: return rule
    t = min(3, max(2, n // 3))
    nc = f"    condition:\n        {t} of them"
    rx = re.sub(r"condition:\s*\n[\s\S]*?\n\}", nc + "\n}", rule)
    if rx == rule:
        rx = re.sub(r"condition:[\s\S]*$", nc + "\n}", rule)
    return rx

def _save(d, fn, c):
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, fn)
    open(p, "w", encoding="utf-8").write(c)
    return p

def _find_bin(ap):
    bd = os.path.join(os.path.dirname(ap), f"bin_{os.path.basename(ap)}")
    if os.path.isdir(bd):
        for f in os.listdir(bd):
            if f.endswith("_apk_dump.bin"):
                return os.path.join(bd, f)
    try:
        md5 = hashlib.md5(open(ap, "rb").read()).hexdigest()
        c = os.path.join(bd, f"{md5}_apk_dump.bin")
        if os.path.isfile(c): return c
    except Exception:
        pass
    return None

def _family(v, ym):
    for y in ym:
        ps = y.get("detection_rule", "").split("_")
        if len(ps) >= 4: return ps[2]
    s = v.get("Summary", "")
    for k in ("FluBot", "SpyNote", "Cerberus", "BankBot", "Ahmyth",
              "Spymax", "Anubis", "Triada", "Coper", "Mamont",
              "Anatsa", "Ermac", "SoumniBot", "TsarBot", "Crocodilus"):
        if k.lower() in s.lower(): return k

def _snort(ev, v, fam):
    doms, ips, urls = [], [], []
    for e in ev:
        if e.direction == "benign": continue
        if e.kind in ("vt_dns", "vt_http", "vt_ip"):
            for d in re.findall(r"\b[\w.-]+\.(?:com|net|org|io|xyz|ru|cn|tk|top)\b", e.value, re.I):
                if d not in doms: doms.append(d)
            for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", e.value):
                if ip not in ips: ips.append(ip)
        if e.kind == "string" and re.match(r"https?://", e.value, re.I):
            urls.append(e.value)
    if not doms and not ips and not urls: return None
    sy = "You are a Snort/Suricata rule author.\nWrite Snort 3 rules. sid from 9900001.\nReturn ONLY rule text.\n"
    us = f"Malware: {fam}\nDomains: {', '.join(doms[:15])}\nIPs: {', '.join(ips[:15])}\nURLs: {chr(10).join(urls[:8])}\n"
    return [{"role": "system", "content": sy}, {"role": "user", "content": us}]

def _cif(ev, fam, sha):
    today = dt.datetime.utcnow().strftime("%Y-%m-%d")
    tags = ["malware", "android", fam.lower()]
    entries, seen = [], set()
    for e in ev:
        if e.direction != "malicious": continue
        for d in re.findall(r"\b[\w.-]+\.(?:com|net|org|io|xyz|ru|cn|tk|top)\b", e.value, re.I):
            if d.lower() not in seen:
                seen.add(d.lower())
                entries.append({"indicator": d, "itype": "fqdn", "tags": tags,
                    "confidence": 8, "provider": "apk-pipeline", "sha256": sha,
                    "first_seen": today, "last_seen": today})
    return entries

def generate_rules(apk_path, apk_facts, evidence_items, clusters,
                   assessments, verdict, yara_matches,
                   logger, llm_client, vt_api_key=None):
    from modified_trial8_multiple_models import call_llm
    fam = _family(verdict, yara_matches)
    cat = _category(assessments)
    sha = ""
    try:
        sha = hashlib.sha256(open(apk_path, "rb").read()).hexdigest()
    except Exception:
        sha = os.path.basename(apk_path).replace(".apk", "")
    out = {"yara_rule": None, "yara_rule_path": None, "yara_validation": None,
           "snort_rules": None, "snort_rules_path": None,
           "cif_entries": [], "cif_path": None,
           "ioc_summary": {"family": fam, "category": cat}}
    dtag = dt.datetime.utcnow().strftime("%y%m%d")
    ss = sha[:8]
    bf = _find_bin(apk_path)
    if not bf:
        logger.warning("[rule_gen] No bin dump - skip YARA")
    else:
        logger.info("[rule_gen] Bin: %s", bf)
        parsed = parse_bin_dump(bf)
        logger.info("[rule_gen] Parsed: %d dex, %d comp, %d assets",
                    len(parsed["dex_strings"]),
                    len(parsed["manifest_components"]),
                    len(parsed["asset_paths"]))
        ranked = rank_strings(parsed, apk_facts, evidence_items, verdict)
        logger.info("[rule_gen] Ranked: %d. Top: %s", len(ranked),
                    f'{ranked[0]["score"]:.1f} "{ranked[0]["value"][:50]}"'
                    if ranked else "none")
        ranked = vt_validate(ranked, vt_api_key, logger)
        out["ioc_summary"]["ranked_strings"] = len(ranked)
        if len(ranked) >= 3:
            ex = _get_examples(cat)
            msgs = build_prompt(ranked, apk_facts, assessments,
                                verdict, ex, fam, sha)
            ps = sum(len(m.get("content", "")) for m in msgs)
            logger.info("[rule_gen] LLM YARA (prompt=%d chars)", ps)
            try:
                raw = call_llm(msgs, MODEL, logger, llm_client)
                yara = _strip_md(_raw_text(raw))
                out["yara_rule"] = yara
                val = _validate(yara, bf, logger)
                out["yara_validation"] = val
                if val["compiles"] and val["self_matches"]:
                    fn = f"Android_{cat}_{fam}_{ss}_{dtag}.yara"
                    out["yara_rule_path"] = _save(_YD, fn, yara)
                    logger.info("[rule_gen] YARA saved: %s",
                                out["yara_rule_path"])
                elif val["compiles"]:
                    logger.warning("[rule_gen] Self-match fail - relaxing")
                    rx = _relax(yara)
                    if rx != yara:
                        v2 = _validate(rx, bf, logger)
                        if v2["compiles"] and v2["self_matches"]:
                            out["yara_rule"] = rx
                            out["yara_validation"] = v2
                            fn = f"Android_{cat}_{fam}_{ss}_{dtag}.yara"
                            out["yara_rule_path"] = _save(_YD, fn, rx)
                            logger.info("[rule_gen] YARA saved (relaxed): %s",
                                        out["yara_rule_path"])
                        else:
                            logger.warning("[rule_gen] Relaxed also failed")
                    else:
                        logger.warning("[rule_gen] Could not relax")
                else:
                    logger.warning("[rule_gen] Compile error: %s",
                                   val["error"])
            except Exception as e:
                logger.error("[rule_gen] YARA failed: %s", e)
        else:
            logger.info("[rule_gen] Only %d ranked - skip YARA",
                        len(ranked))
    sm = _snort(evidence_items, verdict, fam)
    if sm:
        logger.info("[rule_gen] LLM Snort")
        try:
            raw = call_llm(sm, MODEL, logger, llm_client)
            txt = _strip_md(_raw_text(raw))
            out["snort_rules"] = txt
            fn = f"Android_{fam}_{ss}_{dtag}.rules"
            out["snort_rules_path"] = _save(_ND, fn, txt)
            logger.info("[rule_gen] Snort: %s", out["snort_rules_path"])
        except Exception as e:
            logger.error("[rule_gen] Snort failed: %s", e)
    cif = _cif(evidence_items, fam, sha)
    if cif:
        out["cif_entries"] = cif
        fn = f"{dtag}_{fam}_{ss}.json"
        out["cif_path"] = _save(_CD, fn, json.dumps(cif, indent=2))
        logger.info("[rule_gen] CIF: %d -> %s", len(cif), out["cif_path"])
    logger.info("[rule_gen] Done: YARA=%s Snort=%s CIF=%d",
                "saved" if out["yara_rule_path"]
                else ("gen" if out["yara_rule"] else "skip"),
                "OK" if out["snort_rules"] else "skip", len(cif))
    return out
