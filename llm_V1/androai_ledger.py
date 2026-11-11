"""androai_ledger.py - Central tamper-protected analysis ledger + sample cache.

Two tables in one DB:
  analyzed_samples  -- every sample ever processed (dashboard / audit)
  sample_cache      -- cross-batch dedup (skip re-analysis within TTL)

Protection layers:
  1. Application-level: destructive ops (DELETE/DROP/TRUNCATE) require passphrase
  2. OS-level: chattr +i (immutable) set on DB file after writes
  3. Backup: periodic .bak copy also made immutable

The passphrase is set once on first DB creation and stored as bcrypt/sha256 hash.
"""
from __future__ import annotations
import hashlib,json,logging,os,platform,shutil,sqlite3,subprocess,threading
from datetime import datetime,timezone,timedelta
from typing import Any,Dict,List,Optional,Tuple

_SD=os.path.dirname(os.path.abspath(__file__))
_DEFAULT_DB=os.path.join(_SD,"generated_rules","androai_ledger.sqlite")
_BACKUP_EVERY_N=50  # backup after every N writes
_log=logging.getLogger("androai_ledger")

def _now()->str:return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def _hash_passphrase(p:str)->str:return hashlib.sha256(p.encode("utf-8")).hexdigest()

# ---------------------------------------------------------------------------
# OS-level immutable flag helpers (Linux chattr +i / -i)
# ---------------------------------------------------------------------------

def _is_linux()->bool:return platform.system()=="Linux"

def _set_immutable(path:str)->bool:
    if not _is_linux() or not os.path.isfile(path):return False
    try:
        r=subprocess.run(["chattr","+i",path],capture_output=True,timeout=5)
        return r.returncode==0
    except Exception:return False

def _clear_immutable(path:str)->bool:
    if not _is_linux() or not os.path.isfile(path):return False
    try:
        r=subprocess.run(["chattr","-i",path],capture_output=True,timeout=5)
        return r.returncode==0
    except Exception:return False

def _make_backup(db_path:str)->Optional[str]:
    bak=db_path+".bak"
    try:
        _clear_immutable(bak)  # remove immutable from old backup
        shutil.copy2(db_path,bak)
        _set_immutable(bak)
        return bak
    except Exception as e:
        _log.warning("[ledger] backup failed: %s",e)
        return None
_SCHEMA="""
CREATE TABLE IF NOT EXISTS _meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analyzed_samples(
    sha256              TEXT PRIMARY KEY,
    apk_name            TEXT,
    package_name        TEXT DEFAULT '',
    family              TEXT DEFAULT '',
    pipeline_source     TEXT DEFAULT 'manual',
    verdict             TEXT DEFAULT '',
    risk_score          INTEGER DEFAULT 0,
    summary             TEXT DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'in_progress',
    error_note          TEXT DEFAULT '',
    analysis_time_sec   REAL DEFAULT 0,
    started_at          TEXT,
    finished_at         TEXT,
    runner_id           TEXT DEFAULT '',
    llm_key_name        TEXT DEFAULT '',
    llm_call_count      INTEGER DEFAULT 0,
    llm_total_tokens    INTEGER DEFAULT 0,
    yara_created        INTEGER DEFAULT 0,
    yara_rule_name      TEXT DEFAULT '',
    yara_rule_path      TEXT DEFAULT '',
    snort_created       INTEGER DEFAULT 0,
    cif_created         INTEGER DEFAULT 0,
    batch_dir           TEXT DEFAULT '',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_as_status ON analyzed_samples(status);
CREATE INDEX IF NOT EXISTS idx_as_verdict ON analyzed_samples(verdict);
CREATE INDEX IF NOT EXISTS idx_as_finished ON analyzed_samples(finished_at);
CREATE INDEX IF NOT EXISTS idx_as_source ON analyzed_samples(pipeline_source);

CREATE TABLE IF NOT EXISTS sample_cache(
    sha256              TEXT PRIMARY KEY,
    verdict             TEXT NOT NULL,
    risk_score          INTEGER DEFAULT 0,
    analyzed_at         TEXT NOT NULL,
    ttl_days            INTEGER DEFAULT 90,
    force_reanalyze     INTEGER DEFAULT 0
);
"""

class AndroAILedger:
    """Central tamper-protected analysis ledger."""

    def __init__(self,db_path:Optional[str]=None,passphrase:Optional[str]=None):
        self._path=db_path or _DEFAULT_DB
        os.makedirs(os.path.dirname(self._path),exist_ok=True)
        self._local=threading.local()
        self._write_count=0
        self._passphrase=passphrase  # only needed for destructive ops
        self._init_db()

    def _conn(self)->sqlite3.Connection:
        if not hasattr(self._local,"c") or self._local.c is None:
            _clear_immutable(self._path)  # temporarily allow writes
            c=sqlite3.connect(self._path,timeout=30)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA busy_timeout=10000")
            c.row_factory=sqlite3.Row
            self._local.c=c
        return self._local.c

    def _init_db(self):
        c=self._conn();c.executescript(_SCHEMA);c.commit()
        # Set passphrase hash on first creation
        row=c.execute("SELECT value FROM _meta WHERE key='passphrase_hash'").fetchone()
        if not row and self._passphrase:
            h=_hash_passphrase(self._passphrase)
            c.execute("INSERT INTO _meta(key,value) VALUES('passphrase_hash',?)",(h,))
            c.execute("INSERT OR IGNORE INTO _meta(key,value) VALUES('created_at',?)",(_now(),))
            c.commit()
            _log.info("[ledger] passphrase set on new DB")
        elif not row and not self._passphrase:
            # First creation without passphrase -- set a default
            default_pp="androai_ledger_2024"
            h=_hash_passphrase(default_pp)
            c.execute("INSERT INTO _meta(key,value) VALUES('passphrase_hash',?)",(h,))
            c.execute("INSERT OR IGNORE INTO _meta(key,value) VALUES('created_at',?)",(_now(),))
            c.commit()
            _log.warning("[ledger] DB created with DEFAULT passphrase. Set a real one with --init-ledger-passphrase")
        self._after_write()

    def _verify_passphrase(self,pp:str)->bool:
        row=self._conn().execute("SELECT value FROM _meta WHERE key='passphrase_hash'").fetchone()
        if not row:return True  # no passphrase set (should not happen)
        return row["value"]==_hash_passphrase(pp)

    def _after_write(self):
        self._write_count+=1
        if self._write_count%_BACKUP_EVERY_N==0:
            _make_backup(self._path)
        _set_immutable(self._path)

    def close(self):
        if hasattr(self._local,"c") and self._local.c:
            self._local.c.close();self._local.c=None
        _set_immutable(self._path)

    # -- Recording analysis results ----------------------------------------

    def record_analysis(
        self,*,sha256:str,apk_name:str="",package_name:str="",family:str="",
        pipeline_source:str="manual",verdict:str="",risk_score:int=0,
        summary:str="",status:str="done",error_note:str="",
        analysis_time_sec:float=0,started_at:str="",finished_at:str="",
        runner_id:str="",llm_key_name:str="",llm_call_count:int=0,
        llm_total_tokens:int=0,yara_created:bool=False,
        yara_rule_name:str="",yara_rule_path:str="",
        snort_created:bool=False,cif_created:bool=False,batch_dir:str="",
    )->None:
        """Record or update a sample analysis result in the ledger."""
        now=_now()
        _clear_immutable(self._path)
        c=self._conn()
        c.execute(
            "INSERT INTO analyzed_samples("
            "  sha256,apk_name,package_name,family,pipeline_source,verdict,"
            "  risk_score,summary,status,error_note,analysis_time_sec,"
            "  started_at,finished_at,runner_id,llm_key_name,llm_call_count,"
            "  llm_total_tokens,yara_created,yara_rule_name,yara_rule_path,"
            "  snort_created,cif_created,batch_dir,created_at,updated_at"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(sha256) DO UPDATE SET "
            "  apk_name=excluded.apk_name,"
            "  package_name=CASE WHEN excluded.package_name!='' THEN excluded.package_name ELSE analyzed_samples.package_name END,"
            "  family=CASE WHEN excluded.family!='' THEN excluded.family ELSE analyzed_samples.family END,"
            "  pipeline_source=excluded.pipeline_source,"
            "  verdict=excluded.verdict,risk_score=excluded.risk_score,"
            "  summary=excluded.summary,status=excluded.status,"
            "  error_note=excluded.error_note,"
            "  analysis_time_sec=excluded.analysis_time_sec,"
            "  started_at=CASE WHEN excluded.started_at!='' THEN excluded.started_at ELSE analyzed_samples.started_at END,"
            "  finished_at=excluded.finished_at,"
            "  runner_id=excluded.runner_id,llm_key_name=excluded.llm_key_name,"
            "  llm_call_count=excluded.llm_call_count,"
            "  llm_total_tokens=excluded.llm_total_tokens,"
            "  yara_created=excluded.yara_created,"
            "  yara_rule_name=excluded.yara_rule_name,"
            "  yara_rule_path=excluded.yara_rule_path,"
            "  snort_created=excluded.snort_created,"
            "  cif_created=excluded.cif_created,"
            "  batch_dir=excluded.batch_dir,"
            "  updated_at=excluded.updated_at",
            (sha256,apk_name,package_name,family,pipeline_source,verdict,
             risk_score,summary,status,error_note,analysis_time_sec,
             started_at or now,finished_at or now,runner_id,llm_key_name,
             llm_call_count,llm_total_tokens,int(yara_created),
             yara_rule_name,yara_rule_path,int(snort_created),
             int(cif_created),batch_dir,now,now))
        c.commit()
        # Also upsert sample_cache
        if status in("done","corrupt"):
            ttl=90
            try:
                cfg_path=os.path.join(_SD,"config.json")
                with open(cfg_path,"r",encoding="utf-8") as f:cfg=json.load(f)
                ttl=cfg.get("sample_cache",{}).get("ttl_days",90)
            except Exception:pass
            c.execute(
                "INSERT INTO sample_cache(sha256,verdict,risk_score,analyzed_at,ttl_days,force_reanalyze) "
                "VALUES(?,?,?,?,?,0) "
                "ON CONFLICT(sha256) DO UPDATE SET verdict=excluded.verdict,"
                "risk_score=excluded.risk_score,analyzed_at=excluded.analyzed_at,"
                "ttl_days=excluded.ttl_days,force_reanalyze=0",
                (sha256,verdict,risk_score,now,ttl))
            c.commit()
        self._after_write()

    # -- Sample cache check ------------------------------------------------

    def should_skip(self,sha256:str)->Tuple[bool,str]:
        """Check if sample was recently analyzed. Returns (skip, reason)."""
        try:
            enabled=True;skip_clean_only=False
            try:
                with open(os.path.join(_SD,"config.json"),"r",encoding="utf-8") as f:cfg=json.load(f)
                sc=cfg.get("sample_cache",{})
                enabled=sc.get("enabled",True)
                skip_clean_only=sc.get("skip_clean_only",False)
            except Exception:pass
            if not enabled:return False,""
            row=self._conn().execute(
                "SELECT verdict,risk_score,analyzed_at,ttl_days,force_reanalyze "
                "FROM sample_cache WHERE sha256=?",(sha256,)).fetchone()
            if not row:return False,""
            if row["force_reanalyze"]:return False,"force_reanalyze set"
            if skip_clean_only and row["verdict"]!="clean":return False,""
            # Check TTL
            try:
                analyzed=datetime.strptime(row["analyzed_at"],"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                expires=analyzed+timedelta(days=row["ttl_days"])
                if datetime.now(timezone.utc)<expires:
                    return True,f"cached {row['verdict']} (risk={row['risk_score']}) analyzed {row['analyzed_at']}, ttl={row['ttl_days']}d"
            except Exception:pass
            return False,""
        except Exception:return False,""

    def set_force_reanalyze(self,sha256:str)->None:
        _clear_immutable(self._path)
        self._conn().execute("UPDATE sample_cache SET force_reanalyze=1 WHERE sha256=?",(sha256,))
        self._conn().commit();self._after_write()

    # -- Query helpers for dashboard ---------------------------------------

    def get_summary_counts(self)->Dict[str,Any]:
        c=self._conn()
        total=c.execute("SELECT COUNT(*) FROM analyzed_samples").fetchone()[0]
        by_status={r[0]:r[1] for r in c.execute("SELECT status,COUNT(*) FROM analyzed_samples GROUP BY status")}
        by_verdict={r[0]:r[1] for r in c.execute("SELECT verdict,COUNT(*) FROM analyzed_samples WHERE status='done' GROUP BY verdict")}
        yara_count=c.execute("SELECT COUNT(*) FROM analyzed_samples WHERE yara_created=1").fetchone()[0]
        return{"total":total,"by_status":by_status,"by_verdict":by_verdict,"yara_rules_created":yara_count}

    def get_recent(self,limit:int=20)->List[Dict[str,Any]]:
        rows=self._conn().execute(
            "SELECT sha256,apk_name,verdict,risk_score,status,analysis_time_sec,"
            "yara_created,yara_rule_name,pipeline_source,finished_at,error_note "
            "FROM analyzed_samples ORDER BY updated_at DESC LIMIT ?",(limit,)).fetchall()
        return[dict(r) for r in rows]

    def get_all_yara_rules(self)->List[Dict[str,Any]]:
        rows=self._conn().execute(
            "SELECT sha256,apk_name,family,yara_rule_name,yara_rule_path,risk_score,finished_at "
            "FROM analyzed_samples WHERE yara_created=1 ORDER BY finished_at DESC").fetchall()
        return[dict(r) for r in rows]

    def get_sample(self,sha256:str)->Optional[Dict[str,Any]]:
        row=self._conn().execute("SELECT * FROM analyzed_samples WHERE sha256=?",(sha256,)).fetchone()
        return dict(row) if row else None

    # -- Destructive operations (passphrase required) -----------------------

    def clear_all(self,passphrase:str)->Tuple[bool,str]:
        """Delete ALL records. Requires passphrase."""
        if not self._verify_passphrase(passphrase):
            return False,"invalid passphrase"
        _clear_immutable(self._path)
        c=self._conn()
        c.execute("DELETE FROM analyzed_samples")
        c.execute("DELETE FROM sample_cache")
        c.commit();self._after_write()
        return True,"all records deleted"

    def delete_sample(self,sha256:str,passphrase:str)->Tuple[bool,str]:
        """Delete one sample record. Requires passphrase."""
        if not self._verify_passphrase(passphrase):
            return False,"invalid passphrase"
        _clear_immutable(self._path)
        c=self._conn()
        c.execute("DELETE FROM analyzed_samples WHERE sha256=?",(sha256,))
        c.execute("DELETE FROM sample_cache WHERE sha256=?",(sha256,))
        c.commit();self._after_write()
        return True,f"{sha256} deleted"

    def change_passphrase(self,old_pp:str,new_pp:str)->Tuple[bool,str]:
        """Change the passphrase. Requires current passphrase."""
        if not self._verify_passphrase(old_pp):
            return False,"invalid current passphrase"
        _clear_immutable(self._path)
        h=_hash_passphrase(new_pp)
        self._conn().execute("UPDATE _meta SET value=? WHERE key='passphrase_hash'",(h,))
        self._conn().commit();self._after_write()
        return True,"passphrase changed"


# ---------------------------------------------------------------------------
# Module-level singleton for easy access from the pipeline
# ---------------------------------------------------------------------------

_ledger_instance:Optional[AndroAILedger]=None
_ledger_lock=threading.Lock()

def get_ledger(passphrase:Optional[str]=None)->AndroAILedger:
    global _ledger_instance
    with _ledger_lock:
        if _ledger_instance is None:
            _ledger_instance=AndroAILedger(passphrase=passphrase)
        return _ledger_instance


# ---------------------------------------------------------------------------
# CLI for inspection and management
# ---------------------------------------------------------------------------

def main()->int:
    import argparse,sys
    ap=argparse.ArgumentParser(description="AndroAI Analysis Ledger management.")
    ap.add_argument("--status",action="store_true",help="Show summary counts.")
    ap.add_argument("--recent",type=int,default=0,metavar="N",help="Show N most recent analyses.")
    ap.add_argument("--yara-rules",action="store_true",help="List all YARA rules created.")
    ap.add_argument("--lookup",default=None,metavar="SHA256",help="Look up one sample.")
    ap.add_argument("--force-reanalyze",default=None,metavar="SHA256",help="Mark sample for re-analysis.")
    ap.add_argument("--init-passphrase",default=None,help="Set passphrase on new or existing DB.")
    ap.add_argument("--change-passphrase",nargs=2,metavar=("OLD","NEW"),help="Change passphrase.")
    ap.add_argument("--clear-all",default=None,metavar="PASSPHRASE",help="DELETE all records (requires passphrase).")
    args=ap.parse_args()

    ledger=AndroAILedger(passphrase=args.init_passphrase)

    if args.status:
        s=ledger.get_summary_counts()
        print("\n=== AndroAI Analysis Ledger ===")
        print(f"Total samples: {s['total']}")
        print("By status:");[print(f"  {k}: {v}") for k,v in sorted(s["by_status"].items())]
        print("By verdict:");[print(f"  {k}: {v}") for k,v in sorted(s["by_verdict"].items())]
        print(f"YARA rules created: {s['yara_rules_created']}")
        print()

    if args.recent>0:
        print(f"\n--- {args.recent} most recent ---")
        for r in ledger.get_recent(args.recent):
            v=r.get("verdict","?");rs=r.get("risk_score",0);st=r.get("status","?")
            yr="YARA:"+r["yara_rule_name"] if r.get("yara_created") else ""
            err=" err="+r["error_note"][:40] if r.get("error_note") else ""
            print(f"  [{st:7s}] {r['sha256'][:16]} {v:10s} risk={rs:3d} {r.get('analysis_time_sec',0):.1f}s {r.get('pipeline_source','')} {yr}{err}")
        print()

    if args.yara_rules:
        rules=ledger.get_all_yara_rules()
        print(f"\n--- YARA rules ({len(rules)}) ---")
        for r in rules:
            print(f"  {r['sha256'][:16]} {r.get('family','?'):15s} {r['yara_rule_name']}  path={r['yara_rule_path']}")
        print()

    if args.lookup:
        r=ledger.get_sample(args.lookup)
        if r:print(json.dumps(r,indent=2,default=str))
        else:print(f"Sample {args.lookup} not found")

    if args.force_reanalyze:
        ledger.set_force_reanalyze(args.force_reanalyze)
        print(f"Marked {args.force_reanalyze} for re-analysis")

    if args.change_passphrase:
        ok,msg=ledger.change_passphrase(args.change_passphrase[0],args.change_passphrase[1])
        print(f"Change passphrase: {msg}")

    if args.clear_all:
        ok,msg=ledger.clear_all(args.clear_all)
        print(f"Clear all: {msg}")

    ledger.close()
    return 0

if __name__=="__main__":
    import sys;sys.exit(main())
