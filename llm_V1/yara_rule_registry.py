"""yara_rule_registry.py - SQLite registry for YARA rules + refinement state."""
from __future__ import annotations
import hashlib,json,os,re,sqlite3,threading,uuid
from dataclasses import dataclass
from datetime import datetime,timezone
from typing import Any,Dict,List,Optional,Tuple

_SD=os.path.dirname(os.path.abspath(__file__))
_DB=os.path.join(_SD,"generated_rules","yara_rule_registry.sqlite")

def _now():return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def _norm(t):
    t=re.sub(r"//[^\n]*","",t);t=re.sub(r"/\*.*?\*/","",t,flags=re.DOTALL)
    return re.sub(r"\s+"," ",t).strip()
def compute_rule_hash(t):return hashlib.sha256(_norm(t).encode()).hexdigest()
def extract_string_literals(t):return[m.group(1) for m in re.finditer(r'\$\w*\s*=\s*"([^"]+)"',t)]
def compute_string_fingerprint(t):
    return hashlib.sha256("|".join(sorted(set(s.lower() for s in extract_string_literals(t)))).encode()).hexdigest()
def compute_string_overlap(a,b):
    sa=set(s.lower() for s in extract_string_literals(a))
    sb=set(s.lower() for s in extract_string_literals(b))
    return len(sa&sb)/len(sa|sb) if sa and sb else 0.0

@dataclass
class RuleRecord:
    rule_id:str;rule_name:str;family:str;category:str;sha256_source:str
    rule_text:str;rule_hash:str;string_fingerprint:str;status:str
    retrohunt_job_id:Optional[str];refinement_round:int
    max_refinement_rounds:int;fp_count:int;suspicious_fp_count:int
    created_at:str;updated_at:str;runner_id:str;rule_file_path:str
    goodware_tested:bool=False;retrohunt_corpus:str="main"

_SCHEMA="""
CREATE TABLE IF NOT EXISTS yara_rules(
 rule_id TEXT PRIMARY KEY,rule_name TEXT NOT NULL,family TEXT NOT NULL,
 category TEXT DEFAULT '',sha256_source TEXT DEFAULT '',
 rule_text TEXT NOT NULL,rule_hash TEXT NOT NULL,
 string_fingerprint TEXT DEFAULT '',status TEXT DEFAULT 'draft',
 retrohunt_job_id TEXT,refinement_round INTEGER DEFAULT 0,
 max_refinement_rounds INTEGER DEFAULT 3,fp_count INTEGER DEFAULT 0,
 suspicious_fp_count INTEGER DEFAULT 0,created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,runner_id TEXT DEFAULT '',
 rule_file_path TEXT DEFAULT '',goodware_tested INTEGER DEFAULT 0,
 retrohunt_corpus TEXT DEFAULT 'main');
CREATE INDEX IF NOT EXISTS idx_ys ON yara_rules(status);
CREATE INDEX IF NOT EXISTS idx_yf ON yara_rules(family);
CREATE INDEX IF NOT EXISTS idx_yh ON yara_rules(rule_hash);
CREATE TABLE IF NOT EXISTS retrohunt_jobs(
 job_id TEXT PRIMARY KEY,rule_id TEXT NOT NULL,
 vt_api_key_name TEXT DEFAULT '',corpus TEXT DEFAULT 'main',
 status TEXT DEFAULT 'submitted',progress REAL DEFAULT 0.0,
 num_matches INTEGER DEFAULT 0,submitted_at TEXT NOT NULL,
 finished_at TEXT,FOREIGN KEY(rule_id) REFERENCES yara_rules(rule_id));
CREATE TABLE IF NOT EXISTS fp_samples(
 id INTEGER PRIMARY KEY AUTOINCREMENT,rule_id TEXT NOT NULL,
 retrohunt_job_id TEXT NOT NULL,sha256 TEXT NOT NULL,
 classification TEXT DEFAULT 'unknown',malicious_count INTEGER DEFAULT 0,
 has_malicious_parent INTEGER DEFAULT 0,
 matched_strings TEXT DEFAULT '[]',details TEXT DEFAULT '{}',
 created_at TEXT NOT NULL,
 FOREIGN KEY(rule_id) REFERENCES yara_rules(rule_id));
CREATE INDEX IF NOT EXISTS idx_fp ON fp_samples(rule_id);
"""

class YaraRuleRegistry:
    def __init__(self,db_path=None):
        self._p=db_path or _DB
        os.makedirs(os.path.dirname(self._p),exist_ok=True)
        self._local=threading.local();self._init()
    def _c(self):
        if not hasattr(self._local,"c") or self._local.c is None:
            c=sqlite3.connect(self._p,timeout=30)
            c.execute("PRAGMA journal_mode=WAL");c.execute("PRAGMA busy_timeout=10000")
            c.row_factory=sqlite3.Row;self._local.c=c
        return self._local.c
    def _init(self):c=self._c();c.executescript(_SCHEMA);c.commit()
    def close(self):
        if hasattr(self._local,"c") and self._local.c:
            self._local.c.close();self._local.c=None
    def register_rule(self,*,rule_name,family,category,sha256_source,
                      rule_text,rule_file_path,runner_id="",max_refinement_rounds=3)->Tuple[str,str]:
        rh=compute_rule_hash(rule_text);sf=compute_string_fingerprint(rule_text);now=_now();c=self._c()
        row=c.execute("SELECT rule_id FROM yara_rules WHERE rule_hash=?",(rh,)).fetchone()
        if row:return row["rule_id"],"duplicate"
        for ex in c.execute("SELECT rule_id,rule_text,string_fingerprint FROM yara_rules "
                            "WHERE family=? AND status NOT IN('rejected','superseded')",(family,)):
            if compute_string_overlap(rule_text,ex["rule_text"])>=0.70:
                if len(extract_string_literals(rule_text))>len(extract_string_literals(ex["rule_text"])):
                    c.execute("UPDATE yara_rules SET status='superseded',updated_at=? WHERE rule_id=?",(now,ex["rule_id"]));c.commit();break
                else:return ex["rule_id"],"superseded"
        rid=uuid.uuid4().hex[:16]
        c.execute("INSERT INTO yara_rules(rule_id,rule_name,family,category,sha256_source,"
                  "rule_text,rule_hash,string_fingerprint,status,refinement_round,"
                  "max_refinement_rounds,fp_count,suspicious_fp_count,created_at,"
                  "updated_at,runner_id,rule_file_path) "
                  "VALUES(?,?,?,?,?,?,?,?,'draft',0,?,0,0,?,?,?,?)",
                  (rid,rule_name,family,category,sha256_source,rule_text,rh,sf,
                   max_refinement_rounds,now,now,runner_id,rule_file_path))
        c.commit();return rid,"registered"
    def get_rules_by_status(self,status)->List[RuleRecord]:
        return[self._r(r) for r in self._c().execute("SELECT * FROM yara_rules WHERE status=? ORDER BY created_at",(status,))]
    def get_rule(self,rid)->Optional[RuleRecord]:
        r=self._c().execute("SELECT * FROM yara_rules WHERE rule_id=?",(rid,)).fetchone()
        return self._r(r) if r else None
    def get_all_rules(self)->List[RuleRecord]:
        return[self._r(r) for r in self._c().execute("SELECT * FROM yara_rules ORDER BY created_at")]
    def status_counts(self)->Dict[str,int]:
        return{r["status"]:r["cnt"] for r in self._c().execute("SELECT status,COUNT(*) as cnt FROM yara_rules GROUP BY status")}
    def update_status(self,rid,status,**kw):
        s=["status=?","updated_at=?"];v=[status,_now()]
        for k,val in kw.items():s.append(f"{k}=?");v.append(val)
        v.append(rid);self._c().execute(f"UPDATE yara_rules SET {','.join(s)} WHERE rule_id=?",v);self._c().commit()
    def update_rule_text(self,rid,txt,path):
        self._c().execute("UPDATE yara_rules SET rule_text=?,rule_hash=?,string_fingerprint=?,"
                          "rule_file_path=?,updated_at=? WHERE rule_id=?",
                          (txt,compute_rule_hash(txt),compute_string_fingerprint(txt),path,_now(),rid));self._c().commit()
    def increment_refinement_round(self,rid)->int:
        c=self._c();c.execute("UPDATE yara_rules SET refinement_round=refinement_round+1,updated_at=? WHERE rule_id=?",(_now(),rid));c.commit()
        r=c.execute("SELECT refinement_round FROM yara_rules WHERE rule_id=?",(rid,)).fetchone()
        return r["refinement_round"] if r else 0
    def record_retrohunt_job(self,*,rule_id,job_id,vt_key_name="",corpus="main"):
        self._c().execute("INSERT OR REPLACE INTO retrohunt_jobs(job_id,rule_id,vt_api_key_name,"
                          "corpus,status,progress,num_matches,submitted_at) VALUES(?,?,?,?,'submitted',0.0,0,?)",
                          (job_id,rule_id,vt_key_name,corpus,_now()));self._c().commit()
    def update_retrohunt_job(self,jid,*,status="",progress=-1.0,num_matches=-1,finished_at=""):
        s,v=[],[]
        if status:s.append("status=?");v.append(status)
        if progress>=0:s.append("progress=?");v.append(progress)
        if num_matches>=0:s.append("num_matches=?");v.append(num_matches)
        if finished_at:s.append("finished_at=?");v.append(finished_at)
        if not s:return
        v.append(jid);self._c().execute(f"UPDATE retrohunt_jobs SET {','.join(s)} WHERE job_id=?",v);self._c().commit()
    def get_active_job_count_for_key(self,name)->int:
        r=self._c().execute("SELECT COUNT(*) as cnt FROM retrohunt_jobs "
                            "WHERE vt_api_key_name=? AND status IN('submitted','running')",(name,)).fetchone()
        return r["cnt"] if r else 0
    def record_fp_sample(self,*,rule_id,retrohunt_job_id,sha256,classification,
                         malicious_count=0,has_malicious_parent=False,matched_strings=None,details=None):
        self._c().execute("INSERT INTO fp_samples(rule_id,retrohunt_job_id,sha256,classification,"
                          "malicious_count,has_malicious_parent,matched_strings,details,created_at) "
                          "VALUES(?,?,?,?,?,?,?,?,?)",
                          (rule_id,retrohunt_job_id,sha256,classification,malicious_count,
                           int(has_malicious_parent),json.dumps(matched_strings or[]),
                           json.dumps(details or{}),_now()));self._c().commit()
    def get_fp_samples(self,rule_id,retrohunt_job_id="")->List[Dict[str,Any]]:
        if retrohunt_job_id:
            rows=self._c().execute("SELECT * FROM fp_samples WHERE rule_id=? AND retrohunt_job_id=?",
                                   (rule_id,retrohunt_job_id)).fetchall()
        else:rows=self._c().execute("SELECT * FROM fp_samples WHERE rule_id=?",(rule_id,)).fetchall()
        return[dict(r) for r in rows]
    @staticmethod
    def _r(row)->RuleRecord:
        return RuleRecord(rule_id=row["rule_id"],rule_name=row["rule_name"],
            family=row["family"],category=row["category"],sha256_source=row["sha256_source"],
            rule_text=row["rule_text"],rule_hash=row["rule_hash"],
            string_fingerprint=row["string_fingerprint"],status=row["status"],
            retrohunt_job_id=row["retrohunt_job_id"],refinement_round=row["refinement_round"],
            max_refinement_rounds=row["max_refinement_rounds"],fp_count=row["fp_count"],
            suspicious_fp_count=row["suspicious_fp_count"],created_at=row["created_at"],
            updated_at=row["updated_at"],runner_id=row["runner_id"],
            rule_file_path=row["rule_file_path"],goodware_tested=bool(row["goodware_tested"]),
            retrohunt_corpus=row["retrohunt_corpus"])
