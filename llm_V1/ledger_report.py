"""Quick report: samples analyzed, signatures created, YARA registry state."""
import sqlite3, os, sys

_SD = os.path.dirname(os.path.abspath(__file__))
LDB = os.path.join(_SD, "generated_rules", "androai_ledger.sqlite")
YDB = os.path.join(_SD, "generated_rules", "yara_rule_registry.sqlite")


def q(db, sql):
    if not os.path.isfile(db):
        return []
    c = sqlite3.connect(db)
    c.row_factory = sqlite3.Row
    rows = c.execute(sql).fetchall()
    c.close()
    return [dict(r) for r in rows]


def main():
    for label, days in [("LAST 7 DAYS", 7), ("LAST 14 DAYS", 14), ("ALL TIME", 99999)]:
        print(f"\n{'='*50}")
        print(f"  {label}")
        print(f"{'='*50}")
        r = q(LDB,
            f"SELECT COUNT(*) as total,"
            f"SUM(CASE WHEN verdict='malicious' THEN 1 ELSE 0 END) as malicious,"
            f"SUM(CASE WHEN verdict='suspicious' THEN 1 ELSE 0 END) as suspicious,"
            f"SUM(CASE WHEN verdict='clean' THEN 1 ELSE 0 END) as clean,"
            f"SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as failed,"
            f"SUM(CASE WHEN status='corrupt' THEN 1 ELSE 0 END) as corrupt,"
            f"COALESCE(SUM(yara_created),0) as yara_created,"
            f"COALESCE(SUM(snort_created),0) as snort_created,"
            f"COALESCE(SUM(cif_created),0) as cif_created,"
            f"COALESCE(ROUND(AVG(analysis_time_sec),1),0) as avg_time "
            f"FROM analyzed_samples "
            f"WHERE updated_at >= datetime('now','-{days} days')")
        if r:
            d = r[0]
            print(f"  Samples analyzed:  {d['total']}")
            print(f"    Malicious:       {d['malicious'] or 0}")
            print(f"    Suspicious:      {d['suspicious'] or 0}")
            print(f"    Clean:           {d['clean'] or 0}")
            print(f"    Failed:          {d['failed'] or 0}")
            print(f"    Corrupt:         {d['corrupt'] or 0}")
            print(f"  Signatures created:")
            print(f"    YARA:            {d['yara_created']}")
            print(f"    Suricata/Snort:  {d['snort_created']}")
            print(f"    CIF:             {d['cif_created']}")
            print(f"  Avg analysis time: {d['avg_time']}s")
        else:
            print("  (no data)")

    # Pipeline breakdown
    print(f"\n{'='*50}")
    print(f"  BY PIPELINE SOURCE")
    print(f"{'='*50}")
    rows = q(LDB,
        "SELECT pipeline_source, COUNT(*) as total,"
        "SUM(CASE WHEN verdict='malicious' THEN 1 ELSE 0 END) as mal,"
        "SUM(CASE WHEN verdict='suspicious' THEN 1 ELSE 0 END) as sus,"
        "SUM(CASE WHEN verdict='clean' THEN 1 ELSE 0 END) as cln,"
        "COALESCE(SUM(yara_created),0) as yara,"
        "COALESCE(SUM(snort_created),0) as snort,"
        "COALESCE(SUM(cif_created),0) as cif "
        "FROM analyzed_samples WHERE status='done' "
        "GROUP BY pipeline_source ORDER BY total DESC")
    if rows:
        print(f"  {'Source':<20s} {'Total':>6s} {'Mal':>5s} {'Sus':>5s} {'Cln':>5s} {'YARA':>5s} {'Snort':>5s} {'CIF':>5s}")
        print(f"  {'-'*20} {'-'*6} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*5}")
        for r in rows:
            print(f"  {r['pipeline_source']:<20s} {r['total']:>6d} {r['mal'] or 0:>5d} {r['sus'] or 0:>5d} {r['cln'] or 0:>5d} {r['yara']:>5d} {r['snort']:>5d} {r['cif']:>5d}")
    else:
        print("  (no data)")

    # YARA registry state
    print(f"\n{'='*50}")
    print(f"  YARA REGISTRY STATE")
    print(f"{'='*50}")
    rows = q(YDB,
        "SELECT status, COUNT(*) as cnt FROM yara_rules GROUP BY status ORDER BY cnt DESC")
    if rows:
        total = sum(r["cnt"] for r in rows)
        print(f"  Total rules: {total}")
        for r in rows:
            pct = round(100 * r["cnt"] / total, 1) if total else 0
            print(f"    {r['status']:<15s} {r['cnt']:>6d}  ({pct}%)")
    else:
        print("  (no data)")

    print()


if __name__ == "__main__":
    main()
