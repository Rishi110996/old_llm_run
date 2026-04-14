"""Find good download candidates from VT and print full SHA256s."""
import io, sys, yaml, requests, os
if hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

_DIR = os.path.dirname(os.path.abspath(__file__))
cfg = yaml.safe_load(open(os.path.join(_DIR, '..', 'vt_apk_downloader', 'config.yaml')))
key = next(k['key'] for k in cfg['api']['keys'] if k.get('tier') == 'premium' and k.get('key'))
headers = {'x-apikey': key}

queries = [
    ('benign',  'type:apk p:0',                                  0,   0, 50000, 600000),
    ('anubis',  'type:apk engines:Anubis p:10+',                 10, 99, 50000, 600000),
    ('bankbot', 'type:apk engines:Bankbot p:10+ size:50KB-500KB', 10, 99, 50000, 600000),
]

for label, q, min_mal, max_mal, min_sz, max_sz in queries:
    r = requests.get(
        'https://www.virustotal.com/api/v3/intelligence/search',
        headers=headers,
        params={'query': q, 'limit': 20},
        timeout=30,
    )
    items = r.json().get('data', [])
    print()
    print('=== ' + label + ' (' + str(len(items)) + ' results) ===')
    found = 0
    for item in items:
        sha = item.get('id', '')
        a = item.get('attributes', {})
        sz = int(a.get('size') or 0)
        stats = a.get('last_analysis_stats', {})
        mal = int(stats.get('malicious') or 0)
        dl = a.get('downloadable', True)
        nm = a.get('meaningful_name', '') or ''
        tt = a.get('type_tag', '') or ''
        if sz < min_sz or sz > max_sz:
            continue
        if mal < min_mal or mal > max_mal:
            continue
        if not dl:
            continue
        # Must look like APK
        tags = a.get('tags') or []
        is_apk = tt in ('android', 'apk') or 'apk' in tags
        if not is_apk:
            continue
        print('  sha256=' + sha + '  mal=' + str(mal) + '  sz=' + str(sz // 1024) + 'KB  name=' + nm[:40])
        found += 1
        if found >= 3:
            break
    if found == 0:
        print('  (no matching results)')
