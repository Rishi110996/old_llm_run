"""Quick VT search probe - no filters, just show what comes back."""
import io, json, os, sys, yaml, requests
if hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

_DIR = os.path.dirname(os.path.abspath(__file__))
cfg = yaml.safe_load(open(os.path.join(_DIR, '..', 'vt_apk_downloader', 'config.yaml')))
key = next(k['key'] for k in cfg['api']['keys'] if k.get('tier') == 'premium' and k.get('key'))

queries = [
    ('benign_apk', 'type:apk tag:apk p:0 size:50KB-400KB'),
    ('benign_apk2', 'type:apk p:0'),
    ('bankbot', 'type:apk tag:apk engines:Bankbot p:15+'),
    ('anubis', 'type:apk engines:Anubis p:10+'),
]

for label, q in queries:
    r = requests.get(
        'https://www.virustotal.com/api/v3/intelligence/search',
        headers={'x-apikey': key},
        params={'query': q, 'limit': 5},
        timeout=30,
    )
    print(f'\n[{label}] HTTP {r.status_code}  query={q}')
    items = r.json().get('data', [])
    print(f'  results: {len(items)}')
    for item in items:
        a = item.get('attributes', {})
        stats = a.get('last_analysis_stats', {})
        sha = item.get('id', '')[:20]
        mal = stats.get('malicious', '?')
        sz = a.get('size', '?')
        nm = a.get('meaningful_name', '')
        tt = a.get('type_tag', '')
        dl = a.get('downloadable', '?')
        tags = str(a.get('tags', []))[:60]
        print(f'  {sha}  mal={mal}  sz={sz}  name={nm}  type={tt}  dl={dl}  tags={tags}')
