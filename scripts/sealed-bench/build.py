# build.py: makes sealed.jsonl, the sealed attack set (docs/benchmarks.md).
# Sentinel's rules and model are never tuned on it.
#   git clone --depth 1 https://github.com/danielmiessler/SecLists seclists   (commit db92535 for the published numbers)
#   python build.py        (needs mal.jsonl from the open-appsec WAF comparison next to it, to drop overlaps)
# Replay each request at the WAF (status 403 = blocked) and write out-NAME.jsonl lines {"i": row, "status": code};
# then: python score.py NAME
import json, random, glob, urllib.parse, os, sys
base = 'seclists/Fuzzing/'
fam = {
 'sqli': [f for f in glob.glob(base+'Databases/SQLi/**/*.txt', recursive=True)],
 'xss': [base+'XSS/robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt', base+'XSS/robot-friendly/XSS-OFJAAAH.txt', base+'XSS/robot-friendly/XSS-payloadbox.txt'],
 'lfi': [base+'LFI/LFI-Jhaddix.txt', base+'LFI/Linux/LFI-gracefulsecurity-linux.txt'],
 'cmdi': [base+'command-injection-commix.txt'],
 'ssti': [base+'template-engines-expression.txt'],
 'xxe': [base+'XXE-Fuzzing.txt'],
}
seen = set()
for l in open('mal.jsonl'):
    r = json.loads(l); seen.add(urllib.parse.unquote_plus(r['url'].split('p=',1)[-1])); seen.add(urllib.parse.unquote_plus(r['data'][2:]))
ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36", "Accept": "text/html,*/*"}
rnd = random.Random(7); out = []; stats = {}
for f, files in fam.items():
    ps = set()
    for fn in files:
        for line in open(fn, encoding='utf-8', errors='ignore'):
            p = line.rstrip('\r\n')
            if len(p.strip()) >= 4 and not p.startswith('#') and p not in seen: ps.add(p)
    ps = sorted(ps); rnd.shuffle(ps); ps = ps[:1500]; stats[f] = len(ps)
    for p in ps:
        q = urllib.parse.quote(p, safe='')
        out.append({'method':'GET','url':'/search?q='+q,'headers':json.dumps(ua),'data':'','test':f})
        out.append({'method':'POST','url':'/form','headers':json.dumps({**ua,'Content-Type':'application/x-www-form-urlencoded'}),'data':'q='+q,'test':f})
with open('sealed.jsonl','w') as w:
    for r in out: w.write(json.dumps(r)+'\n')
print(stats, len(out))
