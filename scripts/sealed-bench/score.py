# score.py NAME...: blocked share per attack family from out-NAME.jsonl (see build.py)
import json,sys,collections
rows=[json.loads(l) for l in open('sealed.jsonl')]
for n in sys.argv[1:]:
    t=collections.Counter(); b=collections.Counter()
    for x in map(json.loads,open(f'out-{n}.jsonl')):
        f=rows[x['i']]['test']; f='other' if f in('ssti','xxe') else f
        t[f]+=1; b[f]+= x['status']==403
    print(n, {f:f'{100*b[f]/t[f]:.1f}% of {t[f]}' for f in sorted(t)}, f'ALL {100*sum(b.values())/sum(t.values()):.1f}%')
