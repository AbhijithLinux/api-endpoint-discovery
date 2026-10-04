"""Hosted real-time dashboard: crawled sites + endpoints (scroll boxes), click endpoint -> analysis."""
import inspect
import json, pathlib, queue, threading, uuid
from datetime import datetime, timezone
from flask import Flask, Response, jsonify, request

from crawler import crawl
from endpoint_discovery import discover_endpoints, load_wordlist
from endpoint_analysis import EndpointAnalyzer

app = Flask(__name__)
scans = {}
_scan_counter = [0]

SCAN_TTL_SECONDS = 1800  # reports expire 30 minutes after creation

DEFAULT_WORDLIST = str(pathlib.Path(__file__).parent / "common_wordlist.txt")

_FUZZ_PATH_HINTS = ("/api/", "/v1/", "/v2/", "/v3/", "/rest/",
                    "/graphql", "/resources/")


def _fuzz_values(fz):
    """Values for custom param fuzzing: capped numeric range or word list.

    Word values are kept EXACTLY as typed (spacing included — some APIs
    key on values like "Ann Leckie " with a trailing space). Only a
    trailing CR (CRLF uploads) and leading whitespace are removed.
    Allowed chars: letters, digits, space, dot, hyphen, underscore.
    Anything query-breaking (& = ? # / ; : ' ") is rejected.
    """
    if not isinstance(fz, dict):
        return []
    if fz.get("mode") == "words":
        out = []
        for w in (fz.get("words") or [])[:50]:
            w = str(w)
            if w.endswith("\r"):
                w = w[:-1]
            w = w.lstrip()
            if not w or w.startswith("#") or len(w) > 64:
                continue
            if all(c.isalnum() or c in "-_. " for c in w):
                out.append(w)
        return out
    try:
        lo = int(fz.get("from", 1))
        hi = int(fz.get("to", 10))
    except (TypeError, ValueError):
        return []
    lo, hi = max(0, min(lo, hi)), min(max(lo, hi), lo + 49)
    return [str(n) for n in range(lo, hi + 1)][:50]


def _valid_fuzz_name(name):
    if not isinstance(name, str) or not (1 <= len(name) <= 64):
        return None
    if not (name[0].isalpha() or name[0] == "_"):
        return None
    if all(c.isalnum() or c in "_-[]" for c in name):
        return name
    return None


def _custom_fuzz_variants(candidates, name, values, max_total=100):
    """Append ?name=value variants on API-ish endpoints (source param-fuzz)."""
    from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode
    seen = set()
    for c in candidates or []:
        u = c.get("url") if isinstance(c, dict) else None
        if isinstance(u, str):
            seen.add(u.split("#")[0])
    out = []
    for c in candidates or []:
        if not isinstance(c, dict) or not isinstance(c.get("url"), str):
            continue
        try:
            parts = urlsplit(c["url"].split("#")[0])
        except (ValueError, UnicodeError):
            continue
        if not any(h in (parts.path or "").lower() for h in _FUZZ_PATH_HINTS):
            continue
        try:
            pairs = parse_qsl(parts.query, keep_blank_values=True)
        except (ValueError, UnicodeError):
            pairs = []
        have = {k for k, _ in pairs}
        for v in values:
            new_pairs = [(k, val) for k, val in pairs if k != name] + [(name, v)]
            url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                              urlencode(new_pairs), ""))
            if url in seen or len(out) >= max_total:
                continue
            seen.add(url)
            out.append({"url": url, "source": "param-fuzz",
                        "sources": ["param-fuzz"]})
            if len(out) >= max_total:
                return out
    return out


def _purge_expired():
    import time
    now = time.time()
    for sid in [k for k, s in scans.items()
                if now - s.get("created_ts", now) > SCAN_TTL_SECONDS]:
        scans.pop(sid, None)


def _purge_loop():
    import time
    while True:
        time.sleep(60)
        try:
            _purge_expired()
        except Exception:
            pass


threading.Thread(target=_purge_loop, daemon=True).start()

HTML = """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<title>API Endpoint Discovery</title>
<style>
:root{--bg:#f8fafc;--fg:#0f172a;--card:#fff;--line:#e2e8f0;--mut:#64748b;--hov:#f1f5f9;--sel:#e0f2fe;--code-bg:#0f172a;--code-fg:#e2e8f0;--btn-bg:#0f172a;--btn-fg:#fff;--link:#1d4ed8;--link-v:#7c3aed}
[data-theme=dark]{--bg:#0f172a;--fg:#e2e8f0;--card:#1e293b;--line:#334155;--mut:#94a3b8;--hov:#334155;--sel:#0c4a6e;--code-bg:#020617;--code-fg:#e2e8f0;--btn-bg:#e2e8f0;--btn-fg:#0f172a;--link:#7dd3fc;--link-v:#c4b5fd}
a{color:var(--link)}a:visited{color:var(--link-v)}
body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;background:var(--bg);color:var(--fg)}
header{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}input{padding:.6rem;font-size:1rem;flex:1;min-width:280px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg)}
input[type=checkbox]{flex:none;min-width:0;width:1rem;height:1rem;padding:0;margin:0;accent-color:#16a34a}
label.ck{display:inline-flex;align-items:center;gap:.4rem;cursor:pointer}
button{padding:.6rem 1.2rem;cursor:pointer;background:var(--btn-bg);color:var(--btn-fg);border:0;border-radius:8px;font-weight:600}
.top{display:flex;justify-content:space-between;align-items:center}
.icon-btn{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:.4rem .8rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1rem;margin-top:1rem}
h2{margin:.2rem 0;font-size:1.05rem}.count{background:var(--line);border-radius:10px;padding:0 10px;font-size:.8rem}
.scroll{max-height:260px;overflow:auto;border:1px solid var(--line);border-radius:8px}
table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid var(--line);padding:.45rem;text-align:left;font-size:.85rem;word-break:break-all}
thead th{position:sticky;top:0;background:var(--card)}
tr.ep{cursor:pointer}tr.ep:hover{background:var(--hov)}tr.ep.sel{background:var(--sel)}
.badge{padding:2px 10px;border-radius:12px;font-size:.75rem;color:#fff}.confirmed{background:#16a34a}.likely{background:#ca8a04}.uncertain{background:#64748b}.unlikely{background:#dc2626}.pending{background:#94a3b8}
tr.detail pre{background:var(--code-bg);color:var(--code-fg);border-radius:8px;padding:1rem;overflow:auto;max-height:400px;font-size:.8rem;white-space:pre-wrap}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.5rem;margin:.5rem 0}
.kv{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:.5rem}.kv b{display:block;font-size:.72rem;color:var(--mut)}
#status,.mut{color:var(--mut);font-size:.9rem}</style></head>
<body>
<div class=top><h1>API Endpoint Discovery</h1><button class=icon-btn onclick=toggle() id=tb>🌙 Dark</button></div>
<header><input id=url value="http://localhost:8000/"><button onclick=start()>Scan</button><select id=fmt style="padding:.6rem;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);flex:none"><option value=json>JSON</option><option value=yaml>YAML</option><option value=pdf>PDF</option></select><button class=icon-btn id=dlbtn onclick=downloadReport() disabled>Download</button><span id=status></span></header>
<div id=bar style="height:6px;background:var(--line);border-radius:4px;margin-top:.5rem;display:none"><div id=fill style="height:100%;width:0%;background:#16a34a;border-radius:4px;transition:width .3s"></div></div>
<div class=card><h2>Scan options</h2>
<div style="display:flex;gap:1rem;flex-wrap:wrap;align-items:center">
<label>Max pages <input id=mp type=number value=50 min=1 max=500 style="width:5rem;flex:none;min-width:0"></label>
<label title="Enumerate numeric query params (id=1..N) + boundary probes + common params on bare API endpoints. 0 = off.">Enum IDs <input id=enumids type=number value=0 min=0 max=50 style="width:4rem;flex:none;min-width:0"></label>
</div></div>
<div class=card><h2>Wordlist <small class=mut>(optional brute-force)</small></h2>
<textarea id=wl rows=3 autocomplete="off" style="width:100%;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);padding:.5rem"></textarea>
<div style="margin-top:.4rem;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap"><input type=file id=wf accept=".txt,.wordlist" style="border:0;padding:0;flex:none;min-width:0"> <button class=icon-btn onclick=clearWl()>Clear</button> <label class="mut ck" style="margin-left:auto"><input type=checkbox id=wdef checked> also use common_wordlist.txt</label></div><div id=wstat class=mut style="margin-top:.3rem"></div></div>
<div class=card><h2>Parameter fuzzing <small class=mut>(optional — off unless ticked)</small></h2>
<div><label class=ck><input type=checkbox id=fzen> fuzz a query parameter on every API endpoint found</label></div>
<div style="display:flex;gap:1rem;flex-wrap:wrap;align-items:center;margin-top:.4rem">
<label>Param name <input id=fzname value="id" style="width:8rem;flex:none;min-width:0"></label>
<label>Mode <select id=fzmode onchange="document.getElementById('fzrange').style.display=this.value==='range'?'':'none';document.getElementById('fzwords').style.display=this.value==='words'?'':'none'" style="padding:.4rem;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg)"><option value=range>numeric range</option><option value=words>word list</option></select></label>
<span id=fzrange><label>From <input id=fzfrom type=number value=1 style="width:4rem;flex:none;min-width:0"></label>
<label>To <input id=fzto type=number value=10 style="width:4rem;flex:none;min-width:0"></label></span>
</div>
<textarea id=fzwords rows=2 autocomplete="off" style="display:none;width:100%;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);padding:.5rem;margin-top:.4rem" placeholder="one value per line — spacing kept exactly"></textarea>
</div>
<div class=card><h2>Sites crawled <span class=count id=n1>0</span> <small class=mut id=scanid1></small> <small class=mut id=nskipped></small></h2><div class=scroll><table><thead><tr><th>URL</th><th>Status</th><th>Content-Type</th></tr></thead><tbody id=rows1></tbody></table></div></div>
<div class=card><h2>Endpoints found <span class=count id=n2>0</span> <small class=mut id=scanid></small> <small class=mut>— click one to expand/collapse its analysis</small></h2><div id=stat style="margin:.4rem 0;font-size:.8rem"></div><div style="margin:.4rem 0;font-size:.8rem"><label class=mut>Filter by category: <select id=filtSel onchange="setFilt(this.value)" style="padding:.4rem;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg)"><option value=all>all</option><option value=confirmed>confirmed</option><option value=likely>likely</option><option value=uncertain>uncertain</option><option value=unlikely>unlikely</option></select></label></div><div class=scroll><table><thead><tr><th>URL</th><th>Source</th><th>Result</th><th>Status</th></tr></thead><tbody id=rows2></tbody></table></div></div>
<script>
function toggle(){const h=document.documentElement;const d=h.getAttribute('data-theme')==='dark';h.setAttribute('data-theme',d?'light':'dark');document.getElementById('tb').textContent=d?'🌙 Dark':'☀️ Light';try{localStorage.setItem('theme',d?'light':'dark')}catch(e){}}
(function(){try{if(localStorage.getItem('theme')==='dark'){document.documentElement.setAttribute('data-theme','dark');document.getElementById('tb').textContent='☀️ Light'}}catch(e){}})();
let es;const store={};let done=false;let filt='all';let curSid=null;let curNo=null;let scanGen=0;let rowSeq=0;const stat={confirmed:0,likely:0,uncertain:0,unlikely:0};function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;')}
function msg(ev){return (ev||[]).map(x=>String(x).replace(/^@@D@@+[a-z]?:@@S@@*/,'')).join('; ')}
const TIPS={confirmed:'Returned real API data — very likely a working API endpoint.',likely:'Response looks like an API (data, error message or login challenge), but something did not fully check out.',uncertain:'Not enough evidence to say whether this is an API or just a regular page.',unlikely:'Looks like a normal web page, file or image — probably not an API.'};
function badge(c){return '<span class="badge '+c+'" title="'+(TIPS[c]||c)+'">'+c+'</span>';}
function drawStat(){document.getElementById('stat').innerHTML=Object.keys(stat).sort().map(k=>'<span class="badge '+k+'" title="'+(TIPS[k]||k)+'">'+k+' '+stat[k]+'</span>').join('  ');}
function setFilt(c){filt=c;document.getElementById('filtSel').value=c;applyFilt();}
function rowCat(id){if(store[id].result)return (store[id].result.api_behavior||{}).classification||'uncertain';return null;}
function applyFilt(){document.querySelectorAll('#rows2 tr.ep').forEach(r=>{const showIt=filt==='all'||rowCat(r.id)===filt;r.style.display=showIt?'':'none';const n=r.nextSibling;if(n&&n.classList&&n.classList.contains('detail'))n.style.display=showIt?'':'none';});}
function start(){if(es){es.close();es=null;}const myGen=++scanGen;rowSeq=0;
document.getElementById('rows1').innerHTML='';document.getElementById('rows2').innerHTML='';document.getElementById('nskipped').textContent='';
done=false;
for(const k in store)delete store[k];stat.confirmed=stat.likely=stat.uncertain=stat.unlikely=0;drawStat();filt='all';document.getElementById('filtSel').value='all';document.getElementById('n2').textContent='0';
document.getElementById('status').textContent='Starting…';
document.getElementById('wstat').textContent='';
document.getElementById('bar').style.display='block';document.getElementById('fill').style.width='2%';
const u=document.getElementById('url').value;
const mp=Math.max(1,Math.min(500,parseInt(document.getElementById('mp').value)||50));
const enumids=Math.max(0,Math.min(50,parseInt(document.getElementById('enumids').value)||0));
const extra=document.getElementById('wl').value.split('@@N@@').map(s=>s.trim()).filter(s=>s&&!s.startsWith('#')).map(s=>s.startsWith('/')?s:'/'+s);
const useDef=document.getElementById('wdef').checked;
const fz={enabled:document.getElementById('fzen').checked,name:document.getElementById('fzname').value.trim(),mode:document.getElementById('fzmode').value,from:parseInt(document.getElementById('fzfrom').value)||1,to:parseInt(document.getElementById('fzto').value)||10,words:document.getElementById('fzwords').value.split('@@N@@').map(s=>{if(s.length&&s.charCodeAt(s.length-1)===13)s=s.slice(0,-1);return s.trimStart();}).filter(s=>s!==''&&s.charAt(0)!=='#').slice(0,50)};
document.getElementById('dlbtn').disabled=true;curSid=null;curNo=null;
fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u,max_pages:mp,enum_ids:enumids,extra_paths:extra,use_default_wordlist:useDef,fuzz:fz})}).then(r=>r.json()).then(d=>{
if(myGen!==scanGen)return;
if(d.error){document.getElementById('status').textContent=d.error;return;}
curSid=d.scan_id;curNo=d.scan_no;
document.getElementById('scanid').textContent='(scan #'+d.scan_no+')';
document.getElementById('scanid1').textContent='(scan #'+d.scan_no+')';
if(es)es.close();es=new EventSource('/api/stream/'+d.scan_id);
es.onmessage=e=>{if(myGen!==scanGen)return;const m=JSON.parse(e.data);
if(m.phase){document.getElementById('status').textContent=m.phase;}
if(m.wordlist){document.getElementById('wstat').textContent='Probed '+m.wordlist.probed+' wordlist paths → '+m.wordlist.hits+' live';}
if(m.progress!=null){document.getElementById('fill').style.width=m.progress+'%';}
if(m.page){const t=document.getElementById('rows1');t.insertAdjacentHTML('beforeend','<tr><td>'+esc(m.page.url)+'</td><td>'+esc(m.page.status)+'</td><td>'+esc(m.page.content_type)+'</td></tr>');document.getElementById('n1').textContent=t.children.length;}
if(m.skipped){const el=document.getElementById('nskipped');const n=(parseInt((el.textContent.match(/[0-9]+/)||[0])[0])||0)+1;el.textContent='('+n+' unreachable: last '+((m.skipped.reason||'error')+'').slice(0,60)+')';el.title=m.skipped.url||'';}
if(m.candidate){const t=document.getElementById('rows2');const id='e'+(rowSeq++);
t.insertAdjacentHTML('beforeend','<tr class=ep id='+id+' title="from scan #'+(curNo??'?')+'" onclick="show(&quot;'+id+'&quot;)"><td><a href="'+esc(m.candidate.url)+'" target=_blank rel=noopener onclick="event.stopPropagation()">'+esc(m.candidate.url)+'</a></td><td>'+esc(m.candidate.source)+'</td><td><span class=mut>analyzing…</span></td><td class=mut>…</td></tr>');
store[id]={candidate:m.candidate,result:null};applyFilt();}
if(m.result){const b=(m.result.api_behavior||{}).classification||'uncertain';
stat[b]=(stat[b]||0)+1;drawStat();
const k=Object.keys(store).find(k=>store[k].candidate&&store[k].candidate.url===m.result.url);
if(k){store[k].result=m.result;const row=document.getElementById(k);if(row){
row.cells[2].innerHTML=badge(b);row.cells[3].textContent=m.result.status??'';row.cells[3].classList.remove('mut');}}applyFilt();}
if(m.done){document.getElementById('status').textContent='Scan complete';document.getElementById('fill').style.width='100%';document.getElementById('n2').textContent=document.getElementById('rows2').querySelectorAll('tr.ep').length;done=true;if(curSid)document.getElementById('dlbtn').disabled=false;es.close();}}});}
function downloadReport(){if(curSid)window.location.href='/api/report/'+curSid+'?format='+document.getElementById('fmt').value;}
document.getElementById('wf').addEventListener('change',e=>{const f=e.target.files[0];if(!f)return;const r=new FileReader();r.onload=()=>{document.getElementById('wl').value=r.result};r.readAsText(f);});
function clearWl(){document.getElementById('wl').value='';document.getElementById('wf').value='';}
document.getElementById('wl').value='';document.getElementById('wf').value='';
function copyRes(id,btn){const e=store[id];if(!e||!e.result)return;const txt=JSON.stringify(e.result,null,2);
function done(){if(btn){btn.textContent='Copied!';setTimeout(()=>{btn.textContent='Copy analysis'},1500);}}
if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(done).catch(()=>fallback());}else fallback();
function fallback(){const t=document.createElement('textarea');t.value=txt;document.body.appendChild(t);t.select();try{document.execCommand('copy');done();}catch(err){}document.body.removeChild(t);}}
function show(id){const row=document.getElementById(id);
const nxt=row.nextSibling;
if(nxt&&nxt.classList&&nxt.classList.contains('detail')){nxt.remove();row.classList.remove('sel');return;}
document.querySelectorAll('tr.detail').forEach(r=>r.remove());document.querySelectorAll('tr.ep').forEach(r=>r.classList.remove('sel'));
row.classList.add('sel');const e=store[id];
const tr=document.createElement('tr');tr.className='detail';
const td=document.createElement('td');td.colSpan=4;
if(!e.result){td.innerHTML='<span class=mut>'+esc(e.candidate.url)+' — '+(done?'analysis unavailable.':'scanning in progress…')+'</span>';}
else{const r=e.result,b=(r.api_behavior||{}).classification||'',a=(r.access||{}).classification||'';
const params=r.parameters||[];const v=r.verdict||{};const sp=r.security_posture||{};const sf=r.sensitive_findings||[];const op=r.options_probe||{};
const spTxt=(sp.classification||'unknown')+(((sp.issues||[]).length)?' ('+sp.issues.length+' issues)':'');
td.innerHTML=badge(b)+' '+esc(a)+' <button class=icon-btn onclick="copyRes(&quot;'+id+'&quot;,this)">Copy analysis</button>'
+(v.label?'<p><b>Verdict:</b> '+esc(v.label)+(v.summary?' — '+esc(v.summary):'')+'</p>':'')
+'<div class=grid>'+[['Status',r.status],['Content-Type',r.content_type],['Size',r.response_size],['Time (ms)',r.response_time_ms],['Access',a],['Method',r.method],['Security',spTxt],['Sensitive findings',sf.length],['OPTIONS',op.allowed_methods?op.allowed_methods.join(', '):(op.status??'')]].map(x=>'<div class=kv><b>'+x[0]+'</b>'+esc(x[1])+'</div>').join('')+'</div>'
+'<p><b>Evidence:</b> '+esc(msg((r.api_behavior||{}).evidence))+'</p>'
+(params.length?'<p><b>Parameters:</b> '+esc(JSON.stringify(params))+'</p>':'')
+(sf.length?'<p><b>Sensitive findings:</b> '+esc(JSON.stringify(sf).slice(0,500))+'</p>':'')
+(v.next_step?'<p class=mut><b>Next step:</b> '+esc(v.next_step)+'</p>':'')
+'<pre>'+esc(JSON.stringify(r,null,2))+'</pre>';}
tr.appendChild(td);row.after(tr);}
</script></body></html>"""

HTML = HTML.replace("@@D@@", chr(92) + "d").replace("@@N@@", chr(92) + "n").replace("@@S@@", chr(92) + "s")


def emit(sid, obj):
    scans[sid]["q"].put(obj)


def run_scan(sid):
    import time as _time
    s = scans[sid]
    target = s["target"]
    max_pages = s.get("max_pages", 50)
    t0 = _time.time()
    try:
        emit(sid, {"phase": "Crawling site…", "progress": 5})
        crawled = [0]

        def _cb(rec):
            crawled[0] += 1
            emit(sid, {"page": {"url": rec.get("url"), "status": rec.get("status"),
                                "content_type": rec.get("content_type")}})
            n = crawled[0]
            emit(sid, {"phase": f"Crawling… {n}/{max_pages} pages",
                       "progress": 5 + int(35 * min(n, max_pages) / max(max_pages, 1))})

        # on_page/on_error are optional: older checkouts lack them.
        _sig = inspect.signature(crawl).parameters
        if "on_page" in _sig:
            kwargs = {"on_page": _cb}
            if "on_error" in _sig:
                def _err(info):
                    s["skipped"] = s.get("skipped", 0) + 1
                    emit(sid, {"skipped": {"url": info.get("url"),
                                           "reason": info.get("reason")}})
                kwargs["on_error"] = _err
            records = crawl(target, max_pages=max_pages, **kwargs)
        else:
            records = crawl(target, max_pages=max_pages)
            for r in records:
                _cb(r)
        s["pages"] = records
        emit(sid, {"phase": f"Crawled {len(records)} pages — discovering endpoints…",
                   "progress": 45})

        wl_file = DEFAULT_WORDLIST if s.get("use_default_wordlist") else None
        cands = discover_endpoints(records, target, wordlist=wl_file,
                                   extra_paths=s.get("extra_paths") or [])
        # Opt-in numeric enum (mirrors CLI --enum-ids).
        if s.get("enum_ids", 0) > 0:
            try:
                from endpoint_discovery import expand_param_variants
                have = {c["url"] for c in cands}
                for e in expand_param_variants(cands, max_numeric=s["enum_ids"]):
                    if e["url"] not in have:
                        have.add(e["url"])
                        cands.append(e)
            except Exception:
                pass
        # Opt-in custom param fuzz (name + range/words from the dashboard).
        fz = s.get("fuzz") or {}
        if fz.get("enabled"):
            name = _valid_fuzz_name(fz.get("name", ""))
            values = _fuzz_values(fz)
            if name and values:
                have = {c["url"] for c in cands}
                extra_fz = _custom_fuzz_variants(cands, name, values)
                if extra_fz:
                    emit(sid, {"phase": f"Parameter fuzzing ?{name}=… "
                                        f"({len(extra_fz)} variants)…",
                               "progress": 48})
                for e in extra_fz:
                    if e["url"] not in have:
                        have.add(e["url"])
                        cands.append(e)
        s["candidates"] = cands
        wl_hits = sum(1 for c in cands if "common_path" in (c.get("sources") or []))
        emit(sid, {"wordlist": {"probed": s.get("wordlist_size", 0), "hits": wl_hits}})
        for c in cands:
            emit(sid, {"candidate": {"url": c.get("url"), "source": c.get("source"),
                                     "sources": c.get("sources")}})
        total = len(cands)
        with EndpointAnalyzer() as an:
            for i, c in enumerate(cands, 1):
                emit(sid, {"phase": f"Analyzing endpoint {i}/{total}…",
                           "progress": 50 + int(45 * i / max(total, 1))})
                r = an.analyze_endpoint(c)
                s["results"].append(r)
                emit(sid, {"result": r})
        s["status"] = "done"
        s["duration_s"] = round(_time.time() - t0, 1)
        nskip = s.get("skipped", 0)
        skip_txt = f" ({nskip} unreachable)" if nskip else ""
        emit(sid, {"done": f"Done — {len(records)} pages{skip_txt}, "
                           f"{len(cands)} endpoints"})
    except Exception as e:
        s["status"] = "error"
        s["duration_s"] = round(_time.time() - t0, 1)
        emit(sid, {"done": f"Error: {e}"})


@app.route("/")
def index():
    return HTML


@app.route("/api/scan", methods=["POST"])
def scan():
    import time
    _purge_expired()
    data = request.get_json(force=True, silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        max_pages = max(1, min(500, int(data.get("max_pages", 50))))
    except (TypeError, ValueError):
        max_pages = 50
    try:
        enum_ids = max(0, min(50, int(data.get("enum_ids", 0))))
    except (TypeError, ValueError):
        enum_ids = 0
    sid = uuid.uuid4().hex[:8]
    _scan_counter[0] += 1
    scan_no = _scan_counter[0]
    raw_extra = data.get("extra_paths") or []
    extra = []
    for p in raw_extra:
        p = str(p).strip().split()[0] if str(p).strip() else ""
        if not p or p.startswith("#"):
            continue
        extra.append(p if p.startswith("/") else "/" + p)
    try:
        wl_size = len(load_wordlist(DEFAULT_WORDLIST)) if data.get("use_default_wordlist", True) else 0
    except Exception:
        wl_size = 0
    fuzz = data.get("fuzz") if isinstance(data.get("fuzz"), dict) else {}
    scans[sid] = {"status": "running", "target": url, "extra_paths": extra,
                  "sid": sid, "scan_no": scan_no,
                  "max_pages": max_pages, "enum_ids": enum_ids,
                  "fuzz": {"enabled": bool(fuzz.get("enabled")),
                           "name": str(fuzz.get("name", ""))[:64],
                           "mode": fuzz.get("mode", "range"),
                           "from": fuzz.get("from", 1), "to": fuzz.get("to", 10),
                           "words": list(fuzz.get("words") or [])[:50]},
                  "wordlist_size": wl_size + len(extra),
                  "use_default_wordlist": bool(data.get("use_default_wordlist", True)),
                  "pages": [], "candidates": [], "results": [], "q": queue.Queue(),
                  "created_at": datetime.now(timezone.utc).isoformat(),
                  "created_ts": time.time()}
    threading.Thread(target=run_scan, args=(sid,), daemon=True).start()
    return jsonify({"scan_id": sid, "scan_no": scan_no,
                    "expires_in_seconds": SCAN_TTL_SECONDS})


def _get_scan(sid):
    """Accept a scan id OR a scan number ("3", 3). None if unknown;
    'expired' if older than TTL (and purge it)."""
    import time
    s = scans.get(sid)
    if s is None:
        try:
            want = int(str(sid))
        except (TypeError, ValueError):
            return None
        for cand in scans.values():
            if cand.get("scan_no") == want:
                s = cand
                break
    if s is None:
        return None
    if time.time() - s.get("created_ts", time.time()) > SCAN_TTL_SECONDS:
        scans.pop(s.get("sid", sid), None)
        return "expired"
    return s


@app.route("/api/stream/<sid>")
def stream(sid):
    s = _get_scan(sid)
    if s is None:
        return jsonify({"error": "unknown"}), 404
    if s == "expired":
        return jsonify({"error": "report expired (30 min TTL)"}), 410
    q = s["q"]

    def gen():
        yield "retry: 2000\n\n"
        while True:
            try:
                m = q.get(timeout=30)
            except queue.Empty:
                yield ": ping\n\n"
                continue
            yield "data: " + json.dumps(m, default=str) + "\n\n"
            if "done" in m:
                break

    return Response(gen(), mimetype="text/event-stream")


@app.route("/api/result/<sid>")
def result(sid):
    s = _get_scan(sid)
    if s is None:
        return jsonify({"error": "unknown"}), 404
    if s == "expired":
        return jsonify({"error": "report expired (30 min TTL)"}), 410
    return jsonify({"status": s["status"], "target": s["target"], "pages": s["pages"],
                    "scan_no": s.get("scan_no"), "scan_id": s.get("sid"),
                    "candidates": s["candidates"], "results": s["results"]})


@app.route("/api/report/<sid>")
def report(sid):
    """Download the full scan report as JSON, YAML, or PDF."""
    fmt = (request.args.get("format") or "json").lower()
    if fmt not in ("json", "yaml", "yml", "pdf"):
        return jsonify({"error": "format must be json, yaml, or pdf"}), 400
    s = _get_scan(sid)
    if s is None:
        return jsonify({"error": "unknown"}), 404
    if s == "expired":
        return jsonify({"error": "report expired (30 min TTL)"}), 410
    payload = {"tool": "api-endpoint-discovery", "target": s["target"],
               "status": s["status"], "created_at": s["created_at"],
               "duration_s": s.get("duration_s"),
               "scan_no": s.get("scan_no"), "scan_id": s.get("sid"),
               "options": {"max_pages": s.get("max_pages"),
                           "enum_ids": s.get("enum_ids"),
                           "fuzz": s.get("fuzz"),
                           "wordlist_paths_probed": s.get("wordlist_size")},
               "pages": s["pages"], "candidates": s["candidates"],
               "results": s["results"]}
    host = (s["target"].replace("https://", "").replace("http://", "")
            .split("/")[0].replace(":", "_"))
    if fmt in ("yaml", "yml"):
        import yaml
        body = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
        return Response(body, mimetype="application/yaml",
                        headers={"Content-Disposition":
                                 f"attachment; filename=scan-{host}-{sid}.yaml"})
    if fmt == "pdf":
        pdf_bytes = _build_pdf(payload)
        return Response(pdf_bytes, mimetype="application/pdf",
                        headers={"Content-Disposition":
                                 f"attachment; filename=scan-{host}-{sid}.pdf"})
    body = json.dumps(payload, indent=2, default=str)
    return Response(body, mimetype="application/json",
                    headers={"Content-Disposition":
                             f"attachment; filename=scan-{host}-{sid}.json"})


def _latin(text):
    """Fold text into latin-1 for PDF core fonts."""
    s = "" if text is None else str(text)
    return (s.replace("→", "->").replace("—", "-").replace("–", "-")
             .replace("…", "...").replace("✓", "x").replace("✗", "x")
             .encode("latin-1", "replace").decode("latin-1"))


def _struct_summary(r):
    """One-line response shape: array length / object keys / scalar type."""
    st = r.get("response_structure") or {}
    t = st.get("type", "?")
    if t == "array":
        keys = st.get("item_keys") or []
        extra = (" keys: " + ", ".join(keys[:6])) if keys else ""
        return f"array[{st.get('length', '?')}] of {st.get('item_type', '?')}{extra}"
    if t == "object":
        keys = st.get("keys") or []
        return f"object keys: {', '.join(keys[:8])}" if keys else "object{}"
    return t


def _build_pdf(payload):
    from fpdf import FPDF
    from collections import Counter
    pdf = FPDF(orientation="L", format="A4")
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, _latin("API Endpoint Discovery - Scan Report"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    results = payload.get("results") or []
    pages = payload.get("pages") or []
    cands = payload.get("candidates") or []
    cats = Counter((r.get("api_behavior") or {}).get("classification", "?")
                   for r in results)
    verdicts = Counter((r.get("verdict") or {}).get("label", "?")
                       for r in results)
    sources = Counter((r.get("source") or "?") for r in results)
    probed = (payload.get("options") or {}).get("wordlist_paths_probed", "?")
    n_analyses = len(results)
    est_requests = len(pages)
    try:
        est_requests += int(probed)
    except (TypeError, ValueError):
        pass
    est_requests += n_analyses * 2  # analysis GET + conditional OPTIONS probe
    for line in (
        f"Target: {payload.get('target')}",
        f"Scanned: {payload.get('created_at')}  |  Status: {payload.get('status')}",
        f"Pages crawled: {len(pages)}  |  Endpoints: {len(cands)}  |  "
        f"Analyzed: {n_analyses}",
        "Breakdown: " + ", ".join(f"{k}-{v}" for k, v in sorted(cats.items())),
        "Verdicts: " + "; ".join(f"{k} ({v})" for k, v in sorted(verdicts.items())),
        "Sources: " + ", ".join(f"{k} ({v})" for k, v in sorted(sources.items())),
        f"Requests made (approx): {est_requests} in "
        f"{payload.get('duration_s', '?')}s",
    ):
        pdf.cell(0, 6, _latin(line), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, f"Findings ({len(results)})", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8)
    col_widths = (108, 14, 26, 22, 26, 22, 59)
    headers = ("URL", "Status", "Content-Type", "Behavior", "Access",
               "Source", "Verdict")
    with pdf.table(col_widths=col_widths, text_align="LEFT",
                   first_row_as_headings=False) as table:
        row = table.row()
        for h in headers:
            row.cell(_latin(h))
        for r in results:
            b = (r.get("api_behavior") or {}).get("classification", "")
            a = (r.get("access") or {}).get("classification", "")
            v = (r.get("verdict") or {}).get("label", "")
            row = table.row()
            row.cell(_latin(r.get("url", "")))
            row.cell(_latin(r.get("status", "")))
            row.cell(_latin((r.get("content_type") or "").split(";")[0]))
            row.cell(_latin(b))
            row.cell(_latin(a))
            row.cell(_latin(r.get("source", "")))
            row.cell(_latin(v))
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Endpoint details", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 8)
    for r in results:
        b = (r.get("api_behavior") or {}).get("classification", "")
        ev = "; ".join((r.get("api_behavior") or {}).get("evidence") or [])
        v = r.get("verdict") or {}
        sp = r.get("security_posture") or {}
        sf = r.get("sensitive_findings") or []
        op = r.get("options_probe") or {}
        hdrs = r.get("headers") or {}
        params = r.get("parameters") or []
        warns = r.get("warnings") or []
        pdf.set_font("Helvetica", "B", 9)
        pdf.multi_cell(0, 5, _latin(f"{r.get('url', '')}  [{b}]"),
                       new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        if v.get("summary"):
            pdf.multi_cell(0, 5, _latin("Summary: " + v["summary"]),
                           new_x="LMARGIN", new_y="NEXT")
        if v.get("next_step"):
            pdf.multi_cell(0, 5, _latin("Next step: " + v["next_step"]),
                           new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 5, _latin(
            f"Shape: {_struct_summary(r)}  |  Size: {r.get('response_size', '?')} bytes"
            + (" (truncated)" if r.get("response_size_truncated") else "")
            + f"  |  Time: {r.get('response_time_ms', '?')}ms"), new_x="LMARGIN", new_y="NEXT")
        if params:
            pdf.multi_cell(0, 5, _latin(
                "Params: " + ", ".join(
                    f"{p.get('name')}={p.get('example_value', '')}"
                    for p in params[:10])), new_x="LMARGIN", new_y="NEXT")
        if ev:
            pdf.multi_cell(0, 5, _latin("Evidence: " + ev[:800]),
                           new_x="LMARGIN", new_y="NEXT")
        posture = sp.get("classification", "unknown")
        issues = sp.get("issues") or []
        pdf.multi_cell(0, 5, _latin(
            f"Security posture: {posture}"
            + (f" — issues: {'; '.join(map(str, issues))}" if issues else "")),
            new_x="LMARGIN", new_y="NEXT")
        if sf:
            pdf.multi_cell(0, 5, _latin(
                f"Sensitive findings ({len(sf)}): "
                + str(sf)[:400]), new_x="LMARGIN", new_y="NEXT")
        allow = hdrs.get("allow")
        opt_methods = (op.get("allowed_methods")
                       if isinstance(op, dict) else None)
        if allow or opt_methods or op.get("status"):
            pdf.multi_cell(0, 5, _latin(
                f"Methods: Allow header: {allow or '-'}  |  "
                f"OPTIONS probe: {opt_methods or op.get('status', '-')}"),
                new_x="LMARGIN", new_y="NEXT")
        if hdrs.get("www-authenticate"):
            pdf.multi_cell(0, 5, _latin(
                f"Auth scheme: {hdrs['www-authenticate'][:120]}"),
                new_x="LMARGIN", new_y="NEXT")
        if warns:
            pdf.multi_cell(0, 5, _latin(
                "Warnings: " + "; ".join(map(str, warns))[:400]),
                new_x="LMARGIN", new_y="NEXT")
        if r.get("error"):
            pdf.multi_cell(0, 5, _latin(
                f"Error: {r['error'].get('type')}: {r['error'].get('message', '')}"[:300]),
                new_x="LMARGIN", new_y="NEXT")
        if r.get("redirected"):
            pdf.multi_cell(0, 5, _latin(
                f"Redirected to: {r.get('final_url', '')}"),
                new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
    return bytes(pdf.output())


if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), threaded=True)
