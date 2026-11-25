import os,re,requests
from datetime import datetime,timedelta,timezone
H={"User-Agent":"WalletRNGResearchEngine/2.0","Accept":"application/vnd.github+json"}
TERMS=("wallet","bitcoin","ethereum","solana","entropy","random number","rng","seed generation","mnemonic","private key","cryptographic")
def fetch_nvd(days=14,timeout=20):
 end=datetime.now(timezone.utc); start=end-timedelta(days=days)
 headers={"User-Agent":H["User-Agent"]}
 if os.getenv("NVD_API_KEY"): headers["apiKey"]=os.environ["NVD_API_KEY"]
 r=requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",params={"pubStartDate":start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),"pubEndDate":end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),"resultsPerPage":2000},headers=headers,timeout=timeout); r.raise_for_status()
 out=[]
 for row in r.json().get("vulnerabilities",[]):
  c=row.get("cve",{}); desc=" ".join(x.get("value","") for x in c.get("descriptions",[]) if x.get("lang")=="en")
  if any(t in desc.lower() for t in TERMS):
   cid=c.get("id"); out.append({"id":cid,"source":"NVD","title":cid+" "+desc[:180],"summary":desc,"url":"https://nvd.nist.gov/vuln/detail/"+cid,"published":c.get("published"),"raw":c})
 return out
def fetch_github_advisories(pages=2,timeout=20):
 out=[]; headers={**H,**({"Authorization":"Bearer "+os.environ["GITHUB_TOKEN"]} if os.getenv("GITHUB_TOKEN") else {})}
 for page in range(1,pages+1):
  r=requests.get("https://api.github.com/advisories",params={"per_page":100,"page":page,"sort":"published","direction":"desc"},headers=headers,timeout=timeout); r.raise_for_status(); rows=r.json()
  if not rows: break
  for a in rows:
   desc=(a.get("summary","")+" "+a.get("description","")).lower()
   if any(t in desc for t in TERMS):
    out.append({"id":a.get("ghsa_id") or a.get("cve_id") or a.get("html_url"),"source":"GitHub Advisory Database","title":a.get("summary","Untitled advisory"),"summary":a.get("description",""),"url":a.get("html_url"),"published":a.get("published_at"),"raw":a})
 return out
SUSPICIOUS_RNG = [
 ("js-math-random",re.compile(r"Math\.random\s*\(")),
 ("python-random",re.compile(r"\brandom\.(random|randint|randrange|seed)\s*\(")),
 ("mersenne-twister",re.compile(r"\bmt19937\b",re.I)),
 ("c-rand",re.compile(r"\b(?:std::)?rand\s*\(")),
 ("default-random-engine",re.compile(r"default_random_engine")),
 ("time-seeded-rng",re.compile(r"(?:seed|srand)\s*\([^)]*(?:time\s*\(|Date\.now)"))
]
def inspect_repo_commits(repositories,timeout=20):
 out=[]; headers={**H,**({"Authorization":"Bearer "+os.environ["GITHUB_TOKEN"]} if os.getenv("GITHUB_TOKEN") else {})}
 for repo in repositories:
  r=requests.get("https://api.github.com/repos/"+repo+"/commits",params={"per_page":15},headers=headers,timeout=timeout); r.raise_for_status()
  for c in r.json():
   msg=c.get("commit",{}).get("message",""); sha=c.get("sha")
   if not any(t in msg.lower() for t in ("random","entropy","rng","seed","crypto","wallet")): continue
   detail=requests.get("https://api.github.com/repos/"+repo+"/commits/"+sha,headers=headers,timeout=timeout); detail.raise_for_status()
   matches=[]
   for f in detail.json().get("files",[]):
    patch=f.get("patch","")
    for label,pattern in SUSPICIOUS_RNG:
     for line in patch.splitlines():
      if line.startswith("+") and not line.startswith("+++") and pattern.search(line):
       matches.append({"pattern":label,"file":f.get("filename"),"line":line[1:][:300]})
   out.append({"id":sha,"source":"GitHub commit monitor","title":repo+": "+msg.splitlines()[0][:180],"summary":msg[:3000],"url":c.get("html_url"),"published":c.get("commit",{}).get("author",{}).get("date"),"raw":{"repository":repo,"sha":sha,"rng_code_matches":matches,"triage":"potentially-suspicious" if matches else "commit-message-only-review"}})
 return out
