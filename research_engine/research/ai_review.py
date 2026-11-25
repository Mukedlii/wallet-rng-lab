"""Optional AI triage. Output is advisory only and can never confirm a vulnerability."""
import json,os,requests
def review_diff(repository,commit_url,diff_excerpt,timeout=30):
    if os.getenv("AI_REVIEW_ENABLED","").lower() not in ("1","true","yes"):
        return {"enabled":False,"status":"skipped"}
    key=os.getenv("AI_API_KEY"); base=os.getenv("AI_BASE_URL","https://api.openai.com/v1").rstrip("/")
    model=os.getenv("AI_MODEL")
    if not key or not model: return {"enabled":True,"status":"not_configured"}
    prompt=("Review this public repository code diff only for cryptographic RNG/entropy risks. "
      "Return strict JSON with keys: risk (none|low|medium|high), suspicious_patterns (array), "
      "evidence (array of exact short snippets), explanation, required_reproduction (array). "
      "Always set confirmed=false. Do not infer exploitability without reproducible evidence. "
      "Do not suggest attacking wallets or deriving third-party keys.\nRepository: "+repository+
      "\nCommit: "+commit_url+"\nDiff:\n"+diff_excerpt[:12000])
    response=requests.post(base+"/chat/completions",headers={"Authorization":"Bearer "+key},
      json={"model":model,"temperature":0,"messages":[{"role":"system","content":"You are a cautious application-security research assistant. Never claim a vulnerability is confirmed."},{"role":"user","content":prompt}]},timeout=timeout)
    response.raise_for_status(); data=response.json()
    content=data["choices"][0]["message"]["content"]
    try: result=json.loads(content)
    except json.JSONDecodeError: return {"enabled":True,"status":"unparseable","raw_summary":content[:2000],"confirmed":False}
    if not isinstance(result,dict): return {"enabled":True,"status":"invalid-shape","confirmed":False}
    result["confirmed"]=False; result["status"]="ai-triage-only"; return result

def propose_noncrypto_patch(path,source,traceback_text,timeout=45):
    """Request a JSON replacement proposal only; application remains separately gated."""
    blocked=("wallet_rng_lab.py","research_engine/rng/","research_engine/security/","research_engine/wallets/","research_engine/vulnerabilities/")
    if path.startswith(blocked):
        return {"status":"blocked-protected-path","auto_apply":False}
    if os.getenv("AI_REVIEW_ENABLED","").lower() not in ("1","true","yes"):
        return {"status":"skipped","auto_apply":False}
    key=os.getenv("AI_API_KEY"); model=os.getenv("AI_MODEL")
    if not key or not model: return {"status":"not_configured","auto_apply":False}
    prompt=("Propose one minimal non-cryptographic text replacement. Return JSON keys path, old, new, reason; return null if unclear. Never edit crypto, RNG, wallet, key derivation, vault or vulnerability files. Do not include secrets."+chr(10)+"Path: "+path+chr(10)+"Traceback:"+chr(10)+traceback_text[:5000]+chr(10)+"Source:"+chr(10)+source[:10000])
    base=os.getenv("AI_BASE_URL","https://api.openai.com/v1").rstrip("/")
    r=requests.post(base+"/chat/completions",headers={"Authorization":"Bearer "+key},
      json={"model":model,"temperature":0,"messages":[{"role":"system","content":"Suggest cautious minimal fixes. Never claim a vulnerability is confirmed. Never edit cryptographic code."},{"role":"user","content":prompt}]},timeout=timeout)
    r.raise_for_status(); raw=r.json()["choices"][0]["message"]["content"]
    try: result=json.loads(raw)
    except json.JSONDecodeError: return {"status":"unparseable","auto_apply":False}
    if not isinstance(result,dict) or result.get("path")!=path or not isinstance(result.get("old"),str) or not isinstance(result.get("new"),str):
        return {"status":"invalid-or-mismatched-proposal","auto_apply":False}
    result["auto_apply"]=False; result["status"]="proposal-requires-explicit-review"; return result
