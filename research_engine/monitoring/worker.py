import logging,time,traceback,json,signal
from datetime import datetime,timezone
from pathlib import Path
import psutil
from research_engine.config import load_config,resolve_path
from research_engine.database.store import Store
from research_engine.research.feeds import fetch_nvd,fetch_github_advisories,inspect_repo_commits
from research_engine.research.ai_review import review_diff,propose_noncrypto_patch
from research_engine.vulnerabilities.catalog import seed_catalog
from research_engine.rng.diagnostics import diagnose
from research_engine.notifications.telegram import send
from research_engine.monitoring.repair import analyze_traceback
from research_engine.monitoring.mainnet import monitor_authorized_addresses
def setup_logging(cfg):
 p=resolve_path(cfg["app"]["log_file"]); p.parent.mkdir(parents=True,exist_ok=True)
 logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s",handlers=[logging.FileHandler(p,encoding="utf-8"),logging.StreamHandler()])
def run_cycle():
 cfg=load_config(); setup_logging(cfg); db=Store(resolve_path(cfg["app"]["database"])); rid=db.run_start()
 try:
  seed_catalog(db); t=int(cfg["research"].get("request_timeout_seconds",20)); items=[]
  items+=fetch_nvd(int(cfg["research"].get("nvd_days_back",14)),t)
  items+=fetch_github_advisories(int(cfg["research"].get("github_advisory_pages",2)),t)
  items+=inspect_repo_commits(cfg["research"].get("monitored_repositories",[]),t)
  for item in items:
   matches=item.get("raw",{}).get("rng_code_matches",[])
   if matches:
    try: item["raw"]["ai_triage"]=review_diff(item.get("raw",{}).get("repository","unknown"),item.get("url",""),json.dumps(matches,ensure_ascii=False),t)
    except Exception as ai_error: item["raw"]["ai_triage"]={"status":"provider-error","error_type":type(ai_error).__name__,"confirmed":False}
  new=[x for x in items if db.add_advisory(x)]
  rng=diagnose(nbytes=int(cfg["rng"].get("sample_bytes",65536)))
  mainnet=[]
  if cfg.get("mainnet_monitor",{}).get("allowlist"):
   mainnet=monitor_authorized_addresses(cfg)
   for snapshot in mainnet: db.add_chain_snapshot(snapshot)
  cpu=psutil.cpu_percent(interval=.2); mem=psutil.virtual_memory().percent
  summary={"advisories_seen":len(items),"new_advisories":len(new),"rng":rng,"mainnet_addresses_checked":len(mainnet),"mainnet_snapshots":mainnet,"cpu_percent":cpu,"memory_percent":mem}
  if cpu>=float(cfg.get("monitoring",{}).get("max_cpu_percent",90)) or mem>=float(cfg.get("monitoring",{}).get("max_memory_percent",90)):
   db.event("WARN","resource_threshold_exceeded",{"cpu_percent":cpu,"memory_percent":mem})
   send("Wallet RNG Engine: magas erőforrás-használat — CPU "+str(cpu)+"%, RAM "+str(mem)+"%.")
  reports=resolve_path(cfg["app"].get("reports_dir","reports")); reports.mkdir(parents=True,exist_ok=True)
  report=reports/("research-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")+".json")
  report.write_text(json.dumps({"generated_at":datetime.now(timezone.utc).isoformat(),"summary":summary,"findings":items},indent=2,ensure_ascii=False),encoding="utf-8")
  db.event("INFO","research_cycle_complete",{**summary,"report":str(report)})
  if new: send("Wallet RNG Engine: "+str(len(new))+" új advisory/commit találat. Részletek a helyi adatbázisban.")
  if rng["statistical_screen"]!="PASS": send("Wallet RNG Engine figyelmeztetés: RNG teszt felülvizsgálatot igényel.")
  db.run_finish(rid,"success",summary); logging.info("Research cycle completed: %s",summary); return summary
 except Exception as e:
  trace=traceback.format_exc(); diagnosis=analyze_traceback(trace); proposal={"status":"not-requested","auto_apply":False}
  frame=diagnosis.get("affected_file")
  if frame:
   candidate=Path(frame).resolve(); root=Path(__file__).resolve().parents[2]
   if candidate.is_relative_to(root) and candidate.is_file():
    relative=candidate.relative_to(root).as_posix()
    try: proposal=propose_noncrypto_patch(relative,candidate.read_text(encoding="utf-8"),trace,t)
    except Exception as ai_error: proposal={"status":"provider-error","error_type":type(ai_error).__name__,"auto_apply":False}
  reports=resolve_path(cfg["app"].get("reports_dir","reports")); reports.mkdir(parents=True,exist_ok=True)
  error_report=reports/("error-"+datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")+".json")
  error_report.write_text(json.dumps({"created_at":datetime.now(timezone.utc).isoformat(),"error":str(e),"traceback":trace,"diagnosis":diagnosis,"ai_patch_proposal":proposal},indent=2),encoding="utf-8")
  db.event("ERROR","research_cycle_failed",{"error":str(e),"traceback":trace,"diagnosis":diagnosis,"report":str(error_report)}); db.run_finish(rid,"failed",{"error":str(e),"report":str(error_report)})
  logging.exception("Research cycle failed"); send("Wallet RNG Engine hiba: "+type(e).__name__+" — "+str(e)[:500]); raise
 finally: db.close()
def run_forever():
 cfg=load_config(); interval=max(300,int(cfg["research"].get("interval_seconds",21600)))
 stopping=False
 def stop_signal(signum,frame):
  nonlocal stopping
  stopping=True; logging.info("Shutdown requested; finishing current cycle.")
 signal.signal(signal.SIGINT,stop_signal)
 if hasattr(signal,"SIGTERM"): signal.signal(signal.SIGTERM,stop_signal)
 while not stopping:
  try: run_cycle()
  except Exception: logging.exception("Recoverable worker error")
  for _ in range(interval):
   if stopping: break
   time.sleep(1)
 logging.info("Worker stopped gracefully."); send("Wallet RNG Engine: a worker szabályosan leállt.")
