import argparse,json,os,shutil
from pathlib import Path
from research_engine.config import load_config,resolve_path
from research_engine.database.store import Store
from research_engine.rng.diagnostics import diagnose,WeakLCG
from research_engine.monitoring.worker import run_cycle,run_forever
from research_engine.wallets.service import create_test_wallet
from research_engine.monitoring.mainnet import monitor_authorized_addresses
from research_engine.security.vault import decrypt_record
def main():
 p=argparse.ArgumentParser(); s=p.add_subparsers(dest="cmd",required=True)
 s.add_parser("once"); s.add_parser("worker"); s.add_parser("monitor-mainnet"); s.add_parser("rng-test"); s.add_parser("vulnerabilities")
 vc=s.add_parser("vault-check"); vc.add_argument("--vault",default=None)
 ve=s.add_parser("vault-export"); ve.add_argument("--out",required=True)
 w=s.add_parser("wallet"); w.add_argument("--chain",choices=["btc","eth","sol"],required=True)
 a=p.parse_args()
 if a.cmd=="once": print(json.dumps(run_cycle(),indent=2))
 elif a.cmd=="monitor-mainnet":
  c=load_config(); results=monitor_authorized_addresses(c)
  db=Store(resolve_path(c["app"]["database"]))
  try:
   for item in results: db.add_chain_snapshot(item)
  finally: db.close()
  print(json.dumps(results,indent=2,ensure_ascii=False))
 elif a.cmd=="worker": run_forever()
 elif a.cmd=="rng-test": print(json.dumps({"os_csprng":diagnose(),"test_only_weak_lcg":diagnose(WeakLCG(7))},indent=2))
 elif a.cmd=="vault-check":
  c=load_config(); path=resolve_path(a.vault or c["wallets"]["vault_file"]); password=os.getenv("WALLET_VAULT_PASSPHRASE")
  if not path.exists(): raise SystemExit("Vault file not found.")
  count=0
  with path.open("r",encoding="utf-8") as handle:
   for line in handle:
    if line.strip(): decrypt_record(json.loads(line),password); count+=1
  print(json.dumps({"vault":"valid","records_verified":count,"secrets_printed":False},indent=2))
 elif a.cmd=="vault-export":
  c=load_config(); source=resolve_path(c["wallets"]["vault_file"]); target=Path(a.out).expanduser().resolve()
  if not source.is_file(): raise SystemExit("Vault file not found.")
  if target.exists(): raise SystemExit("Export destination already exists; choose a new path.")
  target.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(source,target)
  print(json.dumps({"exported":"encrypted-vault","path":str(target),"plaintext":False},indent=2))
 elif a.cmd=="wallet":
  c=load_config(); db=Store(resolve_path(c["app"]["database"]))
  try:
   x=create_test_wallet(a.chain,c); db.add_wallet_metadata(x["id"],x["chain"],x["address"],x["derivation_path"],x["vault_ref"])
   print(json.dumps({k:v for k,v in x.items() if k!="vault_ref"}|{"secrets":"encrypted locally; never printed"},indent=2))
  finally: db.close()
 else:
  db=Store(resolve_path(load_config()["app"]["database"]))
  try:
   from research_engine.vulnerabilities.catalog import seed_catalog
   seed_catalog(db); print(json.dumps([dict(x) for x in db.db.execute("SELECT * FROM vulnerabilities ORDER BY id")],indent=2))
  finally: db.close()
if __name__=="__main__": main()
