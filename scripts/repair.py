import argparse,json,shutil,sys,subprocess
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BLOCK=("wallet_rng_lab.py","research_engine/rng/","research_engine/security/","research_engine/wallets/","research_engine/vulnerabilities/")
def main():
 ap=argparse.ArgumentParser(); ap.add_argument("patch",type=Path); ap.add_argument("--approve",action="store_true"); a=ap.parse_args()
 x=json.loads(a.patch.read_text(encoding="utf-8")); rel=x.get("path",""); relative=Path(rel)
 if not rel or relative.is_absolute(): print("Rejected path"); return 2
 candidate=ROOT/relative
 if candidate.is_symlink(): print("Rejected path"); return 2
 target=candidate.resolve()
 if not target.is_relative_to(ROOT): print("Rejected path"); return 2
 canonical=target.relative_to(ROOT).as_posix()
 if canonical.startswith(BLOCK): print("Rejected protected path"); return 2
 old=x.get("old"); new=x.get("new")
 if not isinstance(old,str) or not old or not isinstance(new,str) or old==new or not target.is_file(): print("Rejected patch"); return 2
 text=target.read_text(encoding="utf-8")
 if text.count(old)!=1: print("Expected text must match exactly once"); return 2
 if not a.approve: print("Validated; pass --approve to apply"); return 0
 backup=ROOT/"backups"/datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")/rel; backup.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(target,backup)
 target.write_text(text.replace(old,new,1),encoding="utf-8")
 result=subprocess.run([sys.executable,"-m","unittest","discover","-s","tests","-v"],cwd=ROOT,text=True,capture_output=True)
 if result.returncode: shutil.copy2(backup,target); print("Tests failed; rollback completed"); print(result.stdout+result.stderr); return result.returncode
 print("Patch applied; tests passed. Review before publishing."); return 0
if __name__=="__main__": raise SystemExit(main())
