import sqlite3,json
from pathlib import Path
from datetime import datetime,timezone
class Store:
 def __init__(self,path):
  self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
  self.db=sqlite3.connect(self.path,timeout=20); self.db.row_factory=sqlite3.Row
  self.db.execute("PRAGMA journal_mode=WAL"); self.db.execute("PRAGMA foreign_keys=ON")
  self.db.executescript("""
  CREATE TABLE IF NOT EXISTS vulnerabilities(id TEXT PRIMARY KEY,title TEXT NOT NULL,chain TEXT,status TEXT NOT NULL,affected TEXT,root_cause TEXT,still_relevant TEXT,sources TEXT,updated_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS advisories(id TEXT PRIMARY KEY,source TEXT NOT NULL,title TEXT NOT NULL,url TEXT,summary TEXT,published TEXT,raw_json TEXT,created_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY AUTOINCREMENT,started_at TEXT NOT NULL,finished_at TEXT,status TEXT NOT NULL,details TEXT);
  CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT NOT NULL,level TEXT NOT NULL,event TEXT NOT NULL,details TEXT);
  CREATE TABLE IF NOT EXISTS wallet_metadata(id TEXT PRIMARY KEY,chain TEXT,address TEXT,derivation_path TEXT,created_at TEXT NOT NULL,vault_ref TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS chain_snapshots(id INTEGER PRIMARY KEY AUTOINCREMENT,chain TEXT NOT NULL,address TEXT NOT NULL,checked_at TEXT NOT NULL,balance_native TEXT NOT NULL,unit TEXT NOT NULL,tx_count INTEGER,details_json TEXT NOT NULL);
  """); self.db.commit()
 def now(self): return datetime.now(timezone.utc).isoformat()
 def event(self,level,event,details=None):
  self.db.execute("INSERT INTO events(created_at,level,event,details) VALUES(?,?,?,?)",(self.now(),level,event,json.dumps(details or {},ensure_ascii=False))); self.db.commit()
 def run_start(self):
  c=self.db.execute("INSERT INTO runs(started_at,status) VALUES(?,?)",(self.now(),"running")); self.db.commit(); return c.lastrowid
 def run_finish(self,rid,status,details=None):
  self.db.execute("UPDATE runs SET finished_at=?,status=?,details=? WHERE id=?",(self.now(),status,json.dumps(details or {}),rid)); self.db.commit()
 def upsert_vulnerability(self,x):
  self.db.execute("INSERT INTO vulnerabilities VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,chain=excluded.chain,status=excluded.status,affected=excluded.affected,root_cause=excluded.root_cause,still_relevant=excluded.still_relevant,sources=excluded.sources,updated_at=excluded.updated_at",(x["id"],x["title"],x.get("chain"),x["status"],x.get("affected"),x.get("root_cause"),x.get("still_relevant"),json.dumps(x.get("sources",[])),self.now())); self.db.commit()
 def add_advisory(self,a):
  c=self.db.execute("INSERT OR IGNORE INTO advisories VALUES(?,?,?,?,?,?,?,?)",(a["id"],a["source"],a["title"],a.get("url"),a.get("summary"),a.get("published"),json.dumps(a.get("raw",{}))[:20000],self.now())); self.db.commit(); return c.rowcount>0
 def add_wallet_metadata(self,wid,chain,address,path,ref):
  self.db.execute("INSERT INTO wallet_metadata VALUES(?,?,?,?,?,?)",(wid,chain,address,path,self.now(),ref)); self.db.commit()
 def add_chain_snapshot(self,item):
  self.db.execute("INSERT INTO chain_snapshots(chain,address,checked_at,balance_native,unit,tx_count,details_json) VALUES(?,?,?,?,?,?,?)",(item["chain"],item["address"],item["checked_at"],item["balance_native"],item["unit"],item.get("tx_count"),json.dumps(item.get("transactions",[]),ensure_ascii=False))); self.db.commit()
 def close(self): self.db.close()
