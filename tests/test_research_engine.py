import json, os, tempfile, unittest, subprocess, sys
from pathlib import Path
from research_engine.rng.diagnostics import diagnose, WeakLCG
from research_engine.security.vault import store_secret, decrypt_record, VaultError
from research_engine.database.store import Store
from research_engine.vulnerabilities.catalog import seed_catalog
from wallet_rng_lab import generate_wallet
from research_engine.vulnerabilities.reproductions import milk_sad_entropy_ceiling_fixture
from research_engine.research.feeds import SUSPICIOUS_RNG
from research_engine.monitoring.repair import analyze_traceback
from research_engine.research.ai_review import propose_noncrypto_patch

class EngineTests(unittest.TestCase):
 def test_wallet_chains_and_paths(self):
  expected={"btc":"m/84'/0'/0'/0/0","eth":"m/44'/60'/0'/0/0","sol":"m/44'/501'/0'/0'"}
  for chain,path in expected.items():
   with self.subTest(chain=chain):
    w=generate_wallet(chain); self.assertTrue(w["address"]); self.assertEqual(w["derivation_path"],path)
    if chain=="btc": self.assertTrue(w["address"].startswith("bc1q"))
    if chain=="eth": self.assertTrue(w["address"].startswith("0x") and len(w["address"])==42)
    self.assertEqual(len(w["mnemonic"].split()),12)
 def test_vault_encryption_roundtrip_and_wrong_password(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"vault.jsonl"; payload={"private_key":"TEST-SECRET","mnemonic":"alpha beta"}
   store_secret(p,payload,"correct horse battery staple")
   raw=p.read_text(); self.assertNotIn("TEST-SECRET",raw); self.assertNotIn("alpha beta",raw)
   row=json.loads(raw); self.assertEqual(decrypt_record(row,"correct horse battery staple"),payload)
   with self.assertRaises(Exception): decrypt_record(row,"wrong")
 def test_vault_requires_password(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(VaultError): store_secret(Path(d)/"v.jsonl",{"secret":"x"},"")
 def test_rng_screen_and_weak_fixture(self):
  strong=diagnose(nbytes=4096); weak=diagnose(WeakLCG(11),nbytes=4096)
  self.assertFalse(strong["repeat_detected"]); self.assertEqual(weak["source"],"WeakLCG")
  self.assertEqual(WeakLCG(7)(64),WeakLCG(7)(64))
  self.assertIn("warning",strong)
  constant=lambda n: b"\x00"*n
  self.assertTrue(diagnose(constant,nbytes=1024)["repeat_detected"])
 def test_historical_milk_sad_toy_fixture_is_reproducible(self):
  a=milk_sad_entropy_ceiling_fixture(0x12345678)
  b=milk_sad_entropy_ceiling_fixture(0x12345678)
  self.assertEqual(a,b); self.assertEqual(len(a),32)
  with self.assertRaises(ValueError): milk_sad_entropy_ceiling_fixture(2**32)
 def test_source_pattern_triage_flags_weak_prng_calls(self):
  code="+ const r = Math.random();"
  self.assertTrue(any(label=="js-math-random" and pattern.search(code) for label,pattern in SUSPICIOUS_RNG))
 def test_traceback_diagnosis_and_repair_safety(self):
  x=analyze_traceback('File "module.py", line 12, in run')
  self.assertEqual(x["affected_file"],"module.py"); self.assertFalse(x["auto_apply"])
  self.assertEqual(propose_noncrypto_patch("research_engine/security/vault.py","x","trace")["status"],"blocked-protected-path")
 def test_repair_script_rejects_absolute_protected_path(self):
  with tempfile.TemporaryDirectory() as d:
   patch=Path(d)/"patch.json"
   patch.write_text(json.dumps({"path":str(Path("research_engine/security/vault.py").resolve()),"old":"x","new":"y"}))
   result=subprocess.run([sys.executable,"scripts/repair.py",str(patch)],capture_output=True,text=True)
   self.assertEqual(result.returncode,2)
 def test_catalog_and_sqlite_persistence(self):
  with tempfile.TemporaryDirectory() as d:
   db=Store(Path(d)/"test.db"); seed_catalog(db)
   rows=db.db.execute("SELECT id FROM vulnerabilities").fetchall()
   self.assertEqual({x["id"] for x in rows},{"CVE-2023-39910","CVE-2023-31290","RANDSTORM-2023"})
   rid=db.run_start(); db.run_finish(rid,"success",{"ok":True})
   self.assertEqual(db.db.execute("SELECT status FROM runs WHERE id=?",(rid,)).fetchone()["status"],"success")
   db.close()
if __name__=="__main__": unittest.main()
