import os,uuid
from wallet_rng_lab import generate_wallet
from research_engine.security.vault import store_secret
def create_test_wallet(chain,config):
 limit=int(config.get("wallets",{}).get("max_wallets_per_run",3))
 if not 1<=limit<=20: raise ValueError("max_wallets_per_run must be 1..20")
 w=generate_wallet(chain); wid=str(uuid.uuid4())
 ref=store_secret(config.get("wallets",{}).get("vault_file","data/wallet-vault.jsonl"),{**w,"wallet_id":wid},os.getenv("WALLET_VAULT_PASSPHRASE"))
 return {"id":wid,"chain":chain,"address":w["address"],"derivation_path":w["derivation_path"],"vault_ref":ref}
