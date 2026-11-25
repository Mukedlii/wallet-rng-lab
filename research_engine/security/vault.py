import base64,json,os
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
class VaultError(RuntimeError): pass
def _cipher(passphrase,salt):
 if not passphrase: raise VaultError("Set WALLET_VAULT_PASSPHRASE before wallet generation.")
 key=Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(passphrase.encode())
 return Fernet(base64.urlsafe_b64encode(key))
def store_secret(path,payload,passphrase):
 p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); salt=os.urandom(16)
 row={"v":1,"salt":base64.b64encode(salt).decode(),"ciphertext":_cipher(passphrase,salt).encrypt(json.dumps(payload).encode()).decode()}
 with p.open("a+",encoding="utf-8") as f:
  f.seek(0); record_number=sum(1 for _ in f)+1; f.seek(0,2); f.write(json.dumps(row)+"\n")
 try: os.chmod(p,0o600)
 except OSError: pass
 return str(p)+"#"+str(record_number)
def decrypt_record(row,passphrase):
 return json.loads(_cipher(passphrase,base64.b64decode(row["salt"])).decrypt(row["ciphertext"].encode()))
