import hashlib,math,secrets
def _runs(bits): return 1+sum(x!=y for x,y in zip(bits,bits[1:])) if bits else 0
def diagnose(source=None,nbytes=65536):
 source=source or secrets.token_bytes
 if not 1024<=nbytes<=4*1024*1024: raise ValueError("nbytes must be 1 KiB..4 MiB")
 a=source(nbytes); b=source(nbytes)
 if len(a)!=nbytes or len(b)!=nbytes: raise ValueError("Unexpected RNG output length")
 bits=[(v>>i)&1 for v in a for i in range(8)]; n=len(bits); ones=sum(bits); p=ones/n
 z=abs(ones-n/2)/math.sqrt(n/4); runs=_runs(bits); expected=2*n*p*(1-p)+1
 variance=(2*n*p*(1-p)*(2*n*p*(1-p)-1))/(n-1)
 runs_z=abs(runs-expected)/math.sqrt(variance) if variance>0 else 999.0
 mean=p; x=bits[:-1]; y=bits[1:]
 denom=sum((v-mean)**2 for v in x)*sum((v-mean)**2 for v in y)
 lag1=sum((u-mean)*(v-mean) for u,v in zip(x,y))/math.sqrt(denom) if denom else 0.0
 return {"source":getattr(source,"__name__",source.__class__.__name__),"bytes":nbytes,"sha256_a":hashlib.sha256(a).hexdigest(),"sha256_b":hashlib.sha256(b).hexdigest(),"repeat_detected":a==b,"monobit_ones_ratio":round(p,6),"monobit_abs_z":round(z,4),"runs":runs,"runs_expected_approx":round(expected,2),"runs_abs_z":round(runs_z,4),"lag1_bit_correlation":round(lag1,6),"unique_16byte_blocks":len({a[i:i+16] for i in range(0,len(a)-15,16)}),"statistical_screen":"PASS" if z<6 and runs_z<6 and a!=b else "REVIEW","warning":"Statistical screens do not prove cryptographic security."}
class WeakLCG:
 """Intentionally insecure deterministic RNG fixture; never use for wallets."""
 def __init__(self,seed=1): self.state=seed&0xffffffff
 def __call__(self,n):
  out=bytearray()
  while len(out)<n:
   self.state=(1664525*self.state+1013904223)&0xffffffff; out.extend(self.state.to_bytes(4,"little"))
  return bytes(out[:n])
