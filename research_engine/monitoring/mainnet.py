"""Mainnet read-only monitor for explicitly allowlisted addresses only."""
import os, requests
from decimal import Decimal
from datetime import datetime, timezone

class MonitorError(RuntimeError): pass

def _get(url, timeout=20):
    r=requests.get(url, headers={"User-Agent":"WalletRNGResearchEngine/2.1"}, timeout=timeout)
    r.raise_for_status()
    return r.json()

def _rpc(url, method, params, timeout=20):
    if not url: raise MonitorError("Missing RPC endpoint configuration")
    r=requests.post(url, json={"jsonrpc":"2.0","id":1,"method":method,"params":params},
                    headers={"Content-Type":"application/json"}, timeout=timeout)
    r.raise_for_status(); data=r.json()
    if data.get("error"): raise MonitorError(str(data["error"]))
    return data.get("result")

def monitor_btc(address, timeout=20):
    d=_get("https://mempool.space/api/address/"+address, timeout)
    chain=d.get("chain_stats",{}); mem=d.get("mempool_stats",{})
    funded=chain.get("funded_txo_sum",0)+mem.get("funded_txo_sum",0)
    spent=chain.get("spent_txo_sum",0)+mem.get("spent_txo_sum",0)
    txs=_get("https://mempool.space/api/address/"+address+"/txs",timeout)
    return {"chain":"btc","network":"mainnet","address":address,"balance_native":str(Decimal(funded-spent)/Decimal(100000000)),
            "unit":"BTC","tx_count":chain.get("tx_count",0)+mem.get("tx_count",0),
            "transactions":[{"txid":x.get("txid"),"status":x.get("status",{}),"fee_sat":x.get("fee")} for x in txs[:25]]}

def monitor_eth(address, timeout=20):
    rpc=os.getenv("ETH_MAINNET_RPC_URL")
    if rpc:
        wei=int(_rpc(rpc,"eth_getBalance",[address,"latest"],timeout),16)
        nonce=int(_rpc(rpc,"eth_getTransactionCount",[address,"latest"],timeout),16)
        balance=Decimal(wei)/Decimal(10**18)
    else:
        d=_get("https://eth.blockscout.com/api/v2/addresses/"+address,timeout)
        balance=Decimal(d.get("coin_balance") or "0")/Decimal(10**18)
        nonce=None
    history=_get("https://eth.blockscout.com/api/v2/addresses/"+address+"/transactions",timeout)
    items=history.get("items",[])
    return {"chain":"eth","network":"mainnet","address":address,"balance_native":str(balance),
            "unit":"ETH","tx_count":nonce,"transactions":[{"tx_hash":x.get("hash"),"timestamp":x.get("timestamp"),
            "from":(x.get("from") or {}).get("hash"),"to":(x.get("to") or {}).get("hash"),
            "value_wei":(x.get("value")),"status":x.get("status")} for x in items[:25]]}

def monitor_sol(address, timeout=20):
    rpc=os.getenv("SOL_MAINNET_RPC_URL","https://api.mainnet-beta.solana.com")
    lamports=int(_rpc(rpc,"getBalance",[address,{"commitment":"confirmed"}],timeout)["value"])
    sigs=_rpc(rpc,"getSignaturesForAddress",[address,{"limit":25}],timeout) or []
    return {"chain":"sol","network":"mainnet","address":address,
            "balance_native":str(Decimal(lamports)/Decimal(10**9)),"unit":"SOL",
            "tx_count":None,"transactions":[{"signature":x.get("signature"),"block_time":x.get("blockTime"),
            "slot":x.get("slot"),"err":x.get("err")} for x in sigs]}

def monitor_authorized_addresses(config):
    """Only addresses explicitly placed in config.yaml mainnet_monitor.allowlist are queried."""
    allow=config.get("mainnet_monitor",{}).get("allowlist",[])
    results=[]
    for item in allow:
        chain=str(item.get("chain","")).lower(); address=str(item.get("address","")).strip()
        if chain not in ("btc","eth","sol") or not address:
            raise ValueError("Allowlist entries require chain btc/eth/sol and a non-empty address")
        fn={"btc":monitor_btc,"eth":monitor_eth,"sol":monitor_sol}[chain]
        result=fn(address,int(config.get("mainnet_monitor",{}).get("timeout_seconds",20)))
        result["checked_at"]=datetime.now(timezone.utc).isoformat()
        results.append(result)
    return results
