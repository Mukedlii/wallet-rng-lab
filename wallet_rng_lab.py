#!/usr/bin/env python3
"""Local BTC/ETH/SOL wallet generation and single-address balance checks.

Secrets are generated locally. Never send recovery phrases/private keys to RPCs.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from decimal import Decimal
from typing import Any

import requests
from bip_utils import (
    Bip39MnemonicGenerator,
    Bip39SeedGenerator,
    Bip44,
    Bip44Changes,
    Bip44Coins,
    Bip84,
    Bip84Coins,
    Bip39WordsNum,
)
from solders.keypair import Keypair
import base58

TIMEOUT = 15
ETH_RPC_DEFAULT = "https://cloudflare-eth.com"
SOL_RPC_DEFAULT = "https://api.mainnet-beta.solana.com"
BLOCKSTREAM_API = "https://blockstream.info/api"


def _post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = requests.post(url, json=payload, timeout=TIMEOUT)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("Unexpected RPC response")
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")
    return data


def generate_wallet(chain: str) -> dict[str, str]:
    """Generate one BIP39 wallet from OS-backed cryptographic randomness."""
    entropy = secrets.token_bytes(16)  # 128 bits -> 12-word BIP39 mnemonic
    mnemonic = str(Bip39MnemonicGenerator().FromEntropy(entropy))
    seed = Bip39SeedGenerator(mnemonic).Generate()

    if chain == "btc":
        ctx = (Bip84.FromSeed(seed, Bip84Coins.BITCOIN)
               .Account(0).Change(Bip84Changes.CHAIN_EXT).AddressIndex(0))
        return {
            "chain": "Bitcoin (native SegWit / BIP84)",
            "address": ctx.PublicKey().ToAddress(),
            "private_key": ctx.PrivateKey().ToWif(),
            "mnemonic": mnemonic,
            "derivation_path": "m/84'/0'/0'/0/0",
        }

    if chain == "eth":
        ctx = (Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
               .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
               .AddressIndex(0))
        return {
            "chain": "Ethereum (BIP44)",
            "address": ctx.PublicKey().ToAddress(),
            "private_key": "0x" + ctx.PrivateKey().Raw().ToHex(),
            "mnemonic": mnemonic,
            "derivation_path": "m/44'/60'/0'/0/0",
        }

    if chain == "sol":
        ctx = (Bip44.FromSeed(seed, Bip44Coins.SOLANA)
               .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
               .AddressIndex(0))
        seed32 = ctx.PrivateKey().Raw().ToBytes()
        keypair = Keypair.from_seed(seed32)
        return {
            "chain": "Solana (BIP44)",
            "address": str(keypair.pubkey()),
            "private_key": base58.b58encode(bytes(keypair)).decode("ascii"),
            "mnemonic": mnemonic,
            "derivation_path": "m/44'/501'/0'/0'",
        }

    raise ValueError("Unsupported chain")


def get_balance(chain: str, address: str) -> dict[str, str]:
    """Query one public address. No private material is accepted or transmitted."""
    if not address or any(ch.isspace() for ch in address):
        raise ValueError("Address is empty or contains whitespace")

    if chain == "btc":
        url = f"{BLOCKSTREAM_API}/address/{address}"
        response = requests.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
        funded = int(data["chain_stats"]["funded_txo_sum"])
        spent = int(data["chain_stats"]["spent_txo_sum"])
        mem_funded = int(data["mempool_stats"]["funded_txo_sum"])
        mem_spent = int(data["mempool_stats"]["spent_txo_sum"])
        sats = funded - spent + mem_funded - mem_spent
        return {"chain": "BTC", "address": address,
                "balance": f"{Decimal(sats) / Decimal(100_000_000):f} BTC",
                "source": "Blockstream public API"}

    if chain == "eth":
        rpc = os.getenv("ETH_RPC_URL", ETH_RPC_DEFAULT)
        data = _post_json(rpc, {"jsonrpc": "2.0", "id": 1,
                                "method": "eth_getBalance",
                                "params": [address, "latest"]})
        wei = int(data["result"], 16)
        return {"chain": "ETH", "address": address,
                "balance": f"{Decimal(wei) / Decimal(10**18):f} ETH",
                "source": rpc}

    if chain == "sol":
        rpc = os.getenv("SOL_RPC_URL", SOL_RPC_DEFAULT)
        data = _post_json(rpc, {"jsonrpc": "2.0", "id": 1,
                                "method": "getBalance",
                                "params": [address]})
        lamports = int(data["result"]["value"])
        return {"chain": "SOL", "address": address,
                "balance": f"{Decimal(lamports) / Decimal(10**9):f} SOL",
                "source": rpc}

    raise ValueError("Unsupported chain")


def benchmark(seconds: int) -> dict[str, float | int]:
    """Measure local secrets.token_bytes throughput; not a key-search benchmark."""
    if seconds < 1 or seconds > 300:
        raise ValueError("seconds must be between 1 and 300")
    count = 0
    started = time.perf_counter()
    deadline = started + seconds
    while time.perf_counter() < deadline:
        secrets.token_bytes(32)
        count += 1
    elapsed = time.perf_counter() - started
    return {"seconds": round(elapsed, 3), "32_byte_samples": count,
            "samples_per_second": round(count / elapsed, 2),
            "bytes_per_second": round((count * 32) / elapsed, 2)}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Local wallet generation, one-address balance lookup, and RNG benchmark")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate one new wallet locally")
    gen.add_argument("--chain", choices=("btc", "eth", "sol"), required=True)

    bal = sub.add_parser("balance", help="Check one public address you control")
    bal.add_argument("--chain", choices=("btc", "eth", "sol"), required=True)
    bal.add_argument("--address", required=True)

    bench = sub.add_parser("benchmark", help="Benchmark OS CSPRNG byte generation")
    bench.add_argument("--seconds", type=int, default=5)

    args = parser.parse_args()
    try:
        if args.command == "generate":
            wallet = generate_wallet(args.chain)
            print("\n=== NEW WALLET — SAVE OFFLINE ===")
            print("Chain:             " + wallet["chain"])
            print("Address:           " + wallet["address"])
            print("Derivation path:   " + wallet["derivation_path"])
            print("\nRECOVERY PHRASE (12 words):")
            print(wallet["mnemonic"])
            print("\nPRIVATE KEY:")
            print(wallet["private_key"])
            print("\nWARNING: Anyone with the phrase/private key can control the funds.")
            print("This information was generated locally; it was not uploaded.")
        elif args.command == "balance":
            print(json.dumps(get_balance(args.chain, args.address),
                             indent=2, ensure_ascii=False))
            print("Note: the RPC provider can see the queried public address.")
        else:
            print(json.dumps(benchmark(args.seconds), indent=2))
            print("This measures RNG throughput, not wallet-search probability.")
        return 0
    except (requests.RequestException, KeyError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
