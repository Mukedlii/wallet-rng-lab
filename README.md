# Wallet RNG Lab

Local command-line utility for creating **your own** Bitcoin, Ethereum and Solana wallets, checking one address at a time, and measuring local OS-backed randomness throughput.

## Safety model

- Keys and recovery phrases are generated locally with Python's `secrets` module (the operating system CSPRNG).
- No seed phrase or private key is sent to an RPC provider, GitHub, or any remote service.
- Balance lookup accepts one public address at a time. It does not generate candidate keys, enumerate wallets, or search for funds belonging to others.
- A public RPC provider can see the address you query. Use a provider you trust.
- A balance response is not proof of ownership or spendability.
- Back up your recovery phrase offline. Never paste it into chat, websites, or support messages.

## Requirements

- Python 3.11+
- Internet access only for balance queries

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Windows PowerShell activation: `.venv\\Scripts\\Activate.ps1`.

## Commands

Generate one wallet (the recovery phrase and private key are displayed once in the terminal):

```bash
python wallet_rng_lab.py generate --chain btc
python wallet_rng_lab.py generate --chain eth
python wallet_rng_lab.py generate --chain sol
```

Check one address you control:

```bash
python wallet_rng_lab.py balance --chain btc --address YOUR_BTC_ADDRESS
python wallet_rng_lab.py balance --chain eth --address 0xYOUR_ETH_ADDRESS
python wallet_rng_lab.py balance --chain sol --address YOUR_SOL_ADDRESS
```

Optional RPC configuration:
- Ethereum: `ETH_RPC_URL` (defaults to Cloudflare's public Ethereum endpoint)
- Solana: `SOL_RPC_URL` (defaults to Solana mainnet-beta public RPC)

```bash
export ETH_RPC_URL="https://your-trusted-ethereum-rpc"
export SOL_RPC_URL="https://your-trusted-solana-rpc"
```

Run local RNG throughput benchmark:

```bash
python wallet_rng_lab.py benchmark --seconds 5
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Important limitations

A random 256-bit key search has no practical chance of finding a funded wallet. Old or inactive wallets are not unowned. This project intentionally does not implement private-key guessing, brainwallet cracking, historical weak-seed exploitation against third-party wallets, or bulk balance scanning.

The benchmark measures byte-generation throughput only; it is not a measure of the probability of finding a wallet.
