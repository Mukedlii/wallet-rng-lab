# Wallet RNG Research Engine 2.0

Local-first research and diagnostics for historical cryptocurrency wallet RNG weaknesses. Intended for authorized research, self-generated test wallets and public advisory data. It does not search for or recover third-party private keys.

## Features in this increment

- Local Bitcoin BIP84, Ethereum BIP44 and Solana SLIP-0010 Ed25519 test wallet generation.
- Encrypted local secret vault (required for engine wallet generation) (Fernet + Scrypt); keys and recovery phrases are not stored in SQLite or ordinary logs.
- SQLite research database with WAL, vulnerability catalogue, advisory ingestion, run history and event records.
- NVD CVE API, GitHub Global Advisory Database and configured wallet-repository commit metadata monitoring.
- OS CSPRNG statistical screening plus intentionally weak deterministic LCG and MT19937 entropy-ceiling teaching fixtures for tests only. The Milk Sad fixture demonstrates the 32-bit seed-space limitation; it is not a byte-for-byte reproduction of bx.
- Telegram notifications from environment variables; no secrets in alert text.
- Continuous worker loop, traceback capture, CPU/RAM observations and retry after recoverable errors.
- Guarded patch helper: accepts a reviewed JSON text replacement, refuses cryptographic, RNG, vault, wallet and vulnerability-catalogue paths, creates backups and rolls back on failed tests. It does not require Git.
- Windows PowerShell install, start and test scripts.

## Windows installation

Run PowerShell from the repository folder:

    Set-ExecutionPolicy -Scope Process Bypass
    .\scripts\install.ps1

Edit .env and set a strong WALLET_VAULT_PASSPHRASE. Wallet generation refuses to proceed without it. Telegram variables are optional. Never commit .env.

Run tests with .\scripts	est.ps1. Run one research cycle with .\.venv\Scripts\python.exe -m research_engine once. Start the worker with .\scripts\start.ps1. Register a logon startup task with .\scripts\register-task.ps1; remove it with .\scripts\unregister-task.ps1. Back up local data with .\scripts\backup.ps1.

Create an encrypted test wallet with .\.venv\Scripts\python.exe -m research_engine wallet --chain btc (also eth or sol). The command prints only public metadata. Back up the encrypted vault and passphrase separately. Run diagnostics with .\.venv\Scripts\python.exe -m research_engine rng-test. Verify a recovered vault/passphrase without revealing secrets with .\.venv\Scripts\python.exe -m research_engine vault-check. Export the encrypted vault with .\.venv\Scripts\python.exe -m research_engine vault-export --out D:\SecureBackup\wallet-vault.jsonl.

## Historical vulnerability notes

CVE-2023-31290: Trust Wallet Core before 3.1.1 and browser extension 0.0.172–0.0.182 used an MT19937 generator seeded with 32 bits in the affected WASM path. The fixed versions are Core 3.1.1 and extension 0.0.183. This browser-extension incident affected Ethereum and Solana among other supported assets; it does not mean all Trust Wallet platforms were vulnerable.

CVE-2023-39910 (Milk Sad): NVD identifies Libbitcoin Explorer 3.0.0–3.6.0 and a 32-bit effective entropy limitation in bx seed. Researcher FAQ reports that 3.8.0 removed the problematic command; previously generated seed material remains exposed.

RANDSTORM-2023 is a historical research disclosure, not a CVE. Unciphered describes JSBN SecureRandom combined with browser Math.random weaknesses in historical browser-wallet stacks and reports vulnerable wallet creation during 2011–2015. Product exposure is wallet- and version-specific.

The catalogue does not assume that current Bitcoin, Ethereum or Solana wallets share these historical weaknesses. Exact exposure must be verified against software lineage and reproducible evidence.

## Limitations and safety

- Statistical RNG tests are screening tools; they cannot prove cryptographic security.
- NVD/GitHub checks require network access. Failed feeds fail the cycle; they are not treated as zero findings.
- Repository commit monitoring is heuristic triage, not source-code proof. Findings require manual review and reproducible tests.
- Optional AI diff triage is available in research_engine/research/ai_review.py when AI_REVIEW_ENABLED, AI_API_KEY and AI_MODEL are configured. It is advisory-only and forces confirmed=false. When enabled, traceback triage can also produce a non-crypto patch proposal, never auto-applied. Live-model calls were not exercised in this validation run.
- Worker runs as a foreground process. Register scripts/register-task.ps1 to restart it at user logon; remove with scripts/unregister-task.ps1.
- Auto-repair is deliberately not autonomous for cryptographic code. Patch helper requires explicit approval, blocks protected paths and never pushes.
- Wallet creation is an explicit bounded CLI action; the worker does not generate wallets continuously.
- Legacy wallet_rng_lab.py generate remains for compatibility and prints secrets. Prefer the encrypted research_engine wallet command.

## Project layout

research_engine/research — NVD, GitHub advisories and commit feed
research_engine/vulnerabilities — historical vulnerability catalogue
research_engine/rng — diagnostics and test-only weak generators
research_engine/wallets — encrypted test wallet service
research_engine/security — encrypted vault
research_engine/monitoring — scheduled worker and health observations
research_engine/notifications — Telegram alerts
research_engine/database — persistent SQLite storage
tests — unit and integration tests
scripts — PowerShell automation and guarded repair

See config.yaml and .env.example for configuration. Local database, vault and logs are excluded from Git.
