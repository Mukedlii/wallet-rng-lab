import unittest

from wallet_rng_lab import generate_wallet, benchmark


class WalletGenerationTests(unittest.TestCase):
    def test_generates_valid_looking_addresses_and_secrets(self):
        for chain in ("btc", "eth", "sol"):
            with self.subTest(chain=chain):
                wallet = generate_wallet(chain)
                self.assertTrue(wallet["address"])
                self.assertEqual(len(wallet["mnemonic"].split()), 12)
                self.assertTrue(wallet["private_key"])
                self.assertTrue(wallet["derivation_path"])

    def test_generates_distinct_wallets(self):
        first = generate_wallet("eth")
        second = generate_wallet("eth")
        self.assertNotEqual(first["address"], second["address"])
        self.assertNotEqual(first["mnemonic"], second["mnemonic"])

    def test_benchmark(self):
        result = benchmark(1)
        self.assertGreater(result["32_byte_samples"], 0)
        self.assertGreater(result["samples_per_second"], 0)


if __name__ == "__main__":
    unittest.main()
