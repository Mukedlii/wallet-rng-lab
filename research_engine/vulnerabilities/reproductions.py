"""Non-exploitative teaching fixtures for controlled RNG research."""
import random
def milk_sad_entropy_ceiling_fixture(seed_value, output_bytes=32):
    """Toy MT19937 model: a 32-bit seed selects at most 2**32 streams.

    This is not a byte-for-byte build of Libbitcoin bx and does not derive keys.
    It demonstrates the entropy ceiling documented in CVE-2023-39910.
    """
    if not 0 <= seed_value <= 0xffffffff: raise ValueError("seed_value must fit in 32 bits")
    if not 1 <= output_bytes <= 4096: raise ValueError("output_bytes must be 1..4096")
    rng=random.Random(seed_value)
    return bytes(rng.getrandbits(8) for _ in range(output_bytes))
