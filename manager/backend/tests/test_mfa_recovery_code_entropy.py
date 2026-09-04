"""
Regression test: MFA recovery codes must carry >=40 bits of entropy.

A prior implementation used secrets.token_hex(4) (32 bits), too low for a
single-use bearer secret even though it is bcrypt-hashed at rest.
"""

import math

from app.services.mfa_service import MFAService


def test_recovery_codes_have_at_least_40_bits_of_entropy():
    """Each generated recovery code must encode >=40 bits of randomness."""
    plain_codes, hashed_codes = MFAService.generate_recovery_codes(count=8)

    assert len(plain_codes) == 8
    for code in plain_codes:
        # Codes are uppercased hex -- 4 bits per character.
        assert all(c in '0123456789ABCDEF' for c in code)
        entropy_bits = len(code) * math.log2(16)
        assert entropy_bits >= 40, (
            f"recovery code {code!r} has only {entropy_bits} bits of entropy"
        )

    # Codes must still be unique per generation call.
    assert len(set(plain_codes)) == len(plain_codes)


def test_recovery_codes_remain_bcrypt_hashed_and_verifiable():
    """Storage/verify format is unchanged -- bcrypt hash, constant-time check."""
    plain_codes, hashed_codes = MFAService.generate_recovery_codes(count=1)
    code, code_hash = plain_codes[0], hashed_codes[0]

    assert code_hash.startswith('$2')  # bcrypt hash prefix
    assert MFAService.verify_recovery_code(code, code_hash) is True
    assert MFAService.verify_recovery_code('WRONGWRONGWRONG', code_hash) is False
