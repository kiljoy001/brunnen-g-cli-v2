import hashlib
import os
import random
from pqcrypto.sign.ml_dsa_65 import generate_keypair, sign
from hypothesis.strategies import SearchStrategy, binary, just, composite, integers
from hypothesis import strategies as st
from faker import Faker

from src.identity_algorithim import IdentityAlgorithm


# Hypothesis strategies
def generate_ecc_strategy() -> tuple[SearchStrategy[bytes], SearchStrategy[bytes]]:
    """Creates a faked ECC signature and public key using hypothesis strategies."""
    coord = st.binary(min_size=32, max_size=32)
    ecc_pubkey = st.tuples(coord, coord).map(
        lambda pair: b'\x04' + pair[0] + pair[1]
    )
    ecc_signature = st.binary(min_size=64, max_size=64)
    return ecc_pubkey, ecc_signature

def generate_domain_names() -> SearchStrategy[str]:
    """Creates a faked domain names using the emercoin tlds and faker (top level domains)"""
    name_generator = Faker()
    emercoin_tlds = ["coin","emc", "lib", "bazar"]
    domain_maker = st.builds(
        lambda tlds: f"{name_generator.first_name()}.{tlds}",
        tlds=st.sampled_from(emercoin_tlds)
    )
    return domain_maker

def generate_emercoin_signature() -> SearchStrategy[bytes]:
    """Creates fake Emercoin ECDSA signature (DER format)"""
    return st.binary(min_size=66, max_size=66)

def generate_dilithium_hashes() -> SearchStrategy[bytes]:
    """Creates a fake Dilithium signature of 3293 bytes (version3)"""
    return st.binary(min_size=3293, max_size=3293)

def generate_32_bytes() -> SearchStrategy[bytes]:
    """Creates faked yubikey hashes using hypothesis strategies."""
    return st.binary(min_size=32, max_size=32)

def generate_usernames() -> SearchStrategy[str]:
    """Creates a faked username using hypothesis strategies."""
    return st.builds(lambda: Faker().first_name())

def generate_yubikey_signature(yubi_pubkey: bytes) -> bytes:
    """Generate deterministic mock signature for testing"""
    return hashlib.sha256(b"yubikey_sig" + yubi_pubkey).digest() + os.urandom(32)

def mockdb_row_hasher(user_data: dict) -> bytes:
    """Creates hashes for testing and tree generation"""
    husername = hashlib.sha256(user_data["username"].encode('utf-8')).digest()
    htpm_pubkey = hashlib.sha256(user_data["tpm_pubkey"]).digest()
    hmerkle_index = hashlib.sha256(user_data["merkle_index"]).digest()
    hyubikey_pubkey = hashlib.sha256(user_data["yubikey_pub_key"]).digest()
    combined_bytes = husername + htpm_pubkey + hmerkle_index + hyubikey_pubkey
    row_hash = hashlib.sha256(combined_bytes).digest()
    return row_hash

@composite
def minor_byte_string_changes(draw, original_bytes_strategy: SearchStrategy[bytes]):
    """
    A Hypothesis strategy to generate a byte string that is a minor variation
    of an original byte string drawn from the provided strategy.
    """
    original = draw(original_bytes_strategy)

    # Handle empty original input as a special case
    if not original:
        return draw(binary(min_size=1, max_size=1)) # Return a single random byte

    # Choose a modification type randomly using Hypothesis's 'draw'
    modification_type = draw(just('flip_bit') | just('change_byte') | just('append_byte') | just('truncate_byte'))

    modified_data_bytes = None # Initialize to ensure explicit return

    # Use match-case for cleaner handling of modification types (Python 3.10+)
    match modification_type:
        case 'flip_bit':
            # Flip a single random bit at a random index
            byte_index = draw(integers(min_value=0, max_value=len(original) - 1))
            bit_index = draw(integers(min_value=0, max_value=7)) # 0-7 for the 8 bits in a byte

            temp_data = bytearray(original)
            temp_data[byte_index] ^= (1 << bit_index) # XOR with a bitmask to flip
            modified_data_bytes = bytes(temp_data)

        case 'change_byte':
            # Change a single random byte at a random index to a new random value
            byte_index = draw(integers(min_value=0, max_value=len(original) - 1))
            new_byte_value = draw(integers(min_value=0, max_value=255)) # Draw an integer byte value

            temp_data = bytearray(original)
            temp_data[byte_index] = new_byte_value
            modified_data_bytes = bytes(temp_data)

        case 'append_byte':
            # Append a single random byte to the end
            new_byte = draw(binary(min_size=1, max_size=1))
            modified_data_bytes = original + new_byte

        case 'truncate_byte':
            # Truncate by a single byte from the end, ensuring it doesn't become empty
            if len(original) > 1:
                modified_data_bytes = original[:-1]
            else:
                # If the original has only one byte, we can't truncate without making it empty.
                # Instead, change the single byte to a different random value.
                # Use binary().filter() to ensure it's different.
                modified_data_bytes = draw(binary(min_size=1, max_size=1).filter(lambda b: b != original))
                # Fallback if the filter accidentally yields nothing (very rare but possible with specific constraints)
                if not modified_data_bytes:
                    modified_data_bytes = bytes([random.randint(0, 255)]) # Just pick a random byte

        # Ensure a value was assigned; this acts as a safeguard
    if modified_data_bytes is None:
        raise RuntimeError(f"Failed to generate modified data for type: {modification_type}")

    return modified_data_bytes


@composite
def merkle_proof_strategy(draw):
    """Generate valid merkle proof as list of bytes"""
    proof_length = draw(st.integers(min_value=1, max_value=20))
    return [draw(generate_32_bytes()) for _ in range(proof_length)]


@composite
def dilithium_keypair_strategy(draw):
    """Generate real Dilithium3 keypair"""
    public_key, secret_key = generate_keypair()
    return {'public_key': public_key, 'secret_key': secret_key}


@composite
def merkle_tree_data_strategy(draw):
    """Generate consistent merkle tree data with real Dilithium signature"""
    keypair = draw(dilithium_keypair_strategy())
    dih = draw(generate_32_bytes())

    # Sign the DIH with Dilithium
    signature = sign(keypair['secret_key'], dih)

    return {
        'dih': dih,
        'merkle_proof': draw(merkle_proof_strategy()),
        'merkle_index': draw(st.integers(min_value=0, max_value=2 ** 16 - 1)),
        'dilithium_signature': signature,
        'dilithium_public_key': keypair['public_key']
    }