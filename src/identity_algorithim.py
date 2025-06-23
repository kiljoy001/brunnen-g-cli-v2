import asyncpg
import hashlib

class IdentityAlgorithm:
    def __init__(self):
        pass

    async def compute_identity(self, tpm_public_key: bytes, dilithium_sig_on_emercoin_hash: bytes,
                               yubikey_public_key: bytes) -> tuple[bytes, bytes]:
        # Domain Identity Hash (DIH)
        h_dilithium_sig = hashlib.sha256(dilithium_sig_on_emercoin_hash).digest()
        dih = hashlib.sha256(tpm_public_key + h_dilithium_sig).digest()

        # Stable Identity Hash
        h_yubikey_pk = hashlib.sha256(yubikey_public_key).digest()
        id_stable = hashlib.sha256(dih + h_yubikey_pk).digest()

        return id_stable, dih

    async def verify_identity(self, dih:bytes, merkle_proof: [bytes], merkle_index: int, dilithium_domain_signature: bytes) -> bool:
        pass