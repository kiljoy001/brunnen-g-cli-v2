"""
Brunnen-G Identity Algorithm
Copyright (C) 2024 Scott Guyton

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License. See LICENSE.md for full terms.
"""

import asyncpg
import hashlib
from pqcrypto.sign.ml_dsa_65 import generate_keypair, sign, verify

class IdentityAlgorithm:
    def __init__(self):
        pass
    
    @staticmethod
    async def compute_identity(tpm_public_key: bytes, dilithium_sig_on_emercoin_hash: bytes,
                               yubikey_public_key: bytes) -> tuple[bytes, bytes]:
        """Compute IDstable and DIH"""
        # Domain Identity Hash (DIH)
        h_dilithium_sig = hashlib.sha256(dilithium_sig_on_emercoin_hash).digest()
        dih = hashlib.sha256(tpm_public_key + h_dilithium_sig).digest()

        # Stable Identity Hash
        h_yubikey_pk = hashlib.sha256(yubikey_public_key).digest()
        id_stable = hashlib.sha256(dih + h_yubikey_pk).digest()

        return id_stable, dih
    
    @staticmethod
    async def compute_dih(tpm_pubkey: bytes, dilithium_sig_on_emercoin_hash: bytes):
        """Compute DOmain Identity Hash: H(TPMpk || H(DILsig))"""
        return hashlib.sha256(tpm_pubkey + hashlib.sha256(dilithium_sig_on_emercoin_hash)).digest()

    
    @staticmethod
    async def verify_identity(id_stable: bytes, dih: bytes, merkle_proof: list[tuple[str, bytes]], 
                             merkle_index: int, dilithium_domain_signature: bytes, 
                             dilithium_public_key: bytes, merkle_root: bytes,
                             yubikey_public_key: bytes, challenge: bytes, 
                             yubikey_signature: bytes) -> bool:
        """
        Verify identity using merkle proof, dilithium signature, and yubikey challenge
        """
        # Step 1: Verify YubiKey owns this identity (liveness check)
        challenge_response = hashlib.sha256(id_stable + challenge).digest()
        if not yubikey_verify(yubikey_public_key, challenge_response, yubikey_signature):
            return False
        
        # Step 2: Verify Dilithium signature on DIH
        if not verify(dilithium_public_key, dih, dilithium_domain_signature):
            return False
        
        # Step 3: Verify merkle proof using id_stable as leaf
        current_hash = id_stable
        for position, sibling_hash in merkle_proof:
            if position == 'left':
                current_hash = hashlib.sha256(sibling_hash + current_hash).digest()
            else:
                current_hash = hashlib.sha256(current_hash + sibling_hash).digest()
        
        return current_hash == merkle_root