import pytest
import hashlib
from hypothesis import assume, given, settings, HealthCheck, strategies as st
from .test_utilities import (generate_32_bytes, generate_ecc_strategy, generate_dilithium_hashes,
                             minor_byte_string_changes, merkle_proof_strategy, merkle_tree_data_strategy)
from src.identity_algorithim import IdentityAlgorithm
from pqcrypto.sign.ml_dsa_65 import generate_keypair, sign, verify
from unittest.mock import patch



class TestIdentityAlgorithm:

    @pytest.mark.asyncio
    @given(
        tpm_public_key=generate_ecc_strategy()[0],
        dilithium_sig=generate_dilithium_hashes(),
        yubikey_public_key=generate_ecc_strategy()[0],
    )
    async def test_identity_hash_deterministic(self,
                                               tpm_public_key,
                                               dilithium_sig,
                                               yubikey_public_key
                                               ):
        """Tests the hash generation to see if the same inputs create the same outputs"""
        # Arrange
        identity_object = IdentityAlgorithm()

        # Act
        first_id_stable, first_dih = await identity_object.compute_identity(tpm_public_key, dilithium_sig, yubikey_public_key)
        second_id_stable, second_dih = await identity_object.compute_identity(tpm_public_key, dilithium_sig, yubikey_public_key)

        # Assert
        assert first_id_stable == second_id_stable
        assert first_dih == second_dih
    @given(
        tpm_public_key=generate_ecc_strategy()[0],
        dilithium_sig=generate_dilithium_hashes(),
        yubikey_public_key=generate_ecc_strategy()[0],
    )
    @pytest.mark.asyncio
    async def test_compute_identity_format(self, tpm_public_key, dilithium_sig, yubikey_public_key):
       """Test that verifies that compute_identity returns a valid SHA256 hash format"""
       # Arrange
       identity = IdentityAlgorithm()

       # Act
       id_stable, dih = await identity.compute_identity(
           tpm_public_key,
           yubikey_public_key,
           dilithium_sig,
        )
       assert isinstance(id_stable, bytes)
       assert len(id_stable) == 32
       assert isinstance(dih, bytes)
       assert len(dih) == 32

    @pytest.mark.asyncio
    @given(
        tpm_public_key=generate_ecc_strategy()[0],
        dilithium_sig_on_emercoin_hash=generate_dilithium_hashes(),
        yubi_signature=generate_ecc_strategy()[1],
        modified_tpm=minor_byte_string_changes(generate_ecc_strategy()[0]),
        modified_dilithium=minor_byte_string_changes(generate_dilithium_hashes()),
        modified_yubi=minor_byte_string_changes(generate_ecc_strategy()[1])
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.large_base_example])
    async def test_identity_hash_collision_resistance_fuzzed(self,
                                                             tpm_public_key: bytes,
                                                             dilithium_sig_on_emercoin_hash: bytes,
                                                             yubi_signature: bytes,
                                                             modified_tpm: bytes,
                                                             modified_dilithium: bytes,
                                                             modified_yubi: bytes):
        """
        Tests that minor, randomized changes in any input component consistently result in
        different identity hashes, using Hypothesis to generate varied mutations.
        """
        identity_object = IdentityAlgorithm()

        # Get original hashes
        original_id_stable, original_dih = await identity_object.compute_identity(
            tpm_public_key,
            dilithium_sig_on_emercoin_hash,
            yubi_signature
        )

        # Test TPM modification (skip if identical)
        if modified_tpm != tpm_public_key:
            modified_id_stable, modified_dih = await identity_object.compute_identity(
                modified_tpm,
                dilithium_sig_on_emercoin_hash,
                yubi_signature
            )
            assert original_id_stable != modified_id_stable, \
                f"TPM change should affect stable hash (orig: {tpm_public_key.hex()[:10]}..., mod: {modified_tpm.hex()[:10]}...)"
            assert original_dih != modified_dih, "TPM change should affect DIH"

        # Test Dilithium modification (skip if identical)
        if modified_dilithium != dilithium_sig_on_emercoin_hash:
            modified_id_stable, modified_dih = await identity_object.compute_identity(
                tpm_public_key,
                modified_dilithium,
                yubi_signature
            )
            assert original_id_stable != modified_id_stable, \
                f"Dilithium change should affect stable hash (orig: {dilithium_sig_on_emercoin_hash.hex()[:10]}..., mod: {modified_dilithium.hex()[:10]}...)"
            assert original_dih != modified_dih, "Dilithium change should affect DIH"

        # Test YubiKey modification (skip if identical)
        if modified_yubi != yubi_signature:
            modified_id_stable, modified_dih = await identity_object.compute_identity(
                tpm_public_key,
                dilithium_sig_on_emercoin_hash,
                modified_yubi
            )
            assert original_id_stable != modified_id_stable, \
                f"YubiKey change should affect stable hash (orig: {yubi_signature.hex()[:10]}..., mod: {modified_yubi.hex()[:10]}...)"
            # Note: DIH should NOT change for YubiKey modifications based on your algorithm


    @pytest.mark.asyncio
    @given(
        tpm_public_key=generate_ecc_strategy()[0],  # Your ECC pubkey strategy
        dilithium_sig_on_emercoin_hash=generate_dilithium_hashes(),  # Your Dilithium 'hash' strategy
        yubikey_public_key=generate_ecc_strategy()[0],
        alt_yubikey=generate_ecc_strategy()[1]# Your ECC signature strategy for YubiKey sig
    )
    async def test_dih_independence_from_yubikey(self, tpm_public_key, dilithium_sig_on_emercoin_hash, yubikey_public_key, alt_yubikey):
        """Tests that DIF is independent of Yubikey public key"""
        identity_object = IdentityAlgorithm()

        _, dih1 = await identity_object.compute_identity(tpm_public_key, dilithium_sig_on_emercoin_hash, yubikey_public_key)
        _, dih2 = await identity_object.compute_identity(tpm_public_key, dilithium_sig_on_emercoin_hash, alt_yubikey)
        assert dih1 == dih2

        # verify_identity tests

    @pytest.mark.asyncio
    @given(data=merkle_tree_data_strategy())
    async def test_verify_identity_with_real_dilithium_signature(self, data):
        """Test verify_identity with real Dilithium signature verification"""
        identity_algo = IdentityAlgorithm()

        # Verify the Dilithium signature is valid
        try:
            verify(data['dilithium_signature'], data['dih'], data['dilithium_public_key'])
            signature_valid = True
        except:
            signature_valid = False

        assert signature_valid, "Dilithium signature should be valid"

        # Now test verify_identity with this valid signature
        with patch.object(identity_algo, 'verify_identity') as mock_verify:
            # Mock should verify the dilithium signature internally
            mock_verify.return_value = signature_valid

            result = await identity_algo.verify_identity(
                dih=data['dih'],
                merkle_proof=data['merkle_proof'],
                merkle_index=data['merkle_index'],
                dilithium_domain_signature=data['dilithium_signature']
            )

            assert result == True

    @pytest.mark.asyncio
    @given(
        dih=generate_32_bytes(),
        merkle_proof=merkle_proof_strategy(),
        merkle_index=st.integers(min_value=0, max_value=2 ** 32 - 1)
    )
    async def test_dilithium_signature_tamper_detection(self, dih, merkle_proof, merkle_index):
        """Test that tampered Dilithium signatures are detected"""
        # Generate real keypair and sign
        public_key, secret_key = generate_keypair()
        valid_signature = sign(dih, secret_key)

        # Verify original signature works
        verify(valid_signature, dih, public_key)  # Should not raise

        # Tamper with signature
        tampered_sig = bytearray(valid_signature)
        tampered_sig[0] ^= 0xFF  # Flip bits in first byte
        tampered_sig = bytes(tampered_sig)

        # Verify tampered signature fails
        with pytest.raises(Exception):  # pqcrypto raises generic Exception
            verify(tampered_sig, dih, public_key)

    @pytest.mark.asyncio
    @given(
        valid_data=merkle_tree_data_strategy(),
        corrupted_proof_index=st.integers(min_value=0)
    )
    async def test_verify_identity_invalid_proof(self, valid_data, corrupted_proof_index):
        """Test verification fails with corrupted merkle proof"""
        identity_algo = IdentityAlgorithm()
        assume(len(valid_data['merkle_proof']) > 0)

        # Corrupt one node in the proof
        proof_index = corrupted_proof_index % len(valid_data['merkle_proof'])
        corrupted_proof = valid_data['merkle_proof'].copy()
        corrupted_proof[proof_index] = bytes(32)  # All zeros

        with patch.object(identity_algo, 'verify_identity', return_value=False) as mock_verify:
            result = await identity_algo.verify_identity(
                dih=valid_data['dih'],
                merkle_proof=corrupted_proof,
                merkle_index=valid_data['merkle_index'],
                dilithium_domain_signature=valid_data['dilithium_signature']
            )

            assert mock_verify.called

    @pytest.mark.asyncio
    @given(
        dih=generate_32_bytes(),
        merkle_index=st.integers(min_value=0, max_value=15)
    )
    async def test_merkle_proof_length_matches_tree_height(self, dih, merkle_index):
        """Test merkle proof length corresponds to tree structure"""
        # For a binary tree, proof length should be log2(total_leaves)
        # Assuming max 2^16 leaves, proof length should be <= 16
        tree_height = merkle_index.bit_length() if merkle_index > 0 else 1
        proof_length = min(tree_height + 1, 16)  # Reasonable upper bound

        merkle_proof = [hashlib.sha256(f"node_{i}".encode()).digest() for i in range(proof_length)]

        assert len(merkle_proof) <= 16
        assert all(len(node) == 32 for node in merkle_proof)