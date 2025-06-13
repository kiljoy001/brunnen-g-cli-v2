import pytest
from hypothesis import given, settings, HealthCheck, strategies as st
from .test_utilities import (generate_emercoin_signature, generate_yubikey_signature, generate_usernames,
                             generate_32_bytes, generate_ecc_strategy, generate_dilithium_hashes, mockdb_row_hasher,
                             minor_byte_string_changes)
from src.identity_algorithim import IdentityAlgorithm


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



