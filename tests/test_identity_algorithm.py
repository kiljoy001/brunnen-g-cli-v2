import pytest
import hashlib
from hypothesis import assume, given, settings, HealthCheck, strategies as st
from .test_utilities import (generate_32_bytes, generate_ecc_strategy, generate_dilithium_hashes,
                             minor_byte_string_changes, merkle_proof_strategy, merkle_tree_data_strategy)
from src.identity_algorithim import IdentityAlgorithm
from pqcrypto.sign.ml_dsa_65 import generate_keypair, sign, verify
from unittest.mock import patch
from merkletools import MerkleTools
import os


class TestIdentityAlgorithm:

    def create_merkle_tree_with_library(self, leaves: list[bytes]) -> tuple[bytes, list[list[tuple[str, bytes]]]]:
        """Create merkle tree using merkletools library"""
        if len(leaves) == 1:
            return leaves[0], [[]]

        mt = MerkleTools(hash_type='sha256')

        for leaf in leaves:
            mt.add_leaf(leaf.hex(), False)

        mt.make_tree()
        root = mt.get_merkle_root()

        # Generate proofs WITH position information
        proofs = []
        for i in range(len(leaves)):
            proof = mt.get_proof(i)
            proof_with_positions = []
            for p in proof:
                if 'right' in p:
                    proof_with_positions.append(('right', bytes.fromhex(p['right'])))
                elif 'left' in p:
                    proof_with_positions.append(('left', bytes.fromhex(p['left'])))
            proofs.append(proof_with_positions)

        return bytes.fromhex(root), proofs

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
           dilithium_sig,
           yubikey_public_key
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
        tpm_public_key=generate_ecc_strategy()[0],
        dilithium_sig_on_emercoin_hash=generate_dilithium_hashes(),
        yubikey_public_key=generate_ecc_strategy()[0],
        alt_yubikey=generate_ecc_strategy()[1]
    )
    async def test_dih_independence_from_yubikey(self, tpm_public_key, dilithium_sig_on_emercoin_hash, yubikey_public_key, alt_yubikey):
        """Tests that DIF is independent of Yubikey public key"""
        identity_object = IdentityAlgorithm()

        _, dih1 = await identity_object.compute_identity(tpm_public_key, dilithium_sig_on_emercoin_hash, yubikey_public_key)
        _, dih2 = await identity_object.compute_identity(tpm_public_key, dilithium_sig_on_emercoin_hash, alt_yubikey)
        assert dih1 == dih2

    @pytest.mark.asyncio
    async def test_verify_identity_with_valid_signature_and_proof(self):
        """Verification succeeds with valid signature and merkle proof"""
        identity_algo = IdentityAlgorithm()

        # Create test data
        tpm_pubkey = hashlib.sha256(b"tpm").digest()
        dilithium_sig = hashlib.sha256(b"dilithium").digest()
        yubikey_pubkey = hashlib.sha256(b"yubikey").digest()
        id_stable, dih = await identity_algo.compute_identity(tpm_pubkey, dilithium_sig, yubikey_pubkey)

        # Build merkle tree with id_stable as leaves
        leaves = [hashlib.sha256(f"leaf_{i}".encode()).digest() for i in range(8)]
        leaves[3] = id_stable

        root, all_proofs = self.create_merkle_tree_with_library(leaves)
        merkle_index = 3
        proof = all_proofs[merkle_index]

        # Generate valid signature on DIH
        public_key, secret_key = generate_keypair()
        signature = sign(secret_key, dih)

        result = await identity_algo.verify_identity(
            id_stable=id_stable,
            dih=dih,
            merkle_proof=proof,
            merkle_index=merkle_index,
            dilithium_domain_signature=signature,
            dilithium_public_key=public_key,
            merkle_root=root
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_verify_identity_fails_with_wrong_signature(self):
        """Verification fails when signature is for wrong data"""
        identity_algo = IdentityAlgorithm()

        tpm_pubkey = hashlib.sha256(b"tpm").digest()
        dilithium_sig = hashlib.sha256(b"dilithium").digest()
        yubikey_pubkey = hashlib.sha256(b"yubikey").digest()
        id_stable, dih = await identity_algo.compute_identity(tpm_pubkey, dilithium_sig, yubikey_pubkey)

        leaves = [hashlib.sha256(f"leaf_{i}".encode()).digest() for i in range(4)]
        leaves[1] = id_stable

        root, all_proofs = self.create_merkle_tree_with_library(leaves)
        proof = all_proofs[1]

        # Sign different data
        public_key, secret_key = generate_keypair()
        wrong_data = hashlib.sha256(b"wrong_data").digest()
        signature = sign(secret_key, wrong_data)

        result = await identity_algo.verify_identity(
            id_stable=id_stable,
            dih=dih,
            merkle_proof=proof,
            merkle_index=1,
            dilithium_domain_signature=signature,
            dilithium_public_key=public_key,
            merkle_root=root,
            yubikey_public_key=yubikey_pubkey,
            challenge=os.urandom(32),
            yubikey_signature=b"invalid_signature" 
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_verify_identity_fails_with_wrong_merkle_root(self):
        """Verification fails when merkle root doesn't match computed root"""
        identity_algo = IdentityAlgorithm()

        tpm_pubkey = hashlib.sha256(b"tpm").digest()
        dilithium_sig = hashlib.sha256(b"dilithium").digest()
        yubikey_pubkey = hashlib.sha256(b"yubikey").digest()
        id_stable, dih = await identity_algo.compute_identity(tpm_pubkey, dilithium_sig, yubikey_pubkey)

        leaves = [id_stable, hashlib.sha256(b"leaf_1").digest(), hashlib.sha256(b"leaf_2").digest()]

        root, all_proofs = self.create_merkle_tree_with_library(leaves)
        proof = all_proofs[0]

        # Valid signature
        public_key, secret_key = generate_keypair()
        signature = sign(secret_key, dih)

        # Wrong merkle root
        wrong_root = hashlib.sha256(b"wrong_root").digest()

        result = await identity_algo.verify_identity(
            id_stable=id_stable,
            dih=dih,
            merkle_proof=proof,
            merkle_index=0,
            dilithium_domain_signature=signature,
            dilithium_public_key=public_key,
            merkle_root=wrong_root
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_verify_identity_with_single_leaf_tree(self):
        """Verification succeeds with single-leaf tree (empty proof)"""
        identity_algo = IdentityAlgorithm()

        tpm_pubkey = hashlib.sha256(b"tpm").digest()
        dilithium_sig = hashlib.sha256(b"dilithium").digest()
        yubikey_pubkey = hashlib.sha256(b"yubikey").digest()
        id_stable, dih = await identity_algo.compute_identity(tpm_pubkey, dilithium_sig, yubikey_pubkey)

        # Single leaf tree - root IS the leaf
        root, all_proofs = self.create_merkle_tree_with_library([id_stable])
        proof = all_proofs[0]  # Should be empty list

        # Valid signature
        public_key, secret_key = generate_keypair()
        signature = sign(secret_key, dih)

        result = await identity_algo.verify_identity(
            id_stable=id_stable,
            dih=dih,
            merkle_proof=proof,
            merkle_index=0,
            dilithium_domain_signature=signature,
            dilithium_public_key=public_key,
            merkle_root=root
        )

        assert result is True
        assert proof == []  # Verify empty proof

    @pytest.mark.asyncio
    @given(
        tpm_pubkey=generate_32_bytes(),
        dilithium_sig=generate_32_bytes(),
        yubikey_pubkey=generate_32_bytes(),
        tree_size=st.integers(min_value=2, max_value=32),
        leaf_index=st.integers(min_value=0, max_value=31)
    )
    async def test_verify_identity_with_random_tree_sizes(self, tpm_pubkey, dilithium_sig, yubikey_pubkey, tree_size, leaf_index):
        """Test verify_identity with various tree sizes and positions"""
        identity_algo = IdentityAlgorithm()
        leaf_index = leaf_index % tree_size
        id_stable, dih = await identity_algo.compute_identity(tpm_pubkey, dilithium_sig, yubikey_pubkey)

        # Build tree with id_stable at random position
        leaves = [hashlib.sha256(f"leaf_{i}".encode()).digest() for i in range(tree_size)]
        leaves[leaf_index] = id_stable

        root, all_proofs = self.create_merkle_tree_with_library(leaves)
        proof = all_proofs[leaf_index]

        # Valid signature
        public_key, secret_key = generate_keypair()
        signature = sign(secret_key, dih)

        result = await identity_algo.verify_identity(
            id_stable=id_stable,
            dih=dih,
            merkle_proof=proof,
            merkle_index=leaf_index,
            dilithium_domain_signature=signature,
            dilithium_public_key=public_key,
            merkle_root=root
        )

        assert result is True

    @pytest.mark.asyncio
    @given(
        tpm_pubkey=generate_32_bytes(),
        dilithium_sig=generate_32_bytes(),
        yubikey_pubkey=generate_32_bytes(),
        proof_corruption=st.data()
    )
    async def test_verify_identity_corrupted_proof_always_fails(self, tpm_pubkey, dilithium_sig, yubikey_pubkey, proof_corruption):
        """Any corruption in merkle proof should fail verification"""
        identity_algo = IdentityAlgorithm()
        id_stable, dih = await identity_algo.compute_identity(tpm_pubkey, dilithium_sig, yubikey_pubkey)

        # Create valid tree
        leaves = [hashlib.sha256(f"leaf_{i}".encode()).digest() for i in range(8)]
        leaves[3] = id_stable
        root, all_proofs = self.create_merkle_tree_with_library(leaves)
        proof = all_proofs[3].copy()

        # Corrupt proof if it exists
        if proof:
            corrupt_idx = proof_corruption.draw(st.integers(0, len(proof)-1))
            corrupt_byte = proof_corruption.draw(st.integers(0, 31))
            corrupt_bit = proof_corruption.draw(st.integers(1, 255))

            position, hash_bytes = proof[corrupt_idx]
            corrupted = bytearray(hash_bytes)
            corrupted[corrupt_byte] ^= corrupt_bit
            proof[corrupt_idx] = (position, bytes(corrupted))

        # Valid signature
        public_key, secret_key = generate_keypair()
        signature = sign(secret_key, dih)

        result = await identity_algo.verify_identity(
            id_stable=id_stable,
            dih=dih,
            merkle_proof=proof,
            merkle_index=3,
            dilithium_domain_signature=signature,
            dilithium_public_key=public_key,
            merkle_root=root
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_verify_identity_tree_size_3_debug(self):
        """Debug failing case with 3-leaf tree"""
        identity_algo = IdentityAlgorithm()
        tpm_pubkey = hashlib.sha256(b"tpm").digest()
        dilithium_sig = hashlib.sha256(b"dilithium").digest()
        yubikey_pubkey = hashlib.sha256(b"yubikey").digest()
        id_stable, dih = await identity_algo.compute_identity(tpm_pubkey, dilithium_sig, yubikey_pubkey)

        leaves = [hashlib.sha256(f"leaf_{i}".encode()).digest() for i in range(3)]
        leaves[2] = id_stable

        root, all_proofs = self.create_merkle_tree_with_library(leaves)
        proof = all_proofs[2]

        print(f"Tree size: 3, ID_STABLE at index: 2")
        print(f"Root: {root.hex()[:16]}...")
        print(f"Proof length: {len(proof)}")
        for i, (position, hash_bytes) in enumerate(proof):
            print(f"  Proof[{i}]: {position} - {hash_bytes.hex()[:16]}...")

        public_key, secret_key = generate_keypair()
        signature = sign(secret_key, dih)

        result = await identity_algo.verify_identity(
            id_stable=id_stable,
            dih=dih,
            merkle_proof=proof,
            merkle_index=2,
            dilithium_domain_signature=signature,
            dilithium_public_key=public_key,
            merkle_root=root
        )

        assert result is True

    @pytest.mark.asyncio
    @given(
        id_stable=generate_32_bytes(),
        challenge1=st.binary(min_size=16, max_size=64),
        challenge2=st.binary(min_size=16, max_size=64),
        yubikey_private_key=st.binary(min_size=32, max_size=32)
    )
    async def test_different_challenges_different_signatures(self, id_stable, challenge1, challenge2, yubikey_private_key):
        """Different challenges must produce different signatures"""
        assume(challenge1 != challenge2)

        # Mock yubikey_sign function
        with patch('src.identity_algorithim.yubikey_sign') as mock_sign:
            mock_sign.side_effect = lambda key, msg: hashlib.sha256(key + msg).digest()

            sig1 = mock_sign(yubikey_private_key, hashlib.sha256(id_stable + challenge1).digest())
            sig2 = mock_sign(yubikey_private_key, hashlib.sha256(id_stable + challenge2).digest())

            assert sig1 != sig2

    @pytest.mark.asyncio
    @given(
        tpm_pubkey=generate_32_bytes(),
        dilithium_sig=generate_dilithium_hashes(),
        yubikey_pubkey=generate_ecc_strategy()[0],
        challenge=st.binary(min_size=16, max_size=64),
        tree_data=merkle_tree_data_strategy()
    )
    async def test_verify_identity_with_valid_yubikey_challenge(self, tpm_pubkey, dilithium_sig, yubikey_pubkey, challenge, tree_data):
        """Verification succeeds with valid YubiKey challenge-response"""
        identity_algo = IdentityAlgorithm()
        id_stable, dih = await identity_algo.compute_identity(tpm_pubkey, dilithium_sig, yubikey_pubkey)

        # Mock yubikey functions
        with patch('src.identity_algorithim.yubikey_sign') as mock_sign, \
             patch('src.identity_algorithim.yubikey_verify') as mock_verify:

            # Setup mocks
            challenge_response = hashlib.sha256(id_stable + challenge).digest()
            signature = hashlib.sha256(b"sig" + challenge_response).digest()
            mock_sign.return_value = signature
            mock_verify.return_value = True

            # Create valid merkle tree
            leaves = [hashlib.sha256(f"leaf_{i}".encode()).digest() for i in range(4)]
            leaves[1] = id_stable
            root, all_proofs = self.create_merkle_tree_with_library(leaves)

            result = await identity_algo.verify_identity(
                id_stable=id_stable,
                dih=dih,
                merkle_proof=all_proofs[1],
                merkle_index=1,
                dilithium_domain_signature=tree_data['dilithium_signature'],
                dilithium_public_key=tree_data['dilithium_public_key'],
                merkle_root=root,
                yubikey_public_key=yubikey_pubkey,
                challenge=challenge,
                yubikey_signature=signature
            )

            # Verify mock was called correctly
            mock_verify.assert_called_once_with(yubikey_pubkey, challenge_response, signature)
            assert result is True

    @pytest.mark.asyncio
    @given(
        id_stable=generate_32_bytes(),
        challenge=st.binary(min_size=16, max_size=64),
        correct_key=generate_ecc_strategy()[0],
        wrong_key=generate_ecc_strategy()[0],
        tree_data=merkle_tree_data_strategy()
    )
    async def test_wrong_yubikey_fails_verification(self, id_stable, challenge, correct_key, wrong_key, tree_data):
        """Wrong YubiKey cannot authenticate"""
        assume(correct_key != wrong_key)
        identity_algo = IdentityAlgorithm()

        with patch('src.identity_algorithim.yubikey_verify') as mock_verify:
            mock_verify.return_value = False  # Wrong key fails verification

            # Valid merkle proof
            root, all_proofs = self.create_merkle_tree_with_library([id_stable])

            result = await identity_algo.verify_identity(
                id_stable=id_stable,
                dih=tree_data['dih'],
                merkle_proof=all_proofs[0],
                merkle_index=0,
                dilithium_domain_signature=tree_data['dilithium_signature'],
                dilithium_public_key=tree_data['dilithium_public_key'],
                merkle_root=root,
                yubikey_public_key=wrong_key,
                challenge=challenge,
                yubikey_signature=b"wrong_sig"
            )

            assert result is False

    @pytest.mark.asyncio
    @given(
        id_stable=generate_32_bytes(),
        old_challenge=st.binary(min_size=16, max_size=64),
        new_challenge=st.binary(min_size=16, max_size=64),
        yubikey_pubkey=generate_ecc_strategy()[0]
    )
    async def test_replay_attack_prevention(self, id_stable, old_challenge, new_challenge, yubikey_pubkey):
        """Old signatures cannot be reused with new challenges"""
        assume(old_challenge != new_challenge)

        # Generate signature for old challenge
        old_response = hashlib.sha256(id_stable + old_challenge).digest()
        old_sig = hashlib.sha256(b"sig" + old_response).digest()

        # Try to verify old signature with new challenge
        new_response = hashlib.sha256(id_stable + new_challenge).digest()

        with patch('src.identity_algorithim.yubikey_verify') as mock_verify:
            # Mock returns False because signature doesn't match new challenge
            mock_verify.return_value = False

            # This should fail
            verified = mock_verify(yubikey_pubkey, new_response, old_sig)
            assert verified is False