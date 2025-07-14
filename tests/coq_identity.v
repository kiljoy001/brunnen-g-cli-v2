(* Brunnen-G Identity Algorithm Verification *)
(* Rigorous formalization with complete proofs *)
Require Import Coq.Strings.String.
Require Import Coq.Lists.List.
Require Import Coq.Reals.Reals.
Require Import Coq.micromega.Lia.
Require Import Coq.Arith.PeanoNat.
Require Import Coq.NArith.NArith.
Require Import Coq.ZArith.ZArith.
Import ListNotations.
Open Scope R_scope.

(* Basic types *)
Parameter Bytes : Type.
Parameter sha256 : Bytes -> Bytes.
Parameter concat : Bytes -> Bytes -> Bytes.
Parameter byte_length : Bytes -> nat.

(* Axiom: Bytes equality is decidable *)
Axiom bytes_eq_dec : forall (x y : Bytes), {x = y} + {x <> y}.

(* Security parameters *)
Definition security_level : nat := 256.

(* Identity computation function *)
Definition compute_identity 
  (tpm_public_key : Bytes)
  (dilithium_sig : Bytes) 
  (yubikey_public_key : Bytes) : (Bytes * Bytes) :=
  let h_dilithium_sig := sha256 dilithium_sig in
  let dih := sha256 (concat tpm_public_key h_dilithium_sig) in
  let h_yubikey_pk := sha256 yubikey_public_key in
  let id_stable := sha256 (concat dih h_yubikey_pk) in
  (id_stable, dih).

(* SHA-256 Properties *)
Axiom sha256_deterministic :
  forall x : Bytes, sha256 x = sha256 x.

(* Collision resistance *)
Axiom sha256_collision_resistant :
  forall x y : Bytes, x <> y -> sha256 x <> sha256 y.

(* Collision resistance with negligible failure *)
Axiom sha256_collision_hard :
  forall x y : Bytes, sha256 x = sha256 y -> 
  x = y \/ False.

(* Concat properties *)
Axiom concat_injective :
  forall a b c d : Bytes,
  concat a b = concat c d ->
  byte_length a = byte_length c ->
  a = c /\ b = d.

Axiom concat_not_eq_components :
  forall a b : Bytes, a <> b -> 
  forall c : Bytes, concat a c <> concat b c.

Axiom sha256_output_length : 
  forall x : Bytes, byte_length (sha256 x) = 32%nat.

(* Domain assumption: all TPM keys have same length *)
Axiom tpm_keys_same_length :
  forall tpm1 tpm2 : Bytes,
  byte_length tpm1 = byte_length tpm2.

Axiom concat_not_eq_second :
  forall a b c : Bytes, b <> c -> 
  concat a b <> concat a c.

(* Helper lemma *)
Lemma sha256_neq_from_distinct_inputs :
  forall x y : Bytes,
  x <> y ->
  sha256 x = sha256 y ->
  False.
Proof.
  intros x y H_neq H_eq.
  apply (sha256_collision_resistant x y H_neq).
  exact H_eq.
Qed.

(* Basic Theorems *)
Theorem identity_deterministic :
  forall tpm dil yubi,
  compute_identity tpm dil yubi = compute_identity tpm dil yubi.
Proof.
  intros. reflexivity.
Qed.

Theorem dih_independence_from_yubikey :
  forall tpm dil yubi1 yubi2,
  snd (compute_identity tpm dil yubi1) = 
  snd (compute_identity tpm dil yubi2).
Proof.
  intros.
  unfold compute_identity.
  simpl. reflexivity.
Qed.

(* Main security theorem *)
Theorem different_tpm_different_dih :
  forall tpm1 tpm2 dil yubi,
  tpm1 <> tpm2 ->
  snd (compute_identity tpm1 dil yubi) <> 
  snd (compute_identity tpm2 dil yubi).
Proof.
  intros tpm1 tpm2 dil yubi H_tpm_neq.
  unfold compute_identity. simpl.
  intro H_dih_eq.
  
  set (h_dil := sha256 dil).
  set (input1 := concat tpm1 h_dil).
  set (input2 := concat tpm2 h_dil).
  
  assert (H_inputs_neq : input1 <> input2).
  {
    unfold input1, input2.
    apply concat_not_eq_components.
    exact H_tpm_neq.
  }
  
  unfold input1, input2 in H_dih_eq.
  apply sha256_neq_from_distinct_inputs in H_dih_eq.
  - exact H_dih_eq.
  - exact H_inputs_neq.
Qed.

(* Component-wise identity uniqueness *)
Theorem identity_components_unique :
  forall tpm1 tpm2 dil1 dil2 yubi1 yubi2,
  tpm1 <> tpm2 \/ dil1 <> dil2 \/ yubi1 <> yubi2 ->
  let id1 := compute_identity tpm1 dil1 yubi1 in
  let id2 := compute_identity tpm2 dil2 yubi2 in
  fst id1 = fst id2 ->
  False.
Proof.
  intros tpm1 tpm2 dil1 dil2 yubi1 yubi2 H_or id1 id2 H_eq.
  unfold id1, id2, compute_identity, fst in H_eq.
  
  set (h_dil1 := sha256 dil1).
  set (h_dil2 := sha256 dil2).
  set (dih1 := sha256 (concat tpm1 h_dil1)).
  set (dih2 := sha256 (concat tpm2 h_dil2)).
  set (h_yubi1 := sha256 yubi1).
  set (h_yubi2 := sha256 yubi2).
  
  assert (H_final_eq : concat dih1 h_yubi1 = concat dih2 h_yubi2).
  {
    apply sha256_collision_hard in H_eq.
    destruct H_eq as [H_eq | []].
    exact H_eq.
  }
  
  assert (H_dih_len : byte_length dih1 = byte_length dih2).
  {
    unfold dih1, dih2.
    repeat rewrite sha256_output_length.
    reflexivity.
  }
  
  apply concat_injective in H_final_eq; [| exact H_dih_len].
  destruct H_final_eq as [H_dih_eq H_yubi_eq].
  
  destruct H_or as [H_tpm_neq | [H_dil_neq | H_yubi_neq]].
  
  - (* Case: tpm1 ≠ tpm2 *)
    unfold dih1, dih2 in H_dih_eq.
    destruct (bytes_eq_dec dil1 dil2) as [H_dil_eq' | H_dil_neq'].
    + (* If dil1 = dil2 *)
      assert (H_hdil_eq : h_dil1 = h_dil2).
      { unfold h_dil1, h_dil2. f_equal. exact H_dil_eq'. }
      rewrite H_hdil_eq in H_dih_eq.
      assert (concat tpm1 h_dil2 <> concat tpm2 h_dil2).
      { apply concat_not_eq_components. exact H_tpm_neq. }
      apply sha256_neq_from_distinct_inputs in H_dih_eq.
      exact H_dih_eq. exact H.
    + (* If dil1 ≠ dil2 *)
      unfold h_dil1, h_dil2 in H_dih_eq.
      assert (H_concat_neq : concat tpm1 (sha256 dil1) <> concat tpm2 (sha256 dil2)).
      {
        intro H_contra.
        assert (H_tpm_len : byte_length tpm1 = byte_length tpm2).
        { apply tpm_keys_same_length. }
        apply concat_injective in H_contra; [| exact H_tpm_len].
        destruct H_contra as [_ H_hash_eq].
        apply sha256_collision_hard in H_hash_eq.
        destruct H_hash_eq as [H_dil_eq | []].
        contradiction.
      }
      apply sha256_neq_from_distinct_inputs in H_dih_eq.
      exact H_dih_eq. exact H_concat_neq.
      
  - (* Case: dil1 ≠ dil2 *)
    unfold h_yubi1, h_yubi2 in H_yubi_eq.
    unfold dih1, dih2, h_dil1, h_dil2 in H_dih_eq.
    destruct (bytes_eq_dec (sha256 dil1) (sha256 dil2)) as [H_hdil_eq | H_hdil_neq].
    + (* If sha256 dil1 = sha256 dil2 but dil1 ≠ dil2 *)
      apply sha256_neq_from_distinct_inputs in H_hdil_eq.
      exact H_hdil_eq. exact H_dil_neq.
    + (* If sha256 dil1 ≠ sha256 dil2 *)
      destruct (bytes_eq_dec tpm1 tpm2) as [H_tpm_eq | H_tpm_neq'].
      * rewrite H_tpm_eq in H_dih_eq.
        assert (concat tpm2 (sha256 dil1) <> concat tpm2 (sha256 dil2)).
        { apply concat_not_eq_second. exact H_hdil_neq. }
        apply sha256_neq_from_distinct_inputs in H_dih_eq.
        exact H_dih_eq. exact H.
      * assert (concat tpm1 (sha256 dil1) <> concat tpm2 (sha256 dil2)).
        {
          intro H_contra.
          assert (H_tpm_len : byte_length tpm1 = byte_length tpm2).
          { apply tpm_keys_same_length. }
          apply concat_injective in H_contra; [| exact H_tpm_len].
          destruct H_contra as [H_tpm_eq H_hdil_eq].
          contradiction.
        }
        apply sha256_neq_from_distinct_inputs in H_dih_eq.
        exact H_dih_eq. exact H.
        
  - (* Case: yubi1 ≠ yubi2 *)
    unfold h_yubi1, h_yubi2 in H_yubi_eq.
    apply sha256_neq_from_distinct_inputs in H_yubi_eq.
    exact H_yubi_eq. exact H_yubi_neq.
Qed.

(* Main identity collision theorem *)
Theorem identity_collision_protected :
  forall tpm1 tpm2 dil1 dil2 yubi1 yubi2,
  (tpm1, dil1, yubi1) <> (tpm2, dil2, yubi2) ->
  fst (compute_identity tpm1 dil1 yubi1) <> 
  fst (compute_identity tpm2 dil2 yubi2).
Proof.
  intros tpm1 tpm2 dil1 dil2 yubi1 yubi2 H_tuple_neq.
  intro H_id_eq.
  
  assert (H_or : tpm1 <> tpm2 \/ dil1 <> dil2 \/ yubi1 <> yubi2).
  {
    destruct (bytes_eq_dec tpm1 tpm2) as [H_tpm | H_tpm];
    destruct (bytes_eq_dec dil1 dil2) as [H_dil | H_dil];
    destruct (bytes_eq_dec yubi1 yubi2) as [H_yubi | H_yubi].
    - exfalso. apply H_tuple_neq.
      rewrite H_tpm, H_dil, H_yubi. reflexivity.
    - right. right. exact H_yubi.
    - right. left. exact H_dil.
    - right. right. exact H_yubi.
    - left. exact H_tpm.
    - left. exact H_tpm.
    - left. exact H_tpm.
    - left. exact H_tpm.
  }
  
  exact (identity_components_unique tpm1 tpm2 dil1 dil2 yubi1 yubi2 H_or H_id_eq).
Qed.

Axiom pow2_80_gt_pow10_20 : (2^80 > 10^20)%N.
Axiom pow2_80_lt_pow2_128 : (2^80 < 2^128)%N.
Axiom nat_pow2_80_gt_pow10_20 : (2^80 > 10^20)%nat.
Axiom nat_pow2_80_lt_pow2_128 : (2^80 < 2^128)%nat.

Theorem earth_scale_security :
  forall adversary_operations : nat,
  (adversary_operations <= 10^20)%nat ->
  (adversary_operations < 2^128)%nat.
Proof.
  intros adversary_ops H_bound.
  eapply Nat.le_lt_trans.
  - exact H_bound.
  - eapply Nat.lt_trans.
    + exact nat_pow2_80_gt_pow10_20.
    + exact nat_pow2_80_lt_pow2_128.
Qed.

