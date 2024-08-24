use ark_r1cs_std::{eq::EqGadget, R1CSVar};
// use ark_crypto_primitives::signature::SigVerifyGadget;
use ark_r1cs_std::{alloc::{AllocVar, AllocationMode}, prelude::Boolean, uint8::UInt8};
use ark_ff::PrimeField;
mod schnorr_signature;
// use crate::SigVerifyGadget;
use schnorr_signature::
    {parameters_var::ParametersVar, public_key_var::PublicKeyVar, schnorr::{FirstRound, KeyAggContext, Parameters, PartialSignature, PubNonce, PublicKey, Schnorr, SecondRound, Signature}, schnorr_signature_verify_gadget::{SchnorrSignatureVerifyGadget, SigVerifyGadget}, signature_var::SignatureVar
};

use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_ff::Field;
// use schnorr_signature::schnorr::*;
use ark_relations::r1cs::{ConstraintSystem, ConstraintLayer, SynthesisError, ConstraintSynthesizer, ConstraintSystemRef, SynthesisMode, TracingMode::{All, OnlyConstraints}};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub};   // Fq2: finite field, JubJub: curve group
use ark_crypto_primitives::{
    commitment::{blake2s::{constraints::{CommGadget, RandomnessVar as CommitRandomnessVar}, Commitment},
        CommitmentGadget, CommitmentScheme},
    crh::poseidon::CRH,
    encryption::{elgamal::{constraints::{ElGamalEncGadget, OutputVar as ElgamalCiphertextVar, ParametersVar as ElgamalParametersVar, PlaintextVar, PublicKeyVar as ElgamalPublicKeyVar, RandomnessVar as ElgamalRandomnessVar}, Ciphertext, ElGamal, Parameters as EncParams, PublicKey as EncPubKey, Randomness as EncRand},
        AsymmetricEncryptionGadget, AsymmetricEncryptionScheme},
    prf::{blake2s::{constraints::{Blake2sGadget, OutputVar as PrfOutputVar}, Blake2s}, PRFGadget, PRF}, SignatureScheme,
    // signature::{SignatureScheme, constraints::SigVerifyGadget,
    //     schnorr::{self, constraints::{ParametersVar, PublicKeyVar}, Parameters, PublicKey, Schnorr, SecretKey, Signature}}
};
use rand::rngs::OsRng;

fn main() {
    type C = JubJub; 
    type GG = EdwardsVar;
    type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;
    // type RealInsertCircuit = InsertCircuit<C, GG>;
    type MyEnc = ElGamal<JubJub>;

    let rng = &mut OsRng;
    let orig_msg = "hello!";
    let msg: Vec<u8> = orig_msg.as_bytes().to_vec();

    // Print the random vector
    println!("Random msg in Vec<u8>: {:?}", msg);

    let msg2 = msg.clone();
    let msg3 = msg.clone();
    
    /* AGGREGATE SCHNORR ATTEMPT */

    let schnorr_param = Parameters::<C> {
        generator: C::prime_subgroup_generator().into(),
        salt: Some([0u8;32]),
    };
    
    // log and user both only need one pair
    // let (schnorr_pk, schnorr_sk) = Schnorr::<C>::keygen(&schnorr_param, rng).unwrap();
    let (user_pk, user_sk) = Schnorr::<C>::keygen(&schnorr_param, rng).unwrap();
    let (log_pk, log_sk)= Schnorr::<C>::keygen(&schnorr_param, rng).unwrap();
    let pubkeys = vec![user_pk, log_pk];
    println!("PUBKEYS {:?}", pubkeys);
    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
    // println!("KEY AGG CTX {:?}", key_agg_ctx);
    // NOTE: ALWAYS USER FIRST, LOG SECOND IN KEY AGGREGATION

    // let msg = already done

    // USER RUNS ROUND 1
    let first_round_user = FirstRound::new(
        key_agg_ctx.clone(),
        [0xAC; 32], // Replace with your nonce or similar value
        0,          // Use 0 for the index if it's just one signer
        // SecNonceSpices::new().with_seckey(user_sk).with_message(&msg),
    ).expect("failed to construct FirstRound machine");

    // USER EXTRACTS ITS PUBNONCE   // TODO: maybe add a nice wrapper function for these repeated things for user and log
    let pubnonce_user: PubNonce = first_round_user.our_public_nonce();
    // println!("USER PUBLIC NONCE COMPUTED FROM SECRET NONCE {:?}", pubnonce_user);
    // println!("user secnonce {:?}", first_round_user.secnonce);

    // LOG RUNS ROUND 1
    let first_round_log = FirstRound::new(
        key_agg_ctx.clone(),
        [0xAC; 32], // Replace with your nonce or similar value
        1,          // Use 0 for the index if it's just one signer
        // SecNonceSpices::new().with_seckey(log_sk).with_message(&msg),
    ).expect("failed to construct FirstRound machine");

    // LOG EXTRACTS ITS PUBNONCE
    let pubnonce_log: PubNonce = first_round_log.our_public_nonce();
    // println!("LOG PUBLIC NONCE COMPUTED FROM SECRET NONCE {:?}", pubnonce_log);

    // TODO: DISTRIBUTE THE PUBLIC NONCES (LOG GETS USER'S AND VICE VERSA)
    let pubnonces: Vec<PubNonce> = vec![pubnonce_user, pubnonce_log]; // ORDER CORRECT (didn't check explicitly)

    // println!("PUBNONCES - CHECK ORDER {:?}", pubnonces);

    // SKIPPED A FEW SAFETY CHECKS AND COMMUNICATION CHECK

    // ROUND 2: signing

    // USER CREATES SECOND ROUND 2
    let second_round_user: SecondRound<Vec<u8>> = first_round_user
        .finalize(user_sk, msg, pubnonces.clone())
        .expect(&format!("failed to finalize first round for user"));

    let partial_signature_user: PartialSignature = second_round_user.our_signature();

    // println!("USER PARTIAL SIGNATURE RETRIEVED {:?}", partial_signature_user);   // CORRECT
    // LOG CREATES SECOND ROUND 2
    let second_round_log: SecondRound<Vec<u8>> = first_round_log
        .finalize(log_sk, msg2, pubnonces)
        .expect(&format!("failed to finalize first round for log"));

    let partial_signature_log: PartialSignature = second_round_log.our_signature();
    
    let second_rounds = vec![second_round_user, second_round_log];
    let partial_signatures = vec![partial_signature_user, partial_signature_log];
    // println!("LOG PARTIAL SIGNATURE RETRIEVED {:?}", partial_signature_log);     // CORRECT
    
    // MESSAGE DEPENDENT BECAUSE IT'S THE SIGNATURE - THIS IS OK
    // FINALIZATION: signatures can now be aggregated.
    let mut signatures: Vec<Signature<C>> = second_rounds
        .into_iter()
        .enumerate()
        .map(|(i, round)| {
            round
                .finalize(partial_signatures.clone())
                .expect(&format!("failed to finalize second round for signer {}", i))
        })
        .collect();

    let last_sig = signatures.pop().unwrap();
    // println!("VERIFIER CHALLENGE OUTSIDE CIRCUIT {:?}", last_sig.verifier_challenge);

    // println!("PROVER RESPONSE {:?}", last_sig.prover_response);
    // println!("VERIFIER CHALLENGE {:?}", last_sig.verifier_challenge);

    // All signers should output the same aggregated signature.     // CORRECT
    // for sig in signatures {
    //     println!("PROVER RESPONSE {:?}", sig.prover_response);
    //     println!("VERIFIER CHALLENGE {:?}", sig.verifier_challenge);
    // }

    // and of course, the sig should be verifiable as a standard schnorr signature.
    let aggregated_pubkey: PublicKey<C> = key_agg_ctx.aggregated_pubkey();

    // println!("msg3 {:?}", msg3);    // CORRECT
    let orig_msg = "wrong msg";
    let fake_msg: Vec<u8> = orig_msg.as_bytes().to_vec();       // REJECTED AS REQUIRED

    let fake_sig = Signature::<EdwardsProjective> {
        prover_response: <EdwardsProjective as ProjectiveCurve>::ScalarField::from_be_bytes_mod_order(&[3;32]),
        verifier_challenge: [4; 32],
    };             // REJECTED AS REQUIRED

    let fake_agg_pubkey = PublicKey::<EdwardsProjective>::default();        // REJECTED AS REQUIRED
    let schnorr_verified = Schnorr::<C>::verify(&schnorr_param, &aggregated_pubkey, &msg3, &last_sig).unwrap();
    println!("SCHNORR VERIFIED OUTSIDE CIRCUIT {:?}", schnorr_verified);

    let cs: ConstraintSystemRef<ConstraintF<C>> = ConstraintSystem::new_ref();
    let reconstructed_msg_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(
        cs.clone(),
        &msg3
    ).unwrap();
    
    let schnorr_param = ParametersVar::<C,GG>::new_variable(
        cs.clone(),
        || Ok(schnorr_param),
        AllocationMode::Constant,
    ).unwrap();
    
    let schnorr_sig = SignatureVar::<C,GG>::new_variable(
        cs.clone(),
        || Ok(last_sig),
        AllocationMode::Witness,
    ).unwrap();

    let default_pubkey = PublicKey::<C>::default();
    let schnorr_apk = PublicKeyVar::<C,GG>::new_variable(
        cs.clone(),
        || Ok(aggregated_pubkey),
        AllocationMode::Witness,
    ).unwrap();

    let schnorr_verified = SchnorrSignatureVerifyGadget::<C,GG>::verify(cs.clone(), &schnorr_param, &schnorr_apk, &reconstructed_msg_wtns, &schnorr_sig).unwrap();
    println!("schnorr verified inside circuit {:?}", schnorr_verified.value());
    schnorr_verified.is_eq(&Boolean::TRUE);
}