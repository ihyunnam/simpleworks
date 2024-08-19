mod schnorr_signature;

use ark_ec::ProjectiveCurve;
use ark_ff::Field;
use schnorr_signature::schnorr::*;
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
    let schnorr_param: Parameters<C> = Schnorr::<C>::setup(rng).unwrap();
    
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

    // LOG CREATES SECOND ROUND 2
    let second_round_log: SecondRound<Vec<u8>> = first_round_log
        .finalize(log_sk, msg2, pubnonces)
        .expect(&format!("failed to finalize first round for log"));

    let partial_signature_log: PartialSignature = second_round_log.our_signature();
    
    let second_rounds = vec![second_round_user, second_round_log];
    let partial_signatures = vec![partial_signature_user, partial_signature_log];
    
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

    // All signers should output the same aggregated signature.
    // for sig in signatures {
    //     assert_eq!(
    //         sig, last_sig,
    //         "some signers created different aggregated signatures"
    //     );
    // }

    // and of course, the sig should be verifiable as a standard schnorr signature.
    let aggregated_pubkey: PublicKey<C> = key_agg_ctx.aggregated_pubkey();

    // println!("msg3 {:?}", msg3);    // CORRECT
    let schnorr_verified = Schnorr::<C>::verify(&schnorr_param, &aggregated_pubkey, &msg3, &last_sig).unwrap();
    println!("SCHNORR VERIFIED OUTSIDE CIRCUIT {:?}", schnorr_verified);
}