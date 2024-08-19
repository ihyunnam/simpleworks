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
    
    /* AGGREGATE SCHNORR ATTEMPT */
    let schnorr_param: Parameters<C> = Schnorr::<C>::setup(rng).unwrap();
    
    // log and user both only need one pair
    // let (schnorr_pk, schnorr_sk) = Schnorr::<C>::keygen(&schnorr_param, rng).unwrap();
    let (user_pk, user_sk) = Schnorr::<C>::keygen(&schnorr_param, rng).unwrap();
    let (log_pk, log_sk)= Schnorr::<C>::keygen(&schnorr_param, rng).unwrap();
    let pubkeys = vec![user_pk, log_pk];
    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
    
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

    // LOG RUNS ROUND 1
    let first_round_log = FirstRound::new(
        key_agg_ctx.clone(),
        [0xAC; 32], // Replace with your nonce or similar value
        1,          // Use 0 for the index if it's just one signer
        // SecNonceSpices::new().with_seckey(log_sk).with_message(&msg),
    ).expect("failed to construct FirstRound machine");

    // LOG EXTRACTS ITS PUBNONCE
    let pubnonce_log: PubNonce = first_round_log.our_public_nonce();

    let pubnonces: Vec<PubNonce> = vec![pubnonce_user, pubnonce_log];

    // SKIPPED A FEW SAFETY CHECKS AND COMMUNICATION CHECK
    // let first_rounds = vec![first_round_log, first_round_user];

    // TODO: DISTRIBUTE THE PUBLIC NONCES (LOG GETS USER'S AND VICE VERSA)

    // ROUND 2: signing
    // NOTE: LOSSY CONVERSION IS AN OPTION BUT WE CAN'T DO THAT
    // let msg: &str = std::str::from_utf8(&msg).expect("Invalid UTF-8");

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
    let mut partial_signatures = vec![partial_signature_user, partial_signature_log];
    
    // for round in second_rounds.iter() {
    //     assert!(
    //         !round.is_complete(),
    //         "second round should not be complete yet"
    //     );
    // }

    // SECURITY CHECK, SECOND PRIORITY
    // Invalid partial signatures should be automatically rejected.
    // {
    //     let wrong_nonce = SecNonce::build([0xCC; 32]).build();
    //     let invalid_partial_signature: PartialSignature = sign_partial(
    //         &key_agg_ctx,
    //         seckeys[0],
    //         wrong_nonce,
    //         &second_rounds[0].aggnonce,
    //         message,
    //     )
    //     .unwrap();

    //     assert_eq!(
    //         second_rounds[1].receive_signature(0, invalid_partial_signature),
    //         Err(RoundContributionError::invalid_signature(0)),
    //         "partial signature with invalid nonce should be rejected"
    //     );
    // }

    // THEN THERE'S NO NEED FOR THIS, THIS IS FOR CREATING VECTOR OF PARTIAL SIGNATURES TO SHARE AROUND

    // let partial_signatures: Vec<PartialSignature> = second_rounds
    //     .iter()
    //     .map(|round| round.our_signature())
    //     .collect();

    // TODO: IMITATE EXCHANGE OF PARTIAL SIGNATURES BETWEEN LOG AND USER

    // Distribute the partial signatures.
    // for (i, &partial_signature) in partial_signatures.iter().enumerate() {
    //     for (receiver_index, round) in second_rounds.iter_mut().enumerate() {
    //         round
    //             .receive_signature(i, partial_signature)
    //             .expect(&format!("should receive partial signature {} OK", i));

    //         let mut expected_holdouts: Vec<usize> = (0..seckeys.len()).collect();
    //         expected_holdouts.retain(|&j| j != receiver_index && j > i);
    //         assert_eq!(round.holdouts(), expected_holdouts);

    //         // Confirm the round completes only once all signatures are received
    //         if expected_holdouts.len() == 0 {
    //             assert!(
    //                 round.is_complete(),
    //                 "second round should have completed after signer {} receiving partial signature {}",
    //                 receiver_index,
    //                 i
    //             );
    //         } else {
    //             assert!(
    //                 !round.is_complete(),
    //                 "second round should not have completed after signer {} receiving partial signature {}",
    //                 receiver_index,
    //                 i
    //             );
    //         }
    //     }
    // }

    // The second round should be complete now that everyone has each
    // other's partial signatures.
    // for round in second_rounds.iter() {
    //     assert!(round.is_complete());
    // }

    // Test supplying signatures at wrong indices
    // assert_eq!(
    //     second_rounds[0].receive_signature(2, partial_signatures[1].clone()),
    //     Err(RoundContributionError::invalid_signature(2)),
    //     "receiving a valid partial signature for the wrong signer should fail"
    // );
    // assert_eq!(
    //     second_rounds[0]
    //         .receive_signature(partial_signatures.len() + 1, partial_signatures[1].clone()),
    //     Err(RoundContributionError::out_of_range(
    //         partial_signatures.len() + 1,
    //         partial_signatures.len()
    //     )),
    //     "receiving a partial signature at an invalid index should fail"
    // );

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
}