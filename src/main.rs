use ark_crypto_primitives::crh::CRH as CRHTrait;
use ark_crypto_primitives::crh::poseidon::{CRH , Poseidon, constraints::{PoseidonRoundParamsVar, find_poseidon_ark_and_mds}};
use ark_r1cs_std::fields::fp::FpVar;
// use ark_r1cs_std::UInt128::UInt128;
use simpleworks::schnorr_signature::schnorr_signature_verify_gadget::SigVerifyGadget;
use std::time::Duration;
use ark_ec::bls12::Bls12;
use simpleworks::schnorr_signature::schnorr::MyPoseidonParams;
use ark_relations::r1cs::Namespace;
use ark_std::Zero;
use ark_ec::twisted_edwards_extended::GroupAffine;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ed_on_mnt4_753::EdwardsParameters;
use ark_ff::{BitIteratorLE, Fp256, One, PrimeField};
use ark_ff::{
    bytes::ToBytes,
    fields::{Field},
    UniformRand,
};
use ark_ec::mnt4::MNT4;
use ark_serialize::CanonicalSerialize;
// use ark_mnt4_753::{mnt4_753 as E, Fr};
use ark_mnt4_753::{MNT4_753 as E, Parameters};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    prelude::*
};
use std::{time::Instant, result::Result};
use ark_std::vec::Vec;
use ark_snark::SNARK;
use rand::rngs::OsRng;
use ark_groth16::Groth16;
use simpleworks::schnorr_signature::
    {schnorr::{Schnorr, Parameters as SchnorrParameters, PublicKey, Signature, KeyAggContext, FirstRound, SecondRound, PubNonce, PartialSignature},
    schnorr_signature_verify_gadget::SchnorrSignatureVerifyGadget,
    public_key_var::PublicKeyVar,
    parameters_var::ParametersVar,
    signature_var::SignatureVar,
};
use ark_crypto_primitives::{
    commitment::{pedersen::{
    Commitment, Randomness as PedersenRandomness, Parameters as PedersenParameters},
        CommitmentScheme},
    encryption::{elgamal::{constraints::{OutputVar as ElgamalCiphertextVar}, Ciphertext, ElGamal, Parameters as EncParams, PublicKey as EncPubKey, Randomness as EncRand},
        AsymmetricEncryptionScheme},
    signature::SignatureScheme,
};
use ark_relations::r1cs::{SynthesisError, ConstraintSynthesizer, ConstraintSystemRef, };
use ark_ed_on_mnt4_753::{constraints::EdwardsVar, EdwardsProjective as JubJub};   // Fq2: finite field, JubJub: curve group
use ark_std::marker::PhantomData;


type W = Window;
type C = JubJub; 
type GG = EdwardsVar;
type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;
type MyEnc = ElGamal<JubJub>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Window;

impl ark_crypto_primitives::crh::pedersen::Window for Window {
    const WINDOW_SIZE: usize = 16;
    const NUM_WINDOWS: usize = 16;
}

/* BELOW IS MAIN FOR LOGGING CIRCUIT */

fn generate_logging_circuit() -> (LoggingCircuit<W,C,GG>, PublicKey<C>, GroupAffine<EdwardsParameters>, GroupAffine<EdwardsParameters>) {
    // println!("Entering main.");
    let rng = &mut OsRng;
        
    // let start = Instant::now();
    let elgamal_rand = EncRand::<JubJub>::rand(rng);
    let elgamal_param = MyEnc::setup(rng).unwrap();
    let (elgamal_key, _) = MyEnc::keygen(&elgamal_param, rng).unwrap();

    /* Generate Poseidon hash parameters for both Schnorr signature (Musig2) and v_i */      // 6, 5, 8, 57, 0
    
    let (ark, mds) = find_poseidon_ark_and_mds::<ConstraintF<C>> (753, 6, 8, 57, 0);        // ark_mnt4_753::FrParameters::MODULUS_BITS = 255
    let poseidon_params = Poseidon::<ConstraintF<C>, MyPoseidonParams> {
        params: MyPoseidonParams::default(),
        round_keys: ark.into_iter().flatten().collect(),
        mds_matrix: mds,
    };

    /* Assume this is previous record */
    // let mut i_prev_vec = vec![i_prev];
    let mut elgamal_key_bytes = vec![];
    elgamal_key.serialize(&mut elgamal_key_bytes);
    // i_prev_vec.resize(elgamal_key_bytes.len(), 0u8);
    
    /* Assume this is previous record */
    // let i_prev: u8 = 9;         // Change u8 to 
    // // let mut i_prev_vec = vec![i_prev];
    
    // // i_prev_vec.resize(elgamal_key_bytes.len(), 0u8);
    // let mut prev_input = vec![];
    // prev_input.extend_from_slice(&elgamal_key_bytes);
    // prev_input.extend_from_slice(&[i_prev]);     // Later, resize i_prev and pad with 0s to support larger index numbers
    
    // let mut h_prev_bytes = vec![];
    // let h_prev = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(&poseidon_params, &prev_input).unwrap();
    // h_prev.serialize(&mut h_prev_bytes);

    let i: u8 = 10;
    let mut cur_input = vec![];
    cur_input.extend_from_slice(&elgamal_key_bytes);
    cur_input.extend_from_slice(&[i]);
    let h_cur = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(&poseidon_params, &cur_input).unwrap();
    let mut h_cur_bytes = vec![];
    h_cur.write(&mut h_cur_bytes);
    let plaintext = JubJub::rand(rng).into_affine();
    let v_cur = MyEnc::encrypt(&elgamal_param, &elgamal_key, &plaintext, &elgamal_rand).unwrap();
    let mut v_0_bytes = vec![];    // TODO: unify length to check partition later
    // let mut v_1_bytes = vec![];

    v_cur.0.serialize(&mut v_0_bytes).unwrap();
    
    let mut msg = vec![];
    
    // NOTE: msg ends up being 224 bytes.
    msg.extend_from_slice(&h_cur_bytes);
    msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
    v_0_bytes.clear();
    v_cur.1.serialize(&mut v_0_bytes).unwrap();
    // msg.extend_from_slice(&v_0_y_bytes);
    msg.extend_from_slice(&v_0_bytes);
    // msg.extend_from_slice(&v_1_y_bytes);
    // println!("schnorr msg from outside: {:?}", msg);

    let msg2 = msg.clone();
    // let msg3 = msg.clone();

    /* This is previous signature on record i-1 */

    // let plaintext_prev = JubJub::rand(rng).into_affine();
    // let v_prev = MyEnc::encrypt(&elgamal_param, &elgamal_key, &plaintext, &elgamal_rand).unwrap();
    // let mut v_0_bytes = vec![];    // TODO: unify length to check partition later
    // // let mut v_1_bytes = vec![];

    // v_prev.0.serialize(&mut v_0_bytes).unwrap();
    
    // let mut msg_prev = vec![];
    
    // // NOTE: msg ends up being 224 bytes.
    // msg_prev.extend_from_slice(&h_prev_bytes);
    // msg_prev.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
    // v_0_bytes.clear();
    // v_prev.1.serialize(&mut v_0_bytes).unwrap();
    // // msg.extend_from_slice(&v_0_y_bytes);
    // msg_prev.extend_from_slice(&v_0_bytes);
    // msg.extend_from_slice(&v_1_y_bytes);
    // println!("schnorr msg from outside: {:?}", msg);

    /* AGGREGATE SCHNORR ATTEMPT - WORKS!! */

    let schnorr_param = SchnorrParameters::<C> {
        generator: C::prime_subgroup_generator().into(),
        salt: Some([0u8; 32]),      // Not used
    };
    
    let (user_pk, user_sk) = Schnorr::<C>::keygen(&schnorr_param, rng).unwrap();
    let (log_pk, log_sk)= Schnorr::<C>::keygen(&schnorr_param, rng).unwrap();
    let pubkeys = vec![user_pk, log_pk];
    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
    
    // NOTE: ALWAYS USER FIRST, LOG SECOND IN KEY AGGREGATION

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

    // TODO: DISTRIBUTE THE PUBLIC NONCES (LOG GETS USER'S AND VICE VERSA)

    // ROUND 2: signing

    // USER CREATES SECOND ROUND 2
    let second_round_user: SecondRound<Vec<u8>> = first_round_user
        .finalize(user_sk, msg, pubnonces.clone(), &poseidon_params)
        .expect(&format!("failed to finalize first round for user"));

    let partial_signature_user: PartialSignature = second_round_user.our_signature();

    // LOG CREATES SECOND ROUND 2
    let second_round_log: SecondRound<Vec<u8>> = first_round_log
        .finalize(log_sk, msg2, pubnonces, &poseidon_params)
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
                .finalize(partial_signatures.clone(), &poseidon_params)
                .expect(&format!("failed to finalize second round for signer {}", i))
        })
        .collect();

    let last_sig = signatures.pop().unwrap();
    // println!("LAST SIG OUTSIDE {:?}", last_sig);

    // Sig should be verifiable as a standard schnorr signature
    let aggregated_pubkey: PublicKey<C> = key_agg_ctx.aggregated_pubkey();
    
    /* RESUMES NON-AGGREGATE CODE. */
    
    // let schnorr_verified = Schnorr::<C>::verify(&schnorr_param, &aggregated_pubkey, &msg3, &last_sig).unwrap();
    // println!("schnorr verified outside circuit {:?}", schnorr_verified);

    let mut aggregated_pubkey_bytes = vec![];
    aggregated_pubkey.serialize(&mut aggregated_pubkey_bytes);

    /* Commit to aggregated_pubkey and give it to RP. */
    let pedersen_randomness = PedersenRandomness(<JubJub as ProjectiveCurve>::ScalarField::rand(rng));
    let pedersen_params = Commitment::<JubJub, Window>::setup(rng).unwrap();
    let apk_commit: GroupAffine<EdwardsParameters> = Commitment::<JubJub, Window>::commit(&pedersen_params, &aggregated_pubkey_bytes, &pedersen_randomness).unwrap();
    
    let pedersen_rand_elgamal = PedersenRandomness(<JubJub as ProjectiveCurve>::ScalarField::rand(rng));
    let elgamal_commit: GroupAffine<EdwardsParameters> = Commitment::<JubJub, Window>::commit(&pedersen_params, &elgamal_key_bytes, &pedersen_rand_elgamal).unwrap();

    // let end = start.elapsed();
    // println!("User and log generate variables: {:?}", end);
    // let mut result = [0u128; 4]; // Array to hold the 8 resulting i32 values

    let new_circuit = LoggingCircuit::<W,C,GG> {
        schnorr_params: Some(schnorr_param),
        schnorr_apk: Some(aggregated_pubkey),
        apk_commit_x: Some(apk_commit.x),
        apk_commit_y: Some(apk_commit.y),
        pedersen_rand: Some(pedersen_randomness),
        pedersen_params: Some(pedersen_params),
        poseidon_params: Some(poseidon_params),
        schnorr_sig: Some(last_sig),
        record_x: Some(plaintext.x),
        record_y: Some(plaintext.y),
        elgamal_rand: Some(elgamal_rand),
        elgamal_params: Some(elgamal_param),
        pedersen_rand_elgamal: Some(pedersen_rand_elgamal),
        elgamal_key_commit_x: Some(elgamal_commit.x),
        elgamal_key_commit_y: Some(elgamal_commit.y),
        v_cur: Some(v_cur),
        elgamal_key: Some(elgamal_key),
        h_cur: Some(h_cur),
        i: Some(i),
        _curve_var: PhantomData::<GG>,
        _window_var: PhantomData::<W>,
    };

    (new_circuit, aggregated_pubkey, elgamal_commit, apk_commit)
}

fn main() {
    let mut logistics_total: Duration = Duration::default();
    let mut setup_total: Duration = Duration::default();
    let mut proof_time_total = Duration::default();
    let mut verify_time_total = Duration::default();
    for i in 0..10 {
        println!("InsertCircuit iteration {:?}", i);
        let rng = &mut OsRng;
        let (new_circuit, aggregated_pubkey) = generate_insert_circuit();
        let public_inputs = [      // THESE ARE JUST FIELD ELEMENTS, NEITHER TE NOR SW
            aggregated_pubkey.x,
            aggregated_pubkey.y,
        ];

        let start = Instant::now();
        let new_circuit_for_setup = generate_insert_circuit_for_setup();
        logistics_total += start.elapsed();

        let start = Instant::now();
        let (pk, vk) = Groth16::<E>::circuit_specific_setup(new_circuit_for_setup, rng).unwrap();
        let pvk: ark_groth16::PreparedVerifyingKey<E> = Groth16::<E>::process_vk(&vk).unwrap();
        setup_total += start.elapsed();

        let start = Instant::now();
        let proof = Groth16::<E>::prove(
            &pk,
            new_circuit,
            rng
        ).unwrap();
        proof_time_total += start.elapsed();

        let start = Instant::now();
        let verified = Groth16::<E>::verify_with_processed_vk(
            &pvk,
            &public_inputs,        // NOTE: No public inputs for new users (because they weren't supplied for prove phase)
            &proof,
        );
        verify_time_total += start.elapsed();
        println!("{:?}", verified);
    }
    println!("InsertCircuit Logistics time: {:?}", logistics_total/10);
    println!("InsertCircuit Setup time total: {:?}", setup_total/10);
    println!("InsertCircuit Prove time: {:?}", proof_time_total.as_millis()/10);
    println!("InsertCircuit Verify time: {:?}", verify_time_total.as_millis()/10);

    let mut logistics_total: Duration = Duration::default();
    let mut setup_total: Duration = Duration::default();
    let mut proof_time_total = Duration::default();
    let mut verify_time_total = Duration::default();
    for i in 0..10 {
        println!("LoggingCircuit iteration {:?}", i);
        let rng = &mut OsRng;
        let (new_circuit, aggregated_pubkey, elgamal_commit, apk_commit) = generate_logging_circuit();
        let public_inputs = [
            elgamal_commit.x,
            elgamal_commit.y,
            aggregated_pubkey.x,
            aggregated_pubkey.y,
            apk_commit.x,
            apk_commit.y, 
        ];

        let start = Instant::now();
        let new_circuit_for_setup = generate_logging_circuit_for_setup();
        logistics_total += start.elapsed();

        let start = Instant::now();
        let (pk, vk) = Groth16::<E>::circuit_specific_setup(new_circuit_for_setup, rng).unwrap();
        let pvk: ark_groth16::PreparedVerifyingKey<E> = Groth16::<E>::process_vk(&vk).unwrap();
        setup_total += start.elapsed();

        let start = Instant::now();
        let proof = Groth16::<E>::prove(
            &pk,
            new_circuit,
            rng
        ).unwrap();
        proof_time_total += start.elapsed();

        let start = Instant::now();
        let verified = Groth16::<E>::verify_with_processed_vk(
            &pvk,
            &public_inputs,        // NOTE: No public inputs for new users (because they weren't supplied for prove phase)
            &proof,
        );
        verify_time_total += start.elapsed();
        println!("{:?}", verified);
    }
    println!("LoggingCircuit Logistics time: {:?}", logistics_total/10);
    println!("LoggingCircuit Setup time: {:?}", setup_total/10);
    println!("LoggingCircuit Prove time: {:?}", proof_time_total.as_millis()/10);
    println!("LoggingCircuit Verify time: {:?}", verify_time_total.as_millis()/10);
}

fn generate_insert_circuit() -> (InsertCircuit<W,C,GG>, PublicKey<C>) {
    println!("Generating InsertCircuit");
    let rng = &mut OsRng;
        
    // let start = Instant::now();
    let elgamal_rand = EncRand::<JubJub>::rand(rng);
    let elgamal_param = MyEnc::setup(rng).unwrap();
    let (elgamal_key, _) = MyEnc::keygen(&elgamal_param, rng).unwrap();

    let mut elgamal_key_bytes = vec![];
    elgamal_key.serialize(&mut elgamal_key_bytes);

    /* Generate Poseidon hash parameters for both Schnorr signature (Musig2) and v_i */      // 6, 5, 8, 57, 0
    
    let (ark, mds) = find_poseidon_ark_and_mds::<ConstraintF<C>> (753, 6, 8, 57, 0);        // ark_mnt4_753::FrParameters::MODULUS_BITS = 255
    let poseidon_params = Poseidon::<ConstraintF<C>, MyPoseidonParams> {
        params: MyPoseidonParams::default(),
        round_keys: ark.into_iter().flatten().collect(),
        mds_matrix: mds,
    };

    /* Assume this is previous record */
    let i_prev: u8 = 9;         // Change u8 to 
    // let mut i_prev_vec = vec![i_prev];
    
    // i_prev_vec.resize(elgamal_key_bytes.len(), 0u8);
    let mut prev_input = vec![];
    prev_input.extend_from_slice(&elgamal_key_bytes);
    prev_input.extend_from_slice(&[i_prev]);     // Later, resize i_prev and pad with 0s to support larger index numbers
    
    let mut h_prev_bytes = vec![];
    let h_prev = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(&poseidon_params, &prev_input).unwrap();
    h_prev.serialize(&mut h_prev_bytes);

    let i: u8 = 0;
    let mut cur_input = vec![];
    cur_input.extend_from_slice(&elgamal_key_bytes);
    cur_input.extend_from_slice(&[i]);
    let h_cur = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(&poseidon_params, &cur_input).unwrap();

    let plaintext = JubJub::rand(rng).into_affine();
    let v_prev = MyEnc::encrypt(&elgamal_param, &elgamal_key, &plaintext, &elgamal_rand).unwrap();
    let mut v_0_bytes = vec![];    // TODO: unify length to check partition later
    // let mut v_1_bytes = vec![];

    v_prev.0.serialize(&mut v_0_bytes).unwrap();
    
    let mut msg = vec![];
    
    // NOTE: msg ends up being 224 bytes.
    msg.extend_from_slice(&h_prev_bytes);
    msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
    v_0_bytes.clear();
    v_prev.1.serialize(&mut v_0_bytes).unwrap();
    // msg.extend_from_slice(&v_0_y_bytes);
    msg.extend_from_slice(&v_0_bytes);
    // msg.extend_from_slice(&v_1_y_bytes);
    // println!("schnorr msg from outside: {:?}", msg);

    let msg2 = msg.clone();
    // let msg3 = msg.clone();

    /* AGGREGATE SCHNORR ATTEMPT - WORKS!! */

    let schnorr_param = SchnorrParameters::<C> {
        generator: C::prime_subgroup_generator().into(),
        salt: Some([0u8; 32]),
    };
    
    let (user_pk, user_sk) = Schnorr::<C>::keygen(&schnorr_param, rng).unwrap();
    let (log_pk, log_sk)= Schnorr::<C>::keygen(&schnorr_param, rng).unwrap();
    let pubkeys = vec![user_pk, log_pk];
    let key_agg_ctx = KeyAggContext::new(pubkeys).unwrap();
    
    // NOTE: ALWAYS USER FIRST, LOG SECOND IN KEY AGGREGATION

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

    // TODO: DISTRIBUTE THE PUBLIC NONCES (LOG GETS USER'S AND VICE VERSA)

    // ROUND 2: signing

    // USER CREATES SECOND ROUND 2
    let second_round_user: SecondRound<Vec<u8>> = first_round_user
        .finalize(user_sk, msg, pubnonces.clone(), &poseidon_params)
        .expect(&format!("failed to finalize first round for user"));

    let partial_signature_user: PartialSignature = second_round_user.our_signature();

    // LOG CREATES SECOND ROUND 2
    let second_round_log: SecondRound<Vec<u8>> = first_round_log
        .finalize(log_sk, msg2, pubnonces, &poseidon_params)
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
                .finalize(partial_signatures.clone(), &poseidon_params)
                .expect(&format!("failed to finalize second round for signer {}", i))
        })
        .collect();

    let last_sig = signatures.pop().unwrap();
    // println!("LAST SIG OUTSIDE {:?}", last_sig);

    // Sig should be verifiable as a standard schnorr signature
    let aggregated_pubkey: PublicKey<C> = key_agg_ctx.aggregated_pubkey();

    // let insert_circuit = InsertCircuit::<W,C,GG> {
    //     first_login: Some(true),
    //     schnorr_params: None,
    //     schnorr_apk: Some(aggregated_pubkey),
    //     // apk_commit_x: Some(apk_commit.x),
    //     // apk_commit_y: Some(apk_commit.y),
    //     // pedersen_params:  None,
    //     // pedersen_rand: None,
    //     schnorr_sig: None,
    //     poseidon_params: Some(poseidon_params),
    //     h_prev: None,
    //     v_prev:  None,
    //     elgamal_key: Some(elgamal_key),
    //     // prf_key: Some(prf_key),
    //     h_cur: Some(h_cur),
    //     i: Some(i),
    //     _curve_var: PhantomData::<GG>,
    //     _window_var: PhantomData::<W>,
    // };

    let insert_circuit = InsertCircuit::<W,C,GG> {
        first_login: None,
        schnorr_params: Some(schnorr_param),
        schnorr_apk: Some(aggregated_pubkey),
        // apk_commit_x: Some(apk_commit.x),
        // apk_commit_y: Some(apk_commit.y),
        // pedersen_params:  Some(pedersen_params),
        poseidon_params: Some(poseidon_params),
        // pedersen_rand: Some(pedersen_randomness),
        schnorr_sig: Some(last_sig),
        h_prev: Some(h_prev),
        v_prev:  Some(v_prev),
        elgamal_key: Some(elgamal_key),
        h_cur: Some(h_cur),
        i: Some(i),
        _curve_var: PhantomData::<GG>,
        _window_var: PhantomData::<W>,
    };

    (insert_circuit, aggregated_pubkey)
}

fn generate_insert_circuit_for_setup() -> InsertCircuit<W,C,GG> {
        InsertCircuit::<W, C, GG> {
        first_login: None,
        schnorr_params: None,
        schnorr_apk: None,
        poseidon_params: None,
        schnorr_sig: None,
        h_prev: None,
        v_prev: None,
        elgamal_key: None,
        h_cur: None,
        i: Some(0),     // value doesn't mater but needs to be populated 
        _curve_var: PhantomData::<GG>,
        _window_var: PhantomData::<W>,
    }
}

fn generate_logging_circuit_for_setup() -> LoggingCircuit::<W, C, GG> {
    LoggingCircuit::<W,C,GG> {
        schnorr_params: None,
        schnorr_apk: None,
        apk_commit_x: None,
        apk_commit_y: None,
        pedersen_rand: None,
        pedersen_params: None,
        poseidon_params: None,
        schnorr_sig: None,
        record_x: None,
        record_y: None,
        elgamal_rand: None,
        elgamal_params: None,
        pedersen_rand_elgamal: None,
        elgamal_key_commit_x: None,
        elgamal_key_commit_y: None,
        v_cur: None,
        elgamal_key: None,
        h_cur: None,
        i: None,
        _curve_var: PhantomData::<GG>,
        _window_var: PhantomData::<W>,
    }
}

impl<W, C, GG> ConstraintSynthesizer<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr> for InsertCircuit<W, C, GG> where 
    W: ark_crypto_primitives::crh::pedersen::Window,
    ConstraintF<C>: PrimeField,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
    <C as ProjectiveCurve>::Affine: From<ark_ec::twisted_edwards_extended::GroupAffine<EdwardsParameters>>,
    Namespace<<<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField>: From<ConstraintSystemRef<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>>,
    <C as ProjectiveCurve>::BaseField: PrimeField,
    // <C as ProjectiveCurve>::BaseField: ark_r1cs_std::select::CondSelectGadget<<C as ProjectiveCurve>::BaseField>,
    // Vec<u8>: Borrow<<C as ProjectiveCurve>::BaseField>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>) -> Result<(), SynthesisError> {
        let default_affine = C::Affine::default();
        let h_default = <MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr::default();      // This is ConstraintF<C>
        let sig_default = Signature::default();
        let pubkey_default = PublicKey::<C>::default();
        let schnorr_param_default: SchnorrParameters<C> = SchnorrParameters::<C> {
            generator: <C as ProjectiveCurve>::Affine::default(),
            salt: Some([0u8;32]),
        };

        let first_login_wtns = Boolean::<ConstraintF<C>>::new_witness(
            cs.clone(), 
            || {Ok(self.first_login.as_ref().unwrap_or(&false))
        }).unwrap();

        /* If first login, i=0 must be true. */


        let i_wtns = UInt8::<ConstraintF<C>>::new_witness (
            cs.clone(),
            || {
                let i = self.i.as_ref().unwrap();
                Ok(*i)
                // [ *i ]
            }
        ).unwrap();
        
        let zero_wtns = UInt8::<ConstraintF<C>>::new_witness (
            cs.clone(),
            || { Ok(u8::zero()) }
        ).unwrap();

        let supposed_to_be = first_login_wtns.select(&zero_wtns, &i_wtns).unwrap();

        let supposed_to_be_wtns = UInt8::<ConstraintF<C>>::new_witness (
            cs.clone(),
            || {
                Ok(supposed_to_be.value().unwrap_or(u8::one()))
            }
        ).unwrap();

        i_wtns.enforce_equal(&supposed_to_be_wtns);

        let reconstructed_msg_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(
            cs.clone(),
            &{
                let mut h_bytes = vec![];
                let h = self.h_prev.as_ref().unwrap_or(&h_default);
                h.write(&mut h_bytes);
                let default_coords = (<C as ProjectiveCurve>::Affine::default(), <C as ProjectiveCurve>::Affine::default());
                let mut v_0_bytes = vec![];
                let mut v_1_bytes = vec![];
                let v: &(<C as ProjectiveCurve>::Affine, <C as ProjectiveCurve>::Affine) = self.v_prev.as_ref().unwrap_or(&default_coords);
                
                v.0.serialize(&mut v_0_bytes).unwrap();
                v.1.serialize(&mut v_1_bytes).unwrap();

                let mut msg: Vec<u8> = vec![];
                msg.extend_from_slice(&h_bytes);
                msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
                msg.extend_from_slice(&v_1_bytes);

                msg
            }
        ).unwrap();

        let schnorr_param_const = ParametersVar::<C,GG>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_params.as_ref().unwrap_or(&schnorr_param_default)),
            AllocationMode::Constant,
        ).unwrap();

        /* SCHNORR SIG VERIFY GADGET */
        let poseidon_param_default = Poseidon::<ConstraintF<C>, MyPoseidonParams> {
            params: MyPoseidonParams::default(),
            round_keys: vec![<ConstraintF<C>>::zero();455],            // 6 = width hardcoded
            mds_matrix: vec![vec![<ConstraintF<C>>::zero();6];6],
        };
        
        let mut poseidon_params_wtns = PoseidonRoundParamsVar::<ConstraintF<C>, MyPoseidonParams>::new_variable(
            cs.clone(),
            || Ok(self.poseidon_params.as_ref().unwrap_or(&poseidon_param_default)),
            AllocationMode::Witness,
        )?;

        let schnorr_apk_input = PublicKeyVar::<C, GG>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_apk.ok_or(SynthesisError::AssignmentMissing)?),
            AllocationMode::Input,          // NOTE: this should be witness when RP is verifying circuit
        ).unwrap();

        let schnorr_sig_wtns = SignatureVar::<C, GG>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_sig.as_ref().unwrap_or(&sig_default)),
            AllocationMode::Witness,
        ).unwrap();

        let start = Instant::now();
        let schnorr_verified = SchnorrSignatureVerifyGadget::<C,GG>::verify(
            cs.clone(),
            &schnorr_param_const,
            &schnorr_apk_input,
            &reconstructed_msg_wtns,
            &schnorr_sig_wtns,
            &mut poseidon_params_wtns,
        ).unwrap();
        
        let verified_select: Boolean<ConstraintF<C>> = first_login_wtns.select(&Boolean::TRUE, &schnorr_verified)?;

        // verified_select.enforce_equal(&Boolean::TRUE)?;
        
        let mut cur_input = vec![];
        let mut elgamal_key_bytes = vec![];
        let computed_hash_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(
            cs.clone(),
            &{
                let poseidon_params = self.poseidon_params.as_ref().unwrap_or(&poseidon_param_default);
                // let mut cur_input = vec![];
                let elgamal_key = self.elgamal_key.as_ref().unwrap_or(&default_affine);
                // let mut elgamal_key_bytes = vec![];
                elgamal_key.serialize(&mut elgamal_key_bytes);
                cur_input.extend_from_slice(&elgamal_key_bytes);
                cur_input.extend_from_slice(&[*self.i.as_ref().unwrap_or(&0)]);
                let result = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(&poseidon_params, &cur_input).unwrap();
                let mut result_vec = vec![];
                // result.clear();
                result.serialize(&mut result_vec);
                result_vec
            },
        ).unwrap();

        cur_input.clear();
        elgamal_key_bytes.clear();
        let computed_prev_hash_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(
            cs.clone(),
            &{
                let poseidon_params = self.poseidon_params.as_ref().unwrap_or(&poseidon_param_default);
                // let mut prev_input = vec![];
                let elgamal_key = self.elgamal_key.as_ref().unwrap_or(&default_affine);
                // let mut elgamal_key_bytes = vec![];
                elgamal_key.serialize(&mut elgamal_key_bytes);

                let i_value = self.i.as_ref().unwrap_or(&0);
                let selected_i_prev = UInt8::<ConstraintF<C>>::conditionally_select(
                    &Boolean::<ConstraintF<C>>::constant(*i_value == 0),
                    &UInt8::<ConstraintF<C>>::constant(0),
                    &UInt8::<ConstraintF<C>>::constant(i_value.checked_sub(1).unwrap_or(0)),   // both branches run
                )?;

                cur_input.extend_from_slice(&elgamal_key_bytes);
                cur_input.extend_from_slice(&[selected_i_prev.value().unwrap()]);
                elgamal_key_bytes.clear();
                let result = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(&poseidon_params, &cur_input).unwrap();
                result.serialize(&mut elgamal_key_bytes);
                elgamal_key_bytes
            },
        ).unwrap();

        let h_cur_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(
            cs.clone(),
            &{
                let h_cur = self.h_cur.unwrap_or(h_default);            // TODO: consider serializing outside circuit and passing u8 as input
                let mut h_cur_vec = vec![];
                h_cur.write(&mut h_cur_vec);
                h_cur_vec
            },
        ).unwrap();

        let h_prev_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(
            cs.clone(),
            &{
                let h_prev = self.h_prev.unwrap_or(h_default);            // TODO: consider serializing outside circuit and passing u8 as input
                let mut h_prev_vec = vec![];
                h_prev.write(&mut h_prev_vec);
                h_prev_vec
            },
        ).unwrap();

        // computed_hash_wtns.enforce_equal(&h_cur_wtns);
        // computed_prev_hash_wtns.enforce_equal(&h_prev_wtns);

        Ok(())
    }
}

pub struct InsertCircuit<W, C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>> {
    pub first_login: Option<bool>,
    pub schnorr_params: Option<SchnorrParameters<C>>,
    pub schnorr_apk: Option<C::Affine>,
    pub poseidon_params: Option<Poseidon::<ConstraintF<C>, MyPoseidonParams>>,
    pub schnorr_sig: Option<Signature<C>>,
    pub h_prev: Option<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>,           /* Record info */
    pub v_prev: Option<Ciphertext<C>>,
    pub elgamal_key: Option<PublicKey<C>>,  
    pub h_cur: Option<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>,
    pub i: Option<u8>,
    pub _curve_var: PhantomData<GG>,
    pub _window_var: PhantomData<W>,
}

pub struct LoggingCircuit<W, C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>> {
    pub schnorr_params: Option<SchnorrParameters<C>>,
    pub schnorr_apk: Option<C::Affine>,
    pub apk_commit_x: Option<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>,
    pub apk_commit_y: Option<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>,
    pub pedersen_rand: Option<PedersenRandomness<C>>,
    pub pedersen_params: Option<PedersenParameters<C>>,
    pub poseidon_params: Option<Poseidon::<ConstraintF<C>, MyPoseidonParams>>,
    pub schnorr_sig: Option<Signature<C>>,
    pub record_x: Option<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>,
    pub record_y: Option<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>,
    pub elgamal_rand: Option<EncRand<C>>,
    pub elgamal_params: Option<EncParams<C>>,
    pub pedersen_rand_elgamal: Option<PedersenRandomness<C>>,
    pub elgamal_key_commit_x: Option<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>,
    pub elgamal_key_commit_y: Option<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>,
    pub v_cur: Option<Ciphertext<C>>,
    pub elgamal_key: Option<EncPubKey<C>>,  
    pub h_cur: Option<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>,
    pub i: Option<u8>,
    pub _curve_var: PhantomData<GG>,
    pub _window_var: PhantomData<W>,
}

impl<W, C, GG> ConstraintSynthesizer<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr> for LoggingCircuit<W, C, GG> where 
    W: ark_crypto_primitives::crh::pedersen::Window,
    ConstraintF<C>: PrimeField,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
    <C as ProjectiveCurve>::Affine: From<ark_ec::twisted_edwards_extended::GroupAffine<EdwardsParameters>>,
    Namespace<<<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField>: From<ConstraintSystemRef<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>) -> Result<(), SynthesisError> { 
        let affine_default = C::Affine::default();
        let sig_default = Signature::<C>::default();
        let pubkey_default = PublicKey::<C>::default();
        let schnorr_param_default = SchnorrParameters::<C> {
            generator: C::Affine::default(),
            salt: Some([0u8; 32]),
        };
        let poseidon_param_default = Poseidon::<ConstraintF<C>, MyPoseidonParams> {
            params: MyPoseidonParams::default(),
            round_keys: vec![ConstraintF::<C>::zero(); 455], // Assuming 455 is the correct size
            mds_matrix: vec![vec![ConstraintF::<C>::zero(); 6]; 6], // Assuming 6x6 MDS matrix
        };
        let pedersen_rand_default = PedersenRandomness::<C>::default();
        let pedersen_param_default = PedersenParameters::<C> {
            randomness_generator: vec![],
            generators: vec![vec![];16],        // NUM_WINDOWS=16 hardcoded
        };
        let pub_input_default = <MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr::one();

        let mut cur_input = vec![];
        let mut elgamal_key_bytes = vec![];

        /* Check h_i hashes correct Elgamal key. */
        let computed_hash_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(
            cs.clone(),
            &{
                let poseidon_params = self.poseidon_params.as_ref().unwrap_or(&poseidon_param_default);
                let elgamal_key = self.elgamal_key.as_ref().unwrap_or(&affine_default);
                elgamal_key.serialize(&mut elgamal_key_bytes);
                cur_input.extend_from_slice(&elgamal_key_bytes);
                cur_input.extend_from_slice(&[*self.i.as_ref().unwrap_or(&0)]);
                let result = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(&poseidon_params, &cur_input).unwrap();
                let mut result_vec = vec![];
                result.serialize(&mut result_vec);
                result_vec
            },
        ).unwrap();

        let h_cur_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(
            cs.clone(),
            &{
                let h_cur = self.h_cur.unwrap_or(pub_input_default);            // TODO: consider serializing outside circuit and passing u8 as input
                let mut h_cur_vec = vec![];
                h_cur.write(&mut h_cur_vec);
                h_cur_vec
            },
        ).unwrap();

        computed_hash_wtns.enforce_equal(&h_cur_wtns);

        /* Check elgamal key commitment */
        let elgamal_commit_x = self.elgamal_key_commit_x.unwrap_or(pub_input_default);
        let elgamal_commit_y = self.elgamal_key_commit_y.unwrap_or(pub_input_default);
        
        let elgamal_commit_proj = C::from(GroupAffine::<ark_ed_on_mnt4_753::EdwardsParameters>::new(elgamal_commit_x, elgamal_commit_y).into());       // THIS IS TWISTED EDWARDS

        let reconstructed_commit_var = GG::new_variable_omit_prime_order_check( // VERIFY USED TO FAIL BUT PASSES NOW
            cs.clone(),
            || Ok(elgamal_commit_proj),
            AllocationMode::Input,
        ).unwrap();

        let default_elgamal_key = EncPubKey::<C>::default();
        // let start = Instant::now();
        let commit_input = GG::new_variable_omit_prime_order_check( // VERIFY USED TO FAIL BUT PASSES NOW
            cs.clone(),
            || {
                let parameters = self.pedersen_params.as_ref().unwrap_or(&pedersen_param_default);
                let randomness = self.pedersen_rand_elgamal.as_ref().unwrap_or(&pedersen_rand_default);

                let mut h_vec = vec![0u8; 32];  // Vec<u8> avoids lifetime issues
                let pubkey = self.elgamal_key.as_ref().unwrap_or(&default_elgamal_key);
                pubkey.serialize(&mut h_vec[..]).unwrap();
            
                let input = h_vec;
                
                // If the input is too long, return an error.
                if input.len() > W::WINDOW_SIZE * W::NUM_WINDOWS {
                    panic!("incorrect input length: {:?}", input.len());
                }
                // Pad the input to the necessary length.
                let mut padded_input = Vec::with_capacity(input.len());
                let mut input = input;
                if (input.len() * 8) < W::WINDOW_SIZE * W::NUM_WINDOWS {
                    padded_input.extend_from_slice(&input);
                    let padded_length = (W::WINDOW_SIZE * W::NUM_WINDOWS) / 8;
                    padded_input.resize(padded_length, 0u8);
                    input = padded_input;
                }
                assert_eq!(parameters.generators.len(), W::NUM_WINDOWS);

                // Invoke Pedersen CRH here, to prevent code duplication.

                let crh_parameters = ark_crypto_primitives::crh::pedersen::Parameters {
                    // randomness_generator: parameters.randomness_generator.clone(),
                    generators: parameters.generators.clone(),
                };
                let mut result: C = ark_crypto_primitives::crh::pedersen::CRH::<C,W>::evaluate(&crh_parameters, &input).unwrap().into();

                // Compute h^r.
                for (bit, power) in BitIteratorLE::new(randomness.0.into_repr())
                    .into_iter()
                    .zip(&parameters.randomness_generator)
                {
                    if bit {
                        result += power
                    }
                }
                Ok(result)
            },
            AllocationMode::Witness,
        ).unwrap();

        commit_input.enforce_equal(&reconstructed_commit_var);
        
        // println!("time commit {:?}", end);

        let default_coords = (<C as ProjectiveCurve>::Affine::default(), <C as ProjectiveCurve>::Affine::default());

        let v_cur_wtns = ElgamalCiphertextVar::<C,GG>::new_variable (
            cs.clone(),
            || Ok(self.v_cur.as_ref().unwrap_or(&default_coords)),
            AllocationMode::Witness,
        ).unwrap();

        /* Check encryption of correct context (using correct Elgamal key) */
        let default_rand = EncRand::<C>(C::ScalarField::zero());
        let default_param = EncParams::<C>{generator: C::Affine::default()};
        let reconstructed_v_cur_wtns = ElgamalCiphertextVar::<C,GG>::new_variable (
            cs.clone(),
            || {
                let record_x = self.record_x.as_ref().unwrap_or(&pub_input_default);     // TODO: change to unwrap_or() default
                let record_y = self.record_y.as_ref().unwrap_or(&pub_input_default);
                // println!("record x {:?}", record_x);
                // println!("record y {:?}", record_y);
                // println!("here1");
                let record_input = C::Affine::from(GroupAffine::<ark_ed_on_mnt4_753::EdwardsParameters>::new(*record_x, *record_y).into());

                let elgamal_param_input = self.elgamal_params.as_ref().unwrap_or(&default_param);
                let pubkey = self.elgamal_key.as_ref().unwrap_or(&default_elgamal_key);
                let elgamal_rand = self.elgamal_rand.as_ref().unwrap_or(&default_rand);
                let ciphertext: (C::Affine, C::Affine) = ElGamal::<C>::encrypt(elgamal_param_input, pubkey, &record_input, elgamal_rand).unwrap();
                // let hi = ciphertext.c1;
                // let c1_gg = GG::new_variable_omit_prime_order_check(cs.clone(), || Ok(ciphertext.c1), AllocationMode::Constant).unwrap();
                // let c2_gg = GG::new_variable_omit_prime_order_check(cs.clone(), || Ok(ciphertext.c2), AllocationMode::Constant).unwrap();
                Ok((ciphertext.0, ciphertext.1))
            },
            AllocationMode::Witness,
        ).unwrap();

        v_cur_wtns.enforce_equal(&reconstructed_v_cur_wtns);

        /* Check aggregated signature */

        let reconstructed_msg_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(
            cs.clone(),
            &{
                let mut h_bytes = vec![];
                let h = self.h_cur.as_ref().unwrap_or(&pub_input_default);
                h.write(&mut h_bytes);
                let default_coords = (<C as ProjectiveCurve>::Affine::default(), <C as ProjectiveCurve>::Affine::default());
                let mut v_0_bytes = vec![];
                let mut v_1_bytes = vec![];
                let v: &(<C as ProjectiveCurve>::Affine, <C as ProjectiveCurve>::Affine) = self.v_cur.as_ref().unwrap_or(&default_coords);
                
                v.0.serialize(&mut v_0_bytes).unwrap();
                v.1.serialize(&mut v_1_bytes).unwrap();

                let mut msg: Vec<u8> = vec![];
                msg.extend_from_slice(&h_bytes);
                msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
                msg.extend_from_slice(&v_1_bytes);

                // println!("reconstructed msg {:?}", msg);
                msg
            }
        ).unwrap();

        // let start = Instant::now();
        
        let schnorr_param_const = ParametersVar::<C,GG>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_params.as_ref().unwrap_or(&schnorr_param_default)),
            AllocationMode::Constant,
        ).unwrap();

        /* SCHNORR SIG VERIFY GADGET */
        let poseidon_param_default = Poseidon::<ConstraintF<C>, MyPoseidonParams> {
            params: MyPoseidonParams::default(),
            round_keys: vec![<ConstraintF<C>>::zero();455],            // 6 = width hardcoded
            mds_matrix: vec![vec![<ConstraintF<C>>::zero();6];6],
        };
        
        let mut poseidon_params_wtns = PoseidonRoundParamsVar::<ConstraintF<C>, MyPoseidonParams>::new_variable(
            cs.clone(),
            || Ok(self.poseidon_params.as_ref().unwrap_or(&poseidon_param_default)),
            AllocationMode::Witness,
        )?;

        let schnorr_apk_input = PublicKeyVar::<C, GG>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_apk.as_ref().unwrap_or(&pubkey_default)),
            AllocationMode::Input,          // NOTE: this should be witness when RP is verifying circuit
        ).unwrap();

        let schnorr_sig_wtns = SignatureVar::<C, GG>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_sig.as_ref().unwrap_or(&sig_default)),
            AllocationMode::Witness,
        ).unwrap();

        // let end = start.elapsed();
        // println!("Various variable declaration {:?}", end);
        // let start = Instant::now();
        let schnorr_verified = SchnorrSignatureVerifyGadget::<C,GG>::verify(
            cs.clone(),
            &schnorr_param_const,
            &schnorr_apk_input,
            &reconstructed_msg_wtns,
            &schnorr_sig_wtns,
            &mut poseidon_params_wtns,
        ).unwrap();

        // let end = start.elapsed();
        // println!("Schnorr verify time {:?}", end);
        
        // println!("verified {:?}", schnorr_verified.value());

        schnorr_verified.enforce_equal(&Boolean::TRUE)?;
        
        /* Check that the schnorr_apk provided is the apk committed to at registration and given to RP. */

        let apk_commit_x = self.apk_commit_x.unwrap_or(pub_input_default);
        let apk_commit_y = self.apk_commit_y.unwrap_or(pub_input_default);
        
        // println!("here2");
        let apk_commit_proj = C::from(GroupAffine::<ark_ed_on_mnt4_753::EdwardsParameters>::new(apk_commit_x, apk_commit_y).into());       // THIS IS TWISTED EDWARDS
        // println!("APK COMMIT PROJ {:?}", apk_commit_proj);
        let reconstructed_commit_var = GG::new_variable_omit_prime_order_check( // VERIFY USED TO FAIL BUT PASSES NOW
            cs.clone(),
            || Ok(apk_commit_proj),
            AllocationMode::Input,
        ).unwrap();

        // println!("reconstructed_commit_var {:?}", reconstructed_commit_var.value());

        // let end = start.elapsed();
        // println!("time 3 {:?}", end);

        // let start = Instant::now();
        let commit_wtns = GG::new_variable_omit_prime_order_check( // VERIFY USED TO FAIL BUT PASSES NOW
            cs.clone(),
            || {
                let parameters = self.pedersen_params.as_ref().unwrap_or(&pedersen_param_default);
                let randomness = self.pedersen_rand.as_ref().unwrap_or(&pedersen_rand_default);

                let mut h_vec = vec![0u8; 32];  // Vec<u8> avoids lifetime issues
                let apk = self.schnorr_apk.as_ref().unwrap_or(&pubkey_default);
                apk.serialize(&mut h_vec[..]).unwrap();

                let input = h_vec;
                
                // If the input is too long, return an error.
                if input.len() > W::WINDOW_SIZE * W::NUM_WINDOWS {
                    panic!("incorrect input length: {:?}", input.len());
                }
                // Pad the input to the necessary length.
                let mut padded_input = Vec::with_capacity(input.len());
                let mut input = input;
                if (input.len() * 8) < W::WINDOW_SIZE * W::NUM_WINDOWS {
                    padded_input.extend_from_slice(&input);
                    let padded_length = (W::WINDOW_SIZE * W::NUM_WINDOWS) / 8;
                    padded_input.resize(padded_length, 0u8);
                    input = padded_input;
                }
                assert_eq!(parameters.generators.len(), W::NUM_WINDOWS);

                // Invoke Pedersen CRH here, to prevent code duplication.

                let crh_parameters = ark_crypto_primitives::crh::pedersen::Parameters {
                    // randomness_generator: parameters.randomness_generator.clone(),
                    generators: parameters.generators.clone(),
                };
                let mut result: C = ark_crypto_primitives::crh::pedersen::CRH::<C,W>::evaluate(&crh_parameters, &input).unwrap().into();

                // Compute h^r.
                for (bit, power) in BitIteratorLE::new(randomness.0.into_repr())
                    .into_iter()
                    .zip(&parameters.randomness_generator)
                {
                    if bit {
                        result += power
                    }
                }
                Ok(result)
            },
            AllocationMode::Witness,
        ).unwrap();
        commit_wtns.enforce_equal(&reconstructed_commit_var);

        // println!("time 5 {:?}", end);
    
        // println!("last in generate constraints");
        Ok(())
    }
}
