use simpleworks::schnorr_signature::schnorr_signature_verify_gadget::SigVerifyGadget;
use merlin::Transcript;
use libspartan::{Assignment, Instance, NIZKGens, NIZK};
// use ark_crypto_primitives_03::crh::poseidon::Poseidon;
use ark_crypto_primitives_03::SignatureScheme;
use ark_ec::CurveConfig;
// use ark_ec::twisted_edwards::GroupProjective;
use ark_r1cs_std::fields::fp::FpVar;
use ark_sponge::poseidon::find_poseidon_ark_and_mds;
// use ark_r1cs_std::UInt128::UInt128;
// use simpleworks::schnorr_signature::schnorr_signature_verify_gadget::SigVerifyGadget;
use std::time::Duration;
// use ark_ec::bls12::Bls12;
use ark_ed25519::{FrConfig, EdwardsAffine, EdwardsConfig, Fq};
use ark_crypto_primitives::crh::poseidon::constraints::{CRHGadget, CRHParametersVar, TwoToOneCRHGadget};
use ark_crypto_primitives::crh::poseidon::{TwoToOneCRH, CRH};
use ark_crypto_primitives::crh::{CRHScheme, CRHSchemeGadget};
use ark_crypto_primitives::crh::{TwoToOneCRHScheme, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystem, Namespace, SynthesisMode};
use ark_std::{Zero, borrow::Borrow};
use ark_ec::{twisted_edwards::Affine, AffineRepr, CurveGroup};
// use ark_ec::{PairingEngine, ProjectiveCurve};
// use ark_ed25519::EdwardsParameters;
use ark_ff::{MontBackend, BitIteratorLE, Fp256, Fp, One, PrimeField};
use ark_ff::{
    // bytes::ToBytes,
    fields::{Field},
    UniformRand,
};
// use ark_ec::BN254::BN254;
use ark_serialize::{CanonicalSerialize, Compress};
// use ark_bn254::{bn254 as E, Fr};
// use ark_bn254::{Bn254, Bn254 as E, Parameters};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    prelude::*
};
use std::{time::Instant, result::Result};
use ark_std::vec::Vec;
// use ark_snark::SNARK;
use rand::rngs::OsRng;
// use ark_groth16::Groth16;
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
    // signature::SignatureScheme,
};
use ark_relations::r1cs::{SynthesisError, ConstraintSynthesizer, ConstraintSystemRef, };
use ark_ed25519::{constraints::EdwardsVar, EdwardsProjective as JubJub};   // Fq2: finite field, JubJub: curve group
use ark_std::marker::PhantomData;

type Fr = Fp<MontBackend<FrConfig, 4>, 4>;
type C = JubJub; 
type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
type W = Window;
type GG = EdwardsVar;
type MyEnc = ElGamal<JubJub>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Window;

impl ark_crypto_primitives::crh::pedersen::Window for Window {
    const WINDOW_SIZE: usize = 16;
    const NUM_WINDOWS: usize = 16;
}

/* BELOW IS MAIN FOR LOGGING CIRCUIT */


fn generate_logging_circuit() -> LoggingCircuit<W,C,GG> {
    // println!("Entering main.");
    let rng = &mut OsRng;
        
    // let start = Instant::now();
    let elgamal_rand = EncRand::<JubJub>::rand(rng);
    let elgamal_param = MyEnc::setup(rng).unwrap();
    let (elgamal_key, _) = MyEnc::keygen(&elgamal_param, rng).unwrap();

    /* Generate Poseidon hash parameters for both Schnorr signature (Musig2) and v_i */      // 6, 5, 8, 57, 0
    
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr> (255, 2, 8, 24, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255

    let poseidon_params = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);
    /* Assume this is previous record */
    // let mut i_prev_vec = vec![i_prev];
    // Step 1: Serialize the ElGamal key into a byte vector.
    let mut elgamal_key_bytes = vec![];
    elgamal_key.serialize_with_mode(&mut elgamal_key_bytes, Compress::Yes).unwrap(); // Ensure serialization succeeds.

    // Step 2: Prepare a new vector to hold the serialized data.
    let mut cur_input = Vec::with_capacity(elgamal_key_bytes.len() + 1); // Preallocate with the expected size.

    // Step 3: Extend the vector with the serialized key bytes.
    cur_input.extend_from_slice(&elgamal_key_bytes);

    // Step 4: Append the additional `u8` value.
    let i: u8 = 10;
    cur_input.push(i); // Append `i` directly as a byte.

    // Step 5: Convert to the scalar field element directly.
    let fr_element = Fr::from_be_bytes_mod_order(&cur_input);
    // let h_cur = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(&poseidon_params, &cur_input).unwrap();
    let h_cur = CRH::<Fr>::evaluate(&poseidon_params, [fr_element]).unwrap();
    let mut h_cur_bytes = vec![];
    h_cur.serialize_with_mode(&mut h_cur_bytes, Compress::Yes);
    let plaintext = JubJub::rand(rng).into_affine();
    let v_cur = MyEnc::encrypt(&elgamal_param, &elgamal_key, &plaintext, &elgamal_rand).unwrap();

    // println!("vcur.0 {:?}", v_cur.0);
    // println!("vcur.1 {:?}", v_cur.1);
    // println!("v_cur {:?}", v_cur);
    let mut v_0_bytes = vec![];    // TODO: unify length to check partition later
    // let mut v_1_bytes = vec![];

    v_cur.0.serialize_with_mode(&mut v_0_bytes, Compress::Yes).unwrap();
    
    let mut msg = vec![];
    
    // NOTE: msg ends up being 224 bytes.
    msg.extend_from_slice(&h_cur_bytes);
    msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
    v_0_bytes.clear();
    v_cur.1.serialize_with_mode(&mut v_0_bytes, Compress::Yes).unwrap();
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

    let schnorr_param = SchnorrParameters {
        generator: EdwardsAffine::default(),
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
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
    
    /* RESUMES NON-AGGREGATE CODE. */
    
    // let schnorr_verified = Schnorr::<C>::verify(&schnorr_param, &aggregated_pubkey, &msg3, &last_sig).unwrap();
    // println!("schnorr verified outside circuit {:?}", schnorr_verified);

    let mut aggregated_pubkey_bytes = vec![];
    aggregated_pubkey.serialize_with_mode(&mut aggregated_pubkey_bytes, Compress::Yes);

    /* Commit to aggregated_pubkey and give it to RP. */
    let pedersen_randomness = PedersenRandomness(Fr::rand(rng));
    let pedersen_params = Commitment::<JubJub, Window>::setup(rng).unwrap();
    let apk_commit = Commitment::<JubJub, Window>::commit(&pedersen_params, &aggregated_pubkey_bytes, &pedersen_randomness).unwrap();
    
    let pedersen_rand_elgamal = PedersenRandomness(Fr::rand(rng));
    let elgamal_commit = Commitment::<JubJub, Window>::commit(&pedersen_params, &elgamal_key_bytes, &pedersen_rand_elgamal).unwrap();

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
    new_circuit
}

fn main() {
    let mut proof_time_total = Duration::default();
    let mut verify_time_total = Duration::default();
    for i in 0..10 {
        println!("InsertCircuit iteration {:?}", i);
        let cs: ConstraintSystemRef<Fp<MontBackend<FrConfig, 4>, 4>> = ConstraintSystem::new_ref();
        let (circuit, _) = generate_insert_circuit();
        cs.set_mode(SynthesisMode::Prove{construct_matrices: true});
        circuit.generate_constraints(cs.clone());
        
        let matrices: ConstraintMatrices<Fp<MontBackend<FrConfig, 4>, 4>> = cs.to_matrices().unwrap();
        let num_cons = cs.num_constraints();
        let num_vars = cs.num_witness_variables();
        let num_inputs = cs.num_instance_variables();
        println!("num cons {:?}", num_cons);
        println!("num inputs {:?}", num_inputs);
        let a_flat = flatten_vec_vec(matrices.a);
        let b_flat = flatten_vec_vec(matrices.b);
        let c_flat = flatten_vec_vec(matrices.c);

        let cs_inner = cs.into_inner().unwrap();
        let instance_assignment = cs_inner.instance_assignment;    // TODO: CLONE EXPENSIVE
        let instance_assignment_var = Assignment::<Fr>::new(&instance_assignment).unwrap();
        let witness_assignment = cs_inner.witness_assignment;
        let witness_assignment_var = Assignment::<Fr>::new(&witness_assignment).unwrap();
        
        let gens = NIZKGens::<C>::new(num_cons, num_vars, num_inputs);
        // this Fq must be same as constraintsmatrices<fq> i.e. ConstraintSystemRef<Fq>
        let inst = Instance::<Fr>::new(num_cons, num_vars, num_inputs, &a_flat, &b_flat, &c_flat).unwrap();
        
        // TODO: So for NIZK<G> I just need a curve group whose scalar field = base field of bls12-381
        // and it's correct but vscode is not seeing it
        let mut prover_transcript = Transcript::new(b"nizk_example");
        let start = Instant::now();
        let proof = NIZK::<C>::prove(&inst, instance_assignment_var.clone(), &witness_assignment_var, &gens, &mut prover_transcript);
        proof_time_total += start.elapsed();

        // verify the proof of satisfiability
        let mut verifier_transcript = Transcript::new(b"nizk_example");
        let start = Instant::now();
        let verified = proof
        .verify(&inst, &instance_assignment_var, &mut verifier_transcript, &gens)
        .is_ok();
        verify_time_total += start.elapsed();
        println!("verify result: {:?}", verified);
    }
    // println!("InsertCircuit Logistics time: {:?}", logistics_total/10);
    // println!("InsertCircuit Setup time total: {:?}", setup_total/10);
    println!("InsertCircuit Prove time: {:?}", proof_time_total.as_millis()/10);
    println!("InsertCircuit Verify time: {:?}", verify_time_total.as_millis()/10);

    // let mut logistics_total: Duration = Duration::default();
    // let mut setup_total: Duration = Duration::default();
    let mut proof_time_total = Duration::default();
    let mut verify_time_total = Duration::default();
    for i in 0..10 {
        println!("LoggingCircuit iteration {:?}", i);
        // let rng = &mut OsRng;
        // let (new_circuit, aggregated_pubkey, elgamal_commit, apk_commit) = generate_logging_circuit();
        // let public_inputs = [
        //     elgamal_commit.x,
        //     elgamal_commit.y,
        //     aggregated_pubkey.x,
        //     aggregated_pubkey.y,
        //     apk_commit.x,
        //     apk_commit.y, 
        // ];

        let cs: ConstraintSystemRef<Fr> = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Prove{construct_matrices: true});
        let matrices: ConstraintMatrices<Fr> = cs.to_matrices().unwrap();
        let num_cons = cs.num_constraints();
        let num_vars = cs.num_witness_variables();
        let num_inputs = cs.num_instance_variables();
        
        let a_flat = flatten_vec_vec(matrices.a);
        let b_flat = flatten_vec_vec(matrices.b);
        let c_flat = flatten_vec_vec(matrices.c);
        
        let instance_assignment = cs.clone().into_inner().unwrap().instance_assignment;
        let instance_assignment_var = Assignment::<Fr>::new(&instance_assignment).unwrap();
        let witness_assignment = cs.into_inner().unwrap().witness_assignment;
        let witness_assignment_var = Assignment::<Fr>::new(&witness_assignment).unwrap();
        
        let gens = NIZKGens::<C>::new(num_cons, num_vars, num_inputs);
        // this Fq must be same as constraintsmatrices<fq> i.e. ConstraintSystemRef<Fq>
        let inst = Instance::<Fr>::new(num_cons, num_vars, num_inputs, &a_flat, &b_flat, &c_flat).unwrap();
        
        // TODO: So for NIZK<G> I just need a curve group whose scalar field = base field of bls12-381
        // and it's correct but vscode is not seeing it
        let mut prover_transcript = Transcript::new(b"nizk_example");
        let start = Instant::now();
        let proof = NIZK::<C>::prove(&inst, instance_assignment_var, &witness_assignment_var, &gens, &mut prover_transcript);
        proof_time_total += start.elapsed();

        // verify the proof of satisfiability
        let mut verifier_transcript = Transcript::new(b"nizk_example");
        let start = Instant::now();
        let verified = proof
        .verify(&inst, &witness_assignment_var, &mut verifier_transcript, &gens)
        .is_ok();
        verify_time_total += start.elapsed();
        println!("verify result: {:?}", verified);
    }
    // println!("LoggingCircuit Logistics time: {:?}", logistics_total/10);
    // println!("LoggingCircuit Setup time: {:?}", setup_total/10);
    println!("LoggingCircuit Prove time: {:?}", proof_time_total.as_millis()/10);
    println!("LoggingCircuit Verify time: {:?}", verify_time_total.as_millis()/10);
}

fn generate_insert_circuit() -> (InsertCircuit<W,C>, PublicKey) {
    println!("Generating InsertCircuit");
    let rng = &mut OsRng;
    
    // let start = Instant::now();
    let elgamal_rand = EncRand::<JubJub>::rand(rng);
    let elgamal_param = MyEnc::setup(rng).unwrap();
    let (elgamal_key, _) = MyEnc::keygen(&elgamal_param, rng).unwrap();

    let mut elgamal_key_bytes = vec![];
    elgamal_key.serialize_with_mode(&mut elgamal_key_bytes, Compress::Yes);
    println!("here4");
    /* Generate Poseidon hash parameters for both Schnorr signature (Musig2) and v_i */      // 6, 5, 8, 57, 0
    
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr> (253, 2, 8, 24, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255
    let poseidon_params = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);

    println!("here5");
    /* Assume this is previous record */
    let i_prev: u8 = 9;         // Change u8 to 
    // let mut i_prev_vec = vec![i_prev];
    
    // i_prev_vec.resize(elgamal_key_bytes.len(), 0u8);
    let mut prev_input = vec![];
    prev_input.extend_from_slice(&elgamal_key_bytes);
    prev_input.extend_from_slice(&[i_prev]);     // Later, resize i_prev and pad with 0s to support larger index numbers
    
    let mut h_prev_bytes = vec![];
    let fr_element = Fr::from_be_bytes_mod_order(&prev_input);
    // let h_cur = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(&poseidon_params, &cur_input).unwrap();
    let h_prev = CRH::<Fr>::evaluate(&poseidon_params, [fr_element]).unwrap();
    h_prev.serialize_with_mode(&mut h_prev_bytes, Compress::Yes);
    println!("here6");
    
    let i: u8 = 10;
    let mut cur_input = vec![];
    cur_input.extend_from_slice(&elgamal_key_bytes);
    cur_input.extend_from_slice(&[i]);
    let fr_element = Fr::from_be_bytes_mod_order(&cur_input);
    let h_cur = CRH::<Fr>::evaluate(&poseidon_params, [fr_element]).unwrap();

    let plaintext = JubJub::rand(rng).into_affine();
    let v_prev = MyEnc::encrypt(&elgamal_param, &elgamal_key, &plaintext, &elgamal_rand).unwrap();
    let mut v_0_bytes = vec![];    // TODO: unify length to check partition later
    // let mut v_1_bytes = vec![];
    println!("here7");
    v_prev.0.serialize_with_mode(&mut v_0_bytes, Compress::Yes).unwrap();
    
    let mut msg = vec![];
    
    // NOTE: msg ends up being 224 bytes.
    msg.extend_from_slice(&h_prev_bytes);
    msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
    v_0_bytes.clear();
    v_prev.1.serialize_with_mode(&mut v_0_bytes, Compress::Yes).unwrap();
    // msg.extend_from_slice(&v_0_y_bytes);
    msg.extend_from_slice(&v_0_bytes);
    // msg.extend_from_slice(&v_1_y_bytes);
    // println!("schnorr msg from outside: {:?}", msg);
    println!("here8");
    
    let msg2 = msg.clone();
    // let msg3 = msg.clone();
    println!("here1");
    /* AGGREGATE SCHNORR ATTEMPT - WORKS!! */

    let schnorr_param: SchnorrParameters = SchnorrParameters {
        generator: EdwardsAffine::generator(),
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

    println!("here2");
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
    println!("here3");
    // Sig should be verifiable as a standard schnorr signature
    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();

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

    let insert_circuit = InsertCircuit::<W,C> {
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
        // _curve_var: PhantomData::<GG>,
        _window_var: PhantomData::<W>,
    };

    (insert_circuit, aggregated_pubkey)
}

fn generate_insert_circuit_for_setup() -> InsertCircuit<W,C> {
        InsertCircuit::<W, C> {
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
        // _curve_var: PhantomData::<GG>,
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

// type C::Affine = ark_ec::twisted_edwards::Affine::<EdwardsConfig>;

impl<W, C> ConstraintSynthesizer<Fr> for InsertCircuit<W, C> where 
    W: ark_crypto_primitives::crh::pedersen::Window,
    // ConstraintF<C>: PrimeField,
    C: CurveGroup,
    // GG: CurveVar,
    // for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
    // Namespace<<<C as CurveGroup>::BaseField as Field>::BasePrimeField>: From<ConstraintSystemRef<Fr>>,
    C: CurveGroup<Affine = ark_ec::twisted_edwards::Affine<ark_ed25519::EdwardsConfig>>,
    <C as CurveGroup>::BaseField: PrimeField,
    <C as CurveGroup>::BaseField: ark_crypto_primitives::sponge::Absorb,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let default_affine = EdwardsAffine::default();
        let h_default = Fr::default();      // This is ConstraintF<C>
        let sig_default = Signature::default();
        // let pubkey_default = PublicKey::default();
        let schnorr_param_default: SchnorrParameters = SchnorrParameters {
            generator: default_affine,
            salt: Some([0u8;32]),
        };

        let first_login_wtns = Boolean::<Fr>::new_witness(
            cs.clone(), 
            || {Ok(self.first_login.as_ref().unwrap_or(&false))
        }).unwrap();

        /* If first login, i=0 must be true. */

        let i_wtns = UInt8::<Fr>::new_witness (
            cs.clone(),
            || {
                let i = self.i.as_ref().unwrap();
                Ok(*i)
                // [ *i ]
            }
        ).unwrap();
        
        let zero_wtns = UInt8::<Fr>::new_witness (
            cs.clone(),
            || { Ok(u8::zero()) }
        ).unwrap();

        let supposed_to_be = first_login_wtns.select(&zero_wtns, &i_wtns).unwrap();

        let supposed_to_be_wtns = UInt8::<Fr>::new_witness (
            cs.clone(),
            || {
                Ok(supposed_to_be.value().unwrap_or(u8::one()))
            }
        ).unwrap();

        i_wtns.enforce_equal(&supposed_to_be_wtns);

        let reconstructed_msg_wtns = UInt8::<Fr>::new_witness_vec(
            cs.clone(),
            &{
                let mut h_bytes = vec![];
                let h = self.h_prev.as_ref().unwrap_or(&h_default);
                h.serialize_with_mode(&mut h_bytes, Compress::Yes);
                let default_coords = (C::Affine::default(), C::Affine::default());
                let mut v_0_bytes = vec![];
                let mut v_1_bytes = vec![];
                let v: &(C::Affine, C::Affine) = self.v_prev.as_ref().unwrap_or(&default_coords);
                
                v.0.serialize_with_mode(&mut v_0_bytes, Compress::Yes).unwrap();
                v.1.serialize_with_mode(&mut v_1_bytes, Compress::Yes).unwrap();

                let mut msg: Vec<u8> = vec![];
                msg.extend_from_slice(&h_bytes);
                msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
                msg.extend_from_slice(&v_1_bytes);

                msg
            }
        ).unwrap();

        let schnorr_param_const = ParametersVar::<C>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_params.as_ref().unwrap_or(&schnorr_param_default)),
            AllocationMode::Constant,
        ).unwrap();

        /* SCHNORR SIG VERIFY GADGET */

        let (ark, mds) = find_poseidon_ark_and_mds::<Fr> (253, 2, 8, 24, 0);
        let poseidon_params_default = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);
        
        let mut poseidon_params_wtns = CRHParametersVar::<Fr>::new_variable(
            cs.clone(),
            || Ok(self.poseidon_params.as_ref().unwrap_or(&poseidon_params_default)),
            AllocationMode::Witness,
        )?;

        let schnorr_apk_input = PublicKeyVar::<C>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_apk.ok_or(SynthesisError::AssignmentMissing)?),
            AllocationMode::Input,          // NOTE: this should be witness when RP is verifying circuit
        ).unwrap();

        let schnorr_sig_wtns = SignatureVar::<C>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_sig.as_ref().unwrap_or(&sig_default)),
            AllocationMode::Witness,
        ).unwrap();

        let start = Instant::now();
        let schnorr_verified = SchnorrSignatureVerifyGadget::<C>::verify(
            cs.clone(),
            &schnorr_param_const,
            &schnorr_apk_input,
            &reconstructed_msg_wtns,
            &schnorr_sig_wtns,
            &mut poseidon_params_wtns,
        ).unwrap();
        
        let verified_select: Boolean<Fr> = first_login_wtns.select(&Boolean::TRUE, &schnorr_verified)?;

        verified_select.enforce_equal(&Boolean::TRUE)?;
        
        let mut cur_input = vec![];
        let mut elgamal_key_bytes = vec![];
        let computed_hash_wtns = UInt8::<Fr>::new_witness_vec(
            cs.clone(),
            &{
                let poseidon_params = self.poseidon_params.as_ref().unwrap_or(&poseidon_params_default);
                // let mut cur_input = vec![];
                let elgamal_key = self.elgamal_key.as_ref().unwrap_or(&default_affine);
                // let mut elgamal_key_bytes = vec![];
                elgamal_key.serialize_with_mode(&mut elgamal_key_bytes, Compress::Yes);
                cur_input.extend_from_slice(&elgamal_key_bytes);
                cur_input.extend_from_slice(&[*self.i.as_ref().unwrap_or(&0)]);
                let cur_input_fr = Fr::from_be_bytes_mod_order(&cur_input);
                let result = CRH::<Fr>::evaluate(&poseidon_params, [cur_input_fr]).unwrap();
                let mut result_vec = vec![];
                // result.clear();
                result.serialize_with_mode(&mut result_vec, Compress::Yes);
                result_vec
            },
        ).unwrap();

        cur_input.clear();
        elgamal_key_bytes.clear();
        let computed_prev_hash_wtns = UInt8::<Fr>::new_witness_vec(
            cs.clone(),
            &{
                let poseidon_params = self.poseidon_params.as_ref().unwrap_or(&poseidon_params_default);
                // let mut prev_input = vec![];
                let elgamal_key = self.elgamal_key.as_ref().unwrap_or(&default_affine);
                // let mut elgamal_key_bytes = vec![];
                elgamal_key.serialize_with_mode(&mut elgamal_key_bytes, Compress::Yes);

                let i_value = self.i.as_ref().unwrap_or(&0);
                let selected_i_prev = UInt8::<Fr>::conditionally_select(
                    &Boolean::<Fr>::constant(*i_value == 0),
                    &UInt8::<Fr>::constant(0),
                    &UInt8::<Fr>::constant(i_value.checked_sub(1).unwrap_or(0)),   // both branches run
                )?;

                cur_input.extend_from_slice(&elgamal_key_bytes);
                cur_input.extend_from_slice(&[selected_i_prev.value().unwrap()]);
                elgamal_key_bytes.clear();
                let cur_input_fr = Fr::from_be_bytes_mod_order(&cur_input);
                let result = CRH::<Fr>::evaluate(&poseidon_params, [cur_input_fr]).unwrap();
                result.serialize_with_mode(&mut elgamal_key_bytes, Compress::Yes);

                // let output = first_login_wtns.select(&elgamal_key_bytes, &elgamal_key_bytes);
                elgamal_key_bytes
            },
        ).unwrap();

        let h_cur_wtns = UInt8::<Fr>::new_witness_vec(
            cs.clone(),
            &{
                let h_cur = self.h_cur.unwrap_or(h_default);            // TODO: consider serializing outside circuit and passing u8 as input
                let mut h_cur_vec = vec![];
                h_cur.serialize_with_mode(&mut h_cur_vec, Compress::Yes);
                h_cur_vec
            },
        ).unwrap();

        let h_prev_wtns = UInt8::<Fr>::new_witness_vec(
            cs.clone(),
            &{
                let h_prev = self.h_prev.unwrap_or(h_default);            // TODO: consider serializing outside circuit and passing u8 as input
                let mut h_prev_vec = vec![];
                h_prev.serialize_with_mode(&mut h_prev_vec, Compress::Yes);
                h_prev_vec
            },
        ).unwrap();

        computed_hash_wtns.enforce_equal(&h_cur_wtns);

        let mut ouptut = vec![];
        for i in 0..computed_prev_hash_wtns.len() {
            let elem = first_login_wtns.select(&h_prev_wtns[i], &computed_prev_hash_wtns[i]).unwrap_or(UInt8::<Fr>::constant(0));
            ouptut.push(elem);
        };
        // first_login_wtns.select(&h_prev_wtns, &computed_prev_hash_wtns).unwrap();
        ouptut.enforce_equal(&h_prev_wtns);

        Ok(())
    }
}

pub struct InsertCircuit<W, C: CurveGroup> {
    pub first_login: Option<bool>,
    pub schnorr_params: Option<SchnorrParameters>,
    pub schnorr_apk: Option<C::Affine>,
    pub poseidon_params: Option<PoseidonConfig<Fr>>,
    pub schnorr_sig: Option<Signature<C>>,
    pub h_prev: Option<Fr>,           /* Record info */
    pub v_prev: Option<Ciphertext<C>>,
    pub elgamal_key: Option<PublicKey>,  
    pub h_cur: Option<Fr>,
    pub i: Option<u8>,
    // pub _curve_var: PhantomData<GG>,
    pub _window_var: PhantomData<W>,
}

pub struct LoggingCircuit<W, C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    pub schnorr_params: Option<SchnorrParameters>,
    // pub schnorr_apk: Option<Affine<EdwardsConfig>>,
    pub schnorr_apk: Option<PublicKey>,
    pub apk_commit_x: Option<Fq>,
    pub apk_commit_y: Option<Fq>,
    pub pedersen_rand: Option<PedersenRandomness<C>>,
    pub pedersen_params: Option<PedersenParameters<C>>,
    pub poseidon_params: Option<PoseidonConfig<Fr>>,
    pub schnorr_sig: Option<Signature<C>>,
    pub record_x: Option<Fq>,
    pub record_y: Option<Fq>,
    pub elgamal_rand: Option<EncRand<C>>,
    pub elgamal_params: Option<EncParams<C>>,
    pub pedersen_rand_elgamal: Option<PedersenRandomness<C>>,
    pub elgamal_key_commit_x: Option<Fq>,
    pub elgamal_key_commit_y: Option<Fq>,
    pub v_cur: Option<Ciphertext<C>>,
    pub elgamal_key: Option<EncPubKey<C>>,
    pub h_cur: Option<Fr>,
    pub i: Option<u8>,
    pub _curve_var: PhantomData<GG>,
    pub _window_var: PhantomData<W>,
}

impl<W, C, GG> ConstraintSynthesizer<Fr> for LoggingCircuit<W, C, GG> where 
    W: ark_crypto_primitives::crh::pedersen::Window,
    ConstraintF<C>: PrimeField,
    C: CurveGroup,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
    Namespace<<<C as CurveGroup>::BaseField as Field>::BasePrimeField>: From<ConstraintSystemRef<Fr>>,
    C: CurveGroup<Affine = ark_ec::twisted_edwards::Affine<ark_ed25519::EdwardsConfig>>,
    <<C as CurveGroup>::BaseField as Field>::BasePrimeField: ark_crypto_primitives::sponge::Absorb,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> { 
        let affine_default = C::Affine::default();
        let sig_default = Signature::<C>::default();
        let schnorr_param_default = SchnorrParameters {
            generator: EdwardsAffine::default(),
            salt: Some([0u8; 32]),
        };
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr> (255, 2, 8, 24, 0);
        let poseidon_params_default = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);
        let pedersen_rand_default = PedersenRandomness::<C>::default();
        let pedersen_param_default = PedersenParameters::<C> {
            randomness_generator: vec![],
            generators: vec![vec![];16],        // NUM_WINDOWS=16 hardcoded
        };

        let mut cur_input = vec![];
        let mut elgamal_key_bytes = vec![];

        println!("logging1");
        /* Check h_i hashes correct Elgamal key. */
        let computed_hash_wtns = UInt8::<Fr>::new_witness_vec(
            cs.clone(),
            &{
                let poseidon_params = self.poseidon_params.as_ref().unwrap_or(&poseidon_params_default);
                let elgamal_key = self.elgamal_key.as_ref().unwrap_or(&affine_default);
                elgamal_key.serialize_with_mode(&mut elgamal_key_bytes, Compress::Yes);
                cur_input.extend_from_slice(&elgamal_key_bytes);
                cur_input.extend_from_slice(&[*self.i.as_ref().unwrap_or(&0)]);
                let cur_input_fr = Fr::from_be_bytes_mod_order(&cur_input);
                let result = CRH::<Fr>::evaluate(&poseidon_params, [cur_input_fr]).unwrap();
                let mut result_vec = vec![];
                result.serialize_with_mode(&mut result_vec, Compress::Yes);
                result_vec
            },
        ).unwrap();

        let h_cur_wtns = UInt8::<Fr>::new_witness_vec(
            cs.clone(),
            &{
                let h_cur = self.h_cur.unwrap_or(Fr::default());            // TODO: consider serializing outside circuit and passing u8 as input
                let mut h_cur_vec = vec![];
                h_cur.serialize_with_mode(&mut h_cur_vec, Compress::Yes);
                h_cur_vec
            },
        ).unwrap();

        computed_hash_wtns.enforce_equal(&h_cur_wtns);

        println!("logging2");
        /* Check elgamal key commitment */
        let elgamal_commit_x = self.elgamal_key_commit_x.unwrap_or(Fq::one());
        let elgamal_commit_y = self.elgamal_key_commit_y.unwrap_or(Fq::one());
        
        let elgamal_commit_proj = C::from(C::Affine::new_unchecked(elgamal_commit_x, elgamal_commit_y));       // THIS IS TWISTED EDWARDS

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
                pubkey.serialize_with_mode(&mut h_vec[..], Compress::Yes).unwrap();
            
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
                    generators: parameters.generators.clone(),
                };
                let mut result: C = ark_crypto_primitives::crh::pedersen::CRH::<C,W>::evaluate(&crh_parameters, input).unwrap().into();

                // Compute h^r.
                for (bit, power) in BitIteratorLE::new(randomness.0.into_bigint())
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

        println!("logging3");
        commit_input.enforce_equal(&reconstructed_commit_var);
        
        // println!("time commit {:?}", end);

        let default_coords = (C::Affine::default(), C::Affine::default());
        println!("C::Affine::default() {:?}", C::Affine::default());
        let v_cur_wtns = ElgamalCiphertextVar::<C,GG>::new_variable (
            cs.clone(),
            || Ok(self.v_cur.as_ref().unwrap_or(&default_coords)),
            AllocationMode::Witness,
        ).unwrap();

        /* Check encryption of correct context (using correct Elgamal key) */
        // let default_rand = EncRand::<C>(C::ScalarField::one());
        // let default_param = EncParams::<C>{generator: C::Affine::default()};
        // let default_param = EncParams::<C>{ generator: C::Affine::default() };
        let reconstructed_v_cur_wtns = ElgamalCiphertextVar::<C,GG>::new_variable (
            cs.clone(),
            || {
                let record_x = self.record_x.as_ref().unwrap();
                let record_y = self.record_y.as_ref().unwrap();
                println!("record x {:?}", record_x);
                println!("record y {:?}", record_y);
                // println!("GroupAffine::<ark_ed_on_bn254::EdwardsParameters>::new(*record_x, *record_y).into() {:?}", GroupAffine::<ark_ed_on_bn254::EdwardsParameters>::new(*record_x, *record_y));
                // let test: GroupProjective::<ark_ed_on_bn254::EdwardsParameters> = GroupAffine::<ark_ed_on_bn254::EdwardsParameters>::new(*record_x, *record_y).into();
                // println!("test {:?}", test);
                let record_input: C::Affine = ark_ec::twisted_edwards::Affine::<EdwardsConfig>::new_unchecked(*record_x, *record_y);

                let elgamal_param_input = self.elgamal_params.as_ref().unwrap();
                let pubkey = self.elgamal_key.as_ref().unwrap();
                let elgamal_rand = self.elgamal_rand.as_ref().unwrap();
                println!("logging3-1");
                
                let ciphertext: (C::Affine, C::Affine) = ElGamal::<C>::encrypt(elgamal_param_input, pubkey, &record_input, elgamal_rand).unwrap();
                // let test1: (GroupAffine::<EdwardsParameters>, GroupAffine::<EdwardsParameters>) = ciphertext.into();
                println!("default affine {:?}", C::Affine::default());
                println!("logging3-2");
                println!("ciphertext.0 {:?}", ciphertext.0);
                println!("ciphertext.1 {:?}", ciphertext.1);
                // let test: GroupProjective::<ark_ed_on_bn254::EdwardsParameters> = GroupAffine::<ark_ed_on_bn254::EdwardsParameters>::new(ciphertext.0, ciphertext.0).into();
                // println!("test {:?}", test);
                Ok((ciphertext.0, ciphertext.1))
            },
            AllocationMode::Witness,
        ).unwrap();

        println!("logging4");
        v_cur_wtns.enforce_equal(&reconstructed_v_cur_wtns);

        /* Check aggregated signature */

        let reconstructed_msg_wtns = UInt8::<Fr>::new_witness_vec(
            cs.clone(),
            &{
                let mut h_bytes = vec![];
                let default = Fr::default();
                let h = self.h_cur.as_ref().unwrap_or(&default);
                h.serialize_with_mode(&mut h_bytes, Compress::Yes);
                let default_coords = (C::Affine::default(), C::Affine::default());
                let mut v_0_bytes = vec![];
                let mut v_1_bytes = vec![];
                let v: &(C::Affine, C::Affine) = self.v_cur.as_ref().unwrap_or(&default_coords);
                
                v.0.serialize_with_mode(&mut v_0_bytes, Compress::Yes).unwrap();
                v.1.serialize_with_mode(&mut v_1_bytes, Compress::Yes).unwrap();

                let mut msg: Vec<u8> = vec![];
                msg.extend_from_slice(&h_bytes);
                msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
                msg.extend_from_slice(&v_1_bytes);

                // println!("reconstructed msg {:?}", msg);
                msg
            }
        ).unwrap();

        // let start = Instant::now();
        
        println!("logging5");
        let schnorr_param_const = ParametersVar::<C>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_params.as_ref().unwrap_or(&schnorr_param_default)),
            AllocationMode::Constant,
        ).unwrap();

        /* SCHNORR SIG VERIFY GADGET */
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr> (255, 2, 8, 24, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255
        let poseidon_params = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);
        
        let mut poseidon_params_wtns = CRHParametersVar::<Fr>::new_variable(
            cs.clone(),
            || Ok(self.poseidon_params.as_ref().unwrap_or(&poseidon_params_default)),
            AllocationMode::Witness,
        )?;

        let schnorr_apk_input = PublicKeyVar::<C>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_apk.as_ref().unwrap_or(&affine_default)),
            AllocationMode::Input,          // NOTE: this should be witness when RP is verifying circuit
        ).unwrap();

        let schnorr_sig_wtns = SignatureVar::<C>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_sig.as_ref().unwrap_or(&sig_default)),
            AllocationMode::Witness,
        ).unwrap();

        let schnorr_verified = SchnorrSignatureVerifyGadget::<C>::verify(
            cs.clone(),
            &schnorr_param_const,
            &schnorr_apk_input,
            &reconstructed_msg_wtns,
            &schnorr_sig_wtns,
            &mut poseidon_params_wtns,
        ).unwrap();
        println!("logging6");

        schnorr_verified.enforce_equal(&Boolean::TRUE)?;
        
        /* Check that the schnorr_apk provided is the apk committed to at registration and given to RP. */

        let apk_commit_x = self.apk_commit_x.unwrap_or(Fq::one());
        let apk_commit_y = self.apk_commit_y.unwrap_or(Fq::one());
        
        // println!("here2");
        let apk_commit_proj = C::from(EdwardsAffine::new_unchecked(apk_commit_x, apk_commit_y).into());       // THIS IS TWISTED EDWARDS
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
                let apk = self.schnorr_apk.as_ref().unwrap_or(&affine_default);
                apk.serialize_with_mode(&mut h_vec[..], Compress::Yes).unwrap();

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
                let mut result: C = ark_crypto_primitives::crh::pedersen::CRH::<C,W>::evaluate(&crh_parameters, input).unwrap().into();

                // Compute h^r.
                for (bit, power) in BitIteratorLE::new(randomness.0.into_bigint())
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
        println!("logging7");
        // println!("time 5 {:?}", end);
    
        // println!("last in generate constraints");
        Ok(())
    }
}

fn flatten_vec_vec (
    input: Vec<Vec<(Fr, usize)>>
) -> Vec<(usize, usize, Fr)> {
    // Flatten and map the vectors
    let mut result = input.into_iter()
        .enumerate()
        .flat_map(|(i, inner_vec)| {
            inner_vec.into_iter().enumerate().map(move |(j, (fp, usize_val))| {
                (i, usize_val, fp) // Reordering the tuple elements
            })
        })
        .collect::<Vec<_>>();

    result.shrink_to_fit(); // Make sure the vector uses the exact memory size needed
    result
}
