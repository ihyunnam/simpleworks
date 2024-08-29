// use ark_crypto_primitives_04::sponge::poseidon::*;
use ark_crypto_primitives::crh::{CRH as CRHTrait, CRHGadget as CRHGadgetTrait};
use ark_crypto_primitives::crh::poseidon::sbox::PoseidonSbox;
use ark_crypto_primitives::crh::poseidon::PoseidonRoundParams;
use ark_crypto_primitives::crh::poseidon::{CRH , Poseidon, constraints::{PoseidonRoundParamsVar, CRHGadget, find_poseidon_ark_and_mds}};
// use ark_crypto_primitives::CRH;
use ark_r1cs_std::fields::fp::FpVar;
use simpleworks::schnorr_signature::schnorr_signature_verify_gadget::SigVerifyGadget;
use simpleworks::schnorr_signature::SimpleSchnorrSignatureVar;
use std::borrow::Borrow;
use std::convert::TryInto;

// THIS IS WITHOUT AGGREGATE SCHNORR AND PUBLIC INPUTS
// PASSES CORRECT INPUTS FOR BOTH FIRST-TIME AND RETURNING USERS
// (AS REQUIRED) FAILS WRONG INPUTS
mod commit;
// use ark_crypto_primitives::crh::poseidon::constraints::PoseidonRoundParamsVar;
use bitvec::view::AsBits;
// use ark_crypto_primitives::crh::pedersen::Window;
use commit::{CommGadget, RandomnessVar as PedersenRandomnessVar, ParametersVar as PedersenParametersVar};
use ark_ec::bls12::Bls12Parameters;
// use ark_crypto_primitives::crh::{CRH};
use simpleworks::schnorr_signature::schnorr::MyPoseidonParams;
// use simpleworks::schnorr_signature::blake2s::{ROGadget, RandomOracleGadget};
// use simpleworks::schnorr_signature::schnorr_signature_verify_gadget::SigVerifyGadget;
// use simpleworks::schnorr_signature::Blake2sParametersVar;
use std::io::Cursor;
use std::ops::Mul;
use ark_relations::r1cs::Namespace;
use ark_std::Zero;
// use ark_crypto_primitives::crh::poseidon::{Poseidon, PoseidonRoundParams};
// use ark_crypto_primitives::signature::SigVerifyGadget;
// use ark_crypto_primitives::{Error, SignatureScheme};
use ark_ec::twisted_edwards_extended::{GroupAffine, GroupProjective};
use ark_ec::{AffineCurve, ModelParameters, PairingEngine, ProjectiveCurve};
use ark_ed_on_bls12_381::EdwardsParameters;
use ark_ff::{to_bytes, BigInteger, BigInteger256, BitIteratorLE, Fp256, One, PrimeField};
// use ark_ec::{ProjectiveCurve};
use ark_ff::{
    bytes::{FromBytes, ToBytes},
    fields::{Field},
    UniformRand,
};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    prelude::*,
    ToConstraintFieldGadget,
};
// use digest::typenum::Zero;
use tracing_subscriber::layer::SubscriberExt;
use std::{time::Instant, result::Result};
use ark_std::vec::Vec;
use rand::RngCore;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use rand::rngs::OsRng;
use ark_groth16::Groth16;
// use std::borrow::Borrow;
use simpleworks::schnorr_signature::
    {schnorr::{Schnorr, Parameters, PublicKey, Signature, KeyAggContext, FirstRound, SecondRound, PubNonce, PartialSignature},
    schnorr_signature_verify_gadget::SchnorrSignatureVerifyGadget,
    public_key_var::PublicKeyVar,
    parameters_var::ParametersVar,
    signature_var::SignatureVar,
};

use ark_crypto_primitives::{
    commitment::{pedersen::{
     Commitment, Randomness as PedersenRandomness, Parameters as PedersenParameters},
        CommitmentGadget, CommitmentScheme},
    encryption::{elgamal::{constraints::{ElGamalEncGadget, OutputVar as ElgamalCiphertextVar, ParametersVar as ElgamalParametersVar, PlaintextVar, PublicKeyVar as ElgamalPublicKeyVar, RandomnessVar as ElgamalRandomnessVar}, Ciphertext, ElGamal, Parameters as EncParams, PublicKey as EncPubKey, Randomness as EncRand},
        AsymmetricEncryptionGadget, AsymmetricEncryptionScheme},
    prf::{blake2s::{constraints::{Blake2sGadget, OutputVar as PrfOutputVar}, Blake2s}, PRFGadget, PRF},
    signature::{SignatureScheme},
};
use ark_relations::r1cs::{ConstraintSystem, ConstraintLayer, SynthesisError, ConstraintSynthesizer, ConstraintSystemRef, SynthesisMode, TracingMode::{All, OnlyConstraints}};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub};   // Fq2: finite field, JubJub: curve group
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

pub struct InsertCircuit<W, C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>> {
    first_login: Option<bool>,
    schnorr_params: Option<Parameters<C>>,
    schnorr_apk: Option<C::Affine>,
    // apk_commit_x: Option<ark_ff::Fp256<ark_bls12_381::FrParameters>>,
    // apk_commit_y: Option<ark_ff::Fp256<ark_bls12_381::FrParameters>>,
    // pedersen_rand: Option<PedersenRandomness<C>>,
    // pedersen_params: Option<PedersenParameters<C>>,
    poseidon_params: Option<Poseidon::<ConstraintF<C>, MyPoseidonParams>>,
    schnorr_sig: Option<Signature<C>>,
    h_prev: Option<ConstraintF<C>>,           /* Record info */
    v_prev: Option<Ciphertext<C>>,
    elgamal_key: Option<EncPubKey<C>>,  
    h_cur: Option<ConstraintF<C>>,
    i: Option<u8>,
    _curve_var: PhantomData<GG>,
    _window_var: PhantomData<W>,
}

impl<W, C, GG> ConstraintSynthesizer<Fr> for InsertCircuit<W, C, GG> where 
    W: ark_crypto_primitives::crh::pedersen::Window,
    ConstraintF<C>: PrimeField,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
    <C as ProjectiveCurve>::Affine: From<ark_ec::twisted_edwards_extended::GroupAffine<EdwardsParameters>>,
    Namespace<<<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField>: From<ConstraintSystemRef<Fr>>,
    <C as ProjectiveCurve>::BaseField: PrimeField,
    // Vec<u8>: Borrow<<C as ProjectiveCurve>::BaseField>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let affine_default = C::Affine::default();
        let h_default = ConstraintF::<C>::default();
        let default_sig = Signature::default();
        let default_pubkey = PublicKey::<C>::default();
        let default_schnorr_param: Parameters<C> = Parameters::<C> {
            generator: <C as ProjectiveCurve>::Affine::default(),
            salt: Some([0u8;32]),
        };

        let first_login_wtns = Boolean::<ConstraintF<C>>::new_witness(cs.clone(), || {
            Ok(self.first_login.as_ref().unwrap_or(&false))
        }).unwrap();

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
            || Ok(self.schnorr_params.as_ref().unwrap_or(&default_schnorr_param)),
            AllocationMode::Constant,
        ).unwrap();

        /* SCHNORR SIG VERIFY GADGET */
        let default_poseidon_params = Poseidon::<ConstraintF<C>, MyPoseidonParams> {
            params: MyPoseidonParams::default(),
            round_keys: vec![<ConstraintF<C>>::zero();455],            // 6 = width hardcoded
            mds_matrix: vec![vec![<ConstraintF<C>>::zero();6];6],
        };
        
        let mut poseidon_params_wtns = PoseidonRoundParamsVar::<ConstraintF<C>, MyPoseidonParams>::new_variable(
            cs.clone(),
            || Ok(self.poseidon_params.as_ref().unwrap_or(&default_poseidon_params)),
            AllocationMode::Witness,
        )?;

        let schnorr_apk_input = PublicKeyVar::<C, GG>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_apk.as_ref().unwrap_or(&default_pubkey)),
            AllocationMode::Input,          // NOTE: this should be witness when RP is verifying circuit
        ).unwrap();

        let schnorr_sig_wtns = SignatureVar::<C, GG>::new_variable(
            cs.clone(),
            || Ok(self.schnorr_sig.as_ref().unwrap_or(&default_sig)),
            AllocationMode::Witness,
        ).unwrap();

        // let end = start.elapsed();
        // println!("Various variable declaration {:?}", end);
        let start = Instant::now();
        let schnorr_verified = SchnorrSignatureVerifyGadget::<C,GG>::verify(
            cs.clone(),
            &schnorr_param_const,
            &schnorr_apk_input,
            &reconstructed_msg_wtns,
            &schnorr_sig_wtns,
            &mut poseidon_params_wtns,
        ).unwrap();

        let end = start.elapsed();
        println!("Schnorr verify time {:?}", end);
        
        let verified_select: Boolean<ConstraintF<C>> = first_login_wtns.select(&Boolean::TRUE, &schnorr_verified)?;

        verified_select.enforce_equal(&Boolean::TRUE)?;
        
        let mut cur_input = vec![];
        let mut elgamal_key_bytes = vec![];
        let computed_hash_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(
            cs.clone(),
            &{
                let poseidon_params = self.poseidon_params.as_ref().unwrap_or(&default_poseidon_params);
                // let mut cur_input = vec![];
                let elgamal_key = self.elgamal_key.as_ref().unwrap_or(&affine_default);
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
                let poseidon_params = self.poseidon_params.as_ref().unwrap_or(&default_poseidon_params);
                // let mut prev_input = vec![];
                let elgamal_key = self.elgamal_key.as_ref().unwrap_or(&affine_default);
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

        computed_hash_wtns.enforce_equal(&h_cur_wtns);
        computed_prev_hash_wtns.enforce_equal(&h_prev_wtns);

        Ok(())
    }
}

fn main() {
    println!("Entering main.");
    let rng = &mut OsRng;
        
    let start = Instant::now();
    let elgamal_rand = EncRand::<JubJub>::rand(rng);
    let elgamal_param = MyEnc::setup(rng).unwrap();
    let (elgamal_key, _) = MyEnc::keygen(&elgamal_param, rng).unwrap();

    /* Generate Poseidon hash parameters for both Schnorr signature (Musig2) and v_i */      // 6, 5, 8, 57, 0
    
    let (ark, mds) = find_poseidon_ark_and_mds::<ConstraintF<C>> (255, 6, 8, 57, 0);        // ark_bls12_381::FrParameters::MODULUS_BITS = 255
    let poseidon_params = Poseidon::<ConstraintF<C>, MyPoseidonParams> {
        params: MyPoseidonParams::default(),
        round_keys: ark.into_iter().flatten().collect(),
        mds_matrix: mds,
    };

    /* Assume this is previous record */
    let i_prev: u8 = 9;         // Change u8 to 
    // let mut i_prev_vec = vec![i_prev];
    let mut elgamal_key_bytes = vec![];
    elgamal_key.serialize(&mut elgamal_key_bytes);
    // i_prev_vec.resize(elgamal_key_bytes.len(), 0u8);
    let mut prev_input = vec![];
    prev_input.extend_from_slice(&elgamal_key_bytes);
    prev_input.extend_from_slice(&[i_prev]);     // Later, resize i_prev and pad with 0s to support larger index numbers
    
    let mut h_prev_bytes = vec![];
    let h_prev = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(&poseidon_params, &prev_input).unwrap();
    h_prev.serialize(&mut h_prev_bytes);

    let i: u8 = 10;
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

    let schnorr_param = Parameters::<C> {
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
    
    /* RESUMES NON-AGGREGATE CODE. */
    
    // let schnorr_verified = Schnorr::<C>::verify(&schnorr_param, &aggregated_pubkey, &msg3, &last_sig).unwrap();
    // println!("schnorr verified outside circuit {:?}", schnorr_verified);

    // let mut aggregated_pubkey_bytes = vec![];
    // aggregated_pubkey.serialize(&mut aggregated_pubkey_bytes);

    /* Commit to aggregated_pubkey and give it to RP. */
    // let pedersen_randomness = PedersenRandomness(<JubJub as ProjectiveCurve>::ScalarField::rand(rng));
    // let pedersen_params = Commitment::<JubJub, Window>::setup(rng).unwrap();
    // let apk_commit: GroupAffine<EdwardsParameters> = Commitment::<JubJub, Window>::commit(&pedersen_params, &aggregated_pubkey_bytes, &pedersen_randomness).unwrap();
    // THIS IS TWISTED EDWARDS

    let end = start.elapsed();
    println!("User and log generate variables: {:?}", end);
    // let mut result = [0u64; 4]; // Array to hold the 8 resulting i32 values

    let insert_circuit_for_setup = InsertCircuit::<W, C, GG> {
        first_login: None,
        schnorr_params: None,
        schnorr_apk: None,
        // apk_commit_x: Some(apk_commit.x),
        // apk_commit_y: Some(apk_commit.y),
        // pedersen_params: None,
        // pedersen_rand: None,
        poseidon_params: None,
        schnorr_sig: None,
        h_prev: None,
        v_prev: None,
        elgamal_key: None,
        h_cur: None,
        i: None,
        _curve_var: PhantomData::<GG>,
        _window_var: PhantomData::<W>,
    };

    let start = Instant::now();
    // println!("before setup");
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(insert_circuit_for_setup, rng).unwrap();
    // println!("after setup");
    
    // let setup_time = start.elapsed();

    // println!("Setup time: {:?}", setup_time.as_millis());

    // let start = Instant::now();
    let pvk: ark_groth16::PreparedVerifyingKey<E> = Groth16::<E>::process_vk(&vk).unwrap();
    // println!("LENGTH:");
    // println!("{}", pvk.vk.gamma_abc_g1.len());
    let vk_time = start.elapsed();
    println!("Setup time: {:?}", vk_time.as_millis());

    // let returning_user_circuit = InsertCircuit::<W,C,GG> {
    //     first_login: Some(true),
    //     schnorr_params: None,
    //     schnorr_apk: None,
    //     apk_commit_x: Some(apk_commit.x),
    //     apk_commit_y: Some(apk_commit.y),
    //     pedersen_params:  None,
    //     pedersen_rand: None,
    //     schnorr_sig: None,
    //     h_prev: None,
    //     v_prev:  None,
    //     prf_key: Some(prf_key),
    //     h_cur: Some(h_cur),
    //     i: Some(i),
    //     _curve_var: PhantomData::<GG>,
    //     _window_var: PhantomData::<W>,
    // };


    let returning_user_circuit = InsertCircuit::<W,C,GG> {
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

    let start = Instant::now();
    
    let proof = Groth16::<E>::prove(
        &pk,
        returning_user_circuit,
        rng
    ).unwrap();
    let proof_time = start.elapsed();

    println!("Prove time: {:?}", proof_time.as_millis());

    let public_inputs = [      // THESE ARE JUST FIELD ELEMENTS, NEITHER TE NOR SW
        aggregated_pubkey.x,
        aggregated_pubkey.y
    ];

    let start = Instant::now();
    let verified = Groth16::<E>::verify_with_processed_vk(
        &pvk,
        &public_inputs,        // NOTE: No public inputs for new users (because they weren't supplied for prove phase)
        &proof,
    );
    let verify_time = start.elapsed();
    println!("Verify time: {:?}", verify_time.as_millis());

    println!("{:?}", verified);
}
