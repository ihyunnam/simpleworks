use ark_crypto_primitives_04::sponge::poseidon::*;
use ark_crypto_primitives::crh::CRHGadget as CRHGadgetTrait;
use ark_crypto_primitives::crh::poseidon::sbox::PoseidonSbox;
use ark_crypto_primitives::crh::poseidon::PoseidonRoundParams;
use ark_crypto_primitives::crh::poseidon::{Poseidon, constraints::{PoseidonRoundParamsVar, CRHGadget}};
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
use ark_crypto_primitives::crh::CRH;
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
use ark_ff::{BigInteger, BigInteger256, BitIteratorLE, Fp256, One};
// use ark_ec::{ProjectiveCurve};
use ark_ff::{
    // bytes::{FromBytes, ToBytes},
    fields::Field,
    UniformRand,
};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    prelude::*
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
    // schnorr_signature_verify_gadget::SchnorrSignatureVerifyGadget,
    public_key_var::PublicKeyVar,
    parameters_var::ParametersVar,
    signature_var::SignatureVar,
};

// TODO: change blake2s in simpleworks (schnorr) to poseidon for performance
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
    apk_commit_x: Option<ark_ff::Fp256<ark_bls12_381::FrParameters>>,
    apk_commit_y: Option<ark_ff::Fp256<ark_bls12_381::FrParameters>>,
    pedersen_rand: Option<PedersenRandomness<C>>,
    pedersen_params: Option<PedersenParameters<C>>,
    poseidon_params: Option<Poseidon<ConstraintF<C>, MyPoseidonParams>>,
    schnorr_sig: Option<Signature<C>>,
    h_prev: Option<[u8;32]>,           /* Record info */
    v_prev: Option<Ciphertext<C>>,
    prf_key: Option<[u8;32]>,  
    h_cur: Option<[u8;32]>,
    i: Option<u8>,
    _curve_var: PhantomData<GG>,
    _window_var: PhantomData<W>,
}

impl<W, C, GG> ConstraintSynthesizer<Fr> for InsertCircuit<W, C, GG> where 
    W: ark_crypto_primitives::crh::pedersen::Window,
    ConstraintF<C>: ark_ff_04::PrimeField,
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: ark_r1cs_std::groups::GroupOpsBounds<'a, C, GG>,
    <C as ProjectiveCurve>::Affine: From<ark_ec::twisted_edwards_extended::GroupAffine<EdwardsParameters>>,
    Namespace<<<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField>: From<ConstraintSystemRef<Fr>>,
    
{
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let start = Instant::now();
        let prf_key_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(
            cs.clone(),
            self.prf_key.as_ref().unwrap_or(&[0u8;32])
        ).unwrap();

        // let h_cur: Vec<UInt8::<ConstraintF<C>>> = self.h_cur.as_ref().unwrap_or(&[0u8;32]).to_vec();
        // let h_cur_wtns = PrfOutputVar(h_cur);
        let h_cur_wtns = PrfOutputVar::<ConstraintF<C>>::new_variable(  // Vec<Uint8<ConstraintF<C>>>
            cs.clone(),
            || Ok(self.h_cur.as_ref().unwrap_or(&[0u8;32])),
            AllocationMode::Witness,
        ).unwrap();

        let first_login_wtns = Boolean::<ConstraintF<C>>::new_witness(cs.clone(), || {
            Ok(self.first_login.as_ref().unwrap_or(&false))
        }).unwrap();

        // println!("FIRST LOGIN WTNS {:?}", first_login_wtns.value());

        let reconstructed_msg_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(
            cs.clone(),
            &{
                let h = self.h_prev.as_ref().unwrap_or(&[0u8;32]);

                let default_coords = (<C as ProjectiveCurve>::Affine::default(), <C as ProjectiveCurve>::Affine::default());
                let mut v_0_bytes = vec![];
                let mut v_1_bytes = vec![];
                let v: &(<C as ProjectiveCurve>::Affine, <C as ProjectiveCurve>::Affine) = self.v_prev.as_ref().unwrap_or(&default_coords);
                
                v.0.serialize(&mut v_0_bytes).unwrap();
                v.1.serialize(&mut v_1_bytes).unwrap();

                let mut msg: Vec<u8> = vec![];
                msg.extend_from_slice(h);
                msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
                msg.extend_from_slice(&v_1_bytes);

                msg
            }
        ).unwrap();
        let end = start.elapsed();
        println!("time 1 {:?}", end);

        let start = Instant::now();
        let default_schnorr_param: Parameters<C> = Parameters::<C> {
            generator: <C as ProjectiveCurve>::Affine::default(),
            salt: Some([0u8;32]),
        };

        let default_sig = Signature::default();
        let default_pubkey = PublicKey::<C>::default();

        let verifier_challenge_wtns = UInt8::<ConstraintF<C>>::new_witness_vec (
            cs.clone(),
            &{
                let signature = self.schnorr_sig.as_ref().unwrap_or(&default_sig);
                signature.verifier_challenge
            }
        ).unwrap();

        let mut hash_var: Vec<UInt8<ConstraintF<C>>> = verifier_challenge_wtns.clone();

        let end = start.elapsed();
        println!("time before verify {:?}", end);
        let verification_point_wtns = UInt8::<ConstraintF<C>>::new_witness_vec (
            cs.clone(),
            &{
                let start = Instant::now();
                let signature = self.schnorr_sig.as_ref().unwrap_or(&default_sig);
                
                let pubkey_affine = self.schnorr_apk.as_ref().unwrap_or(&default_pubkey);
                let prover_response = signature.prover_response.clone();
                // let verifier_challenge = signature.verifier_challenge.clone();
                let parameters = self.schnorr_params.unwrap_or(default_schnorr_param);
                let end = start.elapsed();
                println!("verify 1 {:?}", end);
                
                let start = Instant::now();
                let mut agg_pubkey_serialized = [0u8; 32];
                pubkey_affine.serialize(&mut agg_pubkey_serialized[..]);
                let agg_pubkey_wtns = UInt8::<ConstraintF<C>>::new_witness_vec (
                    cs.clone(),
                    &agg_pubkey_serialized,
                ).unwrap();
                hash_var.extend(agg_pubkey_wtns);
                hash_var.extend(reconstructed_msg_wtns);
                let end = start.elapsed();
                println!("verify 2 {:?}", end);
                // println!("hash_var {:?}", hash_var.value());
                let start = Instant::now();
                // let b2s_params: Blake2sParametersVar = <Blake2sParametersVar as AllocVar<_, ConstraintF<C>>>::new_constant(
                //     ConstraintSystemRef::None,
                //     (),
                // )?;

                let poseidon_params = PoseidonRoundParamsVar::<ConstraintF<C>, MyPoseidonParams>::new_variable(
                    cs.clone(),
                    || Ok(self.poseidon_params.unwrap_or(Poseidon::<ConstraintF<C>, MyPoseidonParams>::default())),
                    AllocationMode::Witness,
                )?;

                let hash = CRHGadget::evaluate(&poseidon_params, &hash_var)?;
                let end = start.elapsed();
                println!("verify 3 {:?}", end);
                let start = Instant::now();

                // let mut vector = vec![];
                // hash.serialize(&mut vector);

                let hash: Vec<u8> = hash.to_bytes().unwrap_or_default()
                .into_iter()
                .map(|el| el.value().unwrap())
                .collect();

                let e = C::ScalarField::from_be_bytes_mod_order(hash.as_slice());
                
                let verification_point = parameters.generator.mul(prover_response).sub(pubkey_affine.mul(e));
                let mut verification_point_bytes: Vec<u8> = vec![];
                verification_point.serialize(&mut verification_point_bytes);
                let end = start.elapsed();
                println!("verify 4 {:?}", end);
                verification_point_bytes
            }
        ).unwrap();
        
        // Dummy return value
        let schnorr_verified = verification_point_wtns.is_eq(&verifier_challenge_wtns)?;

        let end = start.elapsed();
        println!("time schnorr verify {:?}", end);

        let start = Instant::now();
        // println!("SCHNORR VERIFY AT NONE {:?}", schnorr_verified.value());      // Err(AssignmentMissing if ingredients are [0] and stuff)
        let verified_select: Boolean<ConstraintF<C>> = first_login_wtns.select(&Boolean::TRUE, &schnorr_verified)?;
        // TODO: move enforce equal into verify() and have only one?

        // println!("VERIFIED SELECT (should be true) {:?}", verified_select.value());
        verified_select.enforce_equal(&Boolean::TRUE)?;
        
        /* Check that the schnorr_apk provided is the apk committed to at registration and given to RP. */

        let apk_commit_x: Fp256<ark_bls12_381::FrParameters> = self.apk_commit_x.ok_or(SynthesisError::AssignmentMissing)?;
        let apk_commit_y: Fp256<ark_bls12_381::FrParameters> = self.apk_commit_y.ok_or(SynthesisError::AssignmentMissing)?;
        
        let apk_commit_proj = C::from(GroupAffine::<ark_ed_on_bls12_381::EdwardsParameters>::new(apk_commit_x, apk_commit_y).into());       // THIS IS TWISTED EDWARDS
        println!("APK COMMIT PROJ {:?}", apk_commit_proj);
        let reconstructed_commit_var = GG::new_variable_omit_prime_order_check( // VERIFY USED TO FAIL BUT PASSES NOW
            cs.clone(),
            || Ok(apk_commit_proj),
            AllocationMode::Input,
        ).unwrap();

        println!("reconstructed_commit_var {:?}", reconstructed_commit_var.value());

        let end = start.elapsed();
        println!("time 3 {:?}", end);

        let start = Instant::now();
        let commit_wtns = GG::new_variable_omit_prime_order_check( // VERIFY USED TO FAIL BUT PASSES NOW
            cs.clone(),
            || {
                let default_rand = PedersenRandomness::default();
                let default_param = PedersenParameters::<C> {
                    randomness_generator: vec![],
                    generators: vec![vec![];16],        // NUM_WINDOWS=16 hardcoded
                };
                let parameters = self.pedersen_params.as_ref().unwrap_or(&default_param);
                let randomness = self.pedersen_rand.as_ref().unwrap_or(&default_rand);

                // let pedersen_randomness = PedersenRandomnessVar::<ConstraintF<C>>::new_variable(
                //     cs.clone(),
                //     || Ok(randomness),
                //     AllocationMode::Witness,
                // ).unwrap();

                // let pedersen_params = PedersenParametersVar::<C,GG>::new_variable(
                //     cs.clone(),
                //     || Ok(parameters),
                //     AllocationMode::Constant,
                // ).unwrap();

                let mut h_vec = vec![0u8; 32];  // Vec<u8> avoids lifetime issues
                let schnorr_apk_var = UInt8::<ConstraintF<C>>::new_witness_vec (
                    cs.clone(),
                    &{   
                        let apk = self.schnorr_apk.as_ref().unwrap_or(&default_pubkey);
                        apk.serialize(&mut h_vec[..]).unwrap();

                        h_vec
                    }
                ).unwrap();
                let input = schnorr_apk_var.value().unwrap_or(vec![]);
                
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
        let end = start.elapsed();
        println!("time commit {:?}", end);

        // let computed_commit = CommGadget::<C,GG,Window>::commit(&pedersen_params, &schnorr_apk_var, &pedersen_randomness).unwrap();        // POINT AT INFINITY AT DEFAULT

        let computed_commit = first_login_wtns.select(&reconstructed_commit_var, &commit_wtns).unwrap();
        
        computed_commit.enforce_equal(&reconstructed_commit_var);

        // let end = start.elapsed();
        // println!("time 4 {:?}", end);

        // let start = Instant::now();
        let computed_commit_bytes = computed_commit.to_bytes().unwrap();

        // println!("COMPUTED COMMIT BYTES {:?}", computed_commit_bytes);

        let i_prev_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(          // VERIFY USED TO FAIL BUT WORKS NOW
            cs.clone(),
            &{
                let i_value = self.i.as_ref().unwrap_or(&0);
                let selected_i_prev = UInt8::<ConstraintF<C>>::conditionally_select(
                    &Boolean::<ConstraintF<C>>::constant(*i_value == 0),
                    &UInt8::<ConstraintF<C>>::constant(0),
                    &UInt8::<ConstraintF<C>>::constant(i_value.checked_sub(1).unwrap_or(0)),   // both branches run
                )?;
                let mut i_prev_bytes = [0u8; 32];
                i_prev_bytes[0] = selected_i_prev.value()?;
                i_prev_bytes
            }
        ).unwrap();

        // println!("i PREV WTNS (expecting 0) {:?}", i_prev_wtns.value());

        let i_wtns = UInt8::<ConstraintF<C>>::new_witness_vec(           // VERIFY FAILS
            cs.clone(),
            &{
                let mut i_prev_bytes = [0u8; 32];
                i_prev_bytes[0] = *self.i.as_ref().unwrap_or(&0);
                i_prev_bytes
            }
        ).unwrap();

        // println!("i wtns (expecting 0) {:?}", i_wtns.value());
        let start = Instant::now();
        let computed_prf_wtns = Blake2sGadget::evaluate(&prf_key_wtns, &i_wtns).unwrap();

        let computed_prev_prf_wtns = Blake2sGadget::evaluate(&prf_key_wtns, &i_prev_wtns).unwrap();
        let end = start.elapsed();
        println!("time 5 {:?}", end);
        let h_prev_wtns = PrfOutputVar::<ConstraintF<C>>::new_variable(          // VERIFY FAILS
            cs.clone(),
            || {
                let prf_key = self.prf_key.as_ref().unwrap_or(&[0u8;32]);
                 // if first login, 'compute' with i=0. Otherwise just declare given h_prev as new_variable::witness
                let zero_prf = Blake2s::evaluate(&prf_key, &[0u8;32]).unwrap().clone();
                let h_prev = self.h_prev.as_ref().unwrap_or(&zero_prf);
                println!("h prev computed {:?}", h_prev);
                // TODO: need minor change - when first_login=true and h_cur≠0, still passes??
                Ok(*h_prev)
            },
            AllocationMode::Witness,
        ).unwrap();

        // println!("h cur wtns {:?}", h_cur_wtns.value());
        // println!("computed_prf_wtns {:?}", computed_prf_wtns.value());
        h_cur_wtns.enforce_equal(&computed_prf_wtns);

        // // for first time users, this checks that i=0
        // // h_prev_wtns is computed with i=0 and computed_prev_prf_wtns is computed with provided i
        // println!("computed_prev_prf_wtns {:?}", computed_prev_prf_wtns.value());
        // println!("h prev computed wtns {:?}", h_prev_wtns.value());

        computed_prev_prf_wtns.enforce_equal(&h_prev_wtns);
        // let end = start.elapsed();
        // println!("time 5 {:?}", end);
        println!("last in generate constraints");
        Ok(())
    }
}

fn main() {
    // let cs: ConstraintSystemRef<ConstraintF<C>> = ConstraintSystem::new_ref();
    // cs.set_mode(SynthesisMode::Prove{construct_matrices: true});

    println!("Entering main.");
    let rng = &mut OsRng;
        
    let elgamal_rand = EncRand::<JubJub>::rand(rng);
    let elgamal_param = MyEnc::setup(rng).unwrap();
    let (pubkey, _) = MyEnc::keygen(&elgamal_param, rng).unwrap();

    // Make PRF key
    let mut prf_key = [0u8; 32];
    rng.fill_bytes(&mut prf_key);

    /* Assume this is previous record */
    let i_prev: u8 = 9;
    
    let i_bytes = i_prev.to_le_bytes();
    let mut i_array = [0u8; 32];
    i_array[..i_bytes.len()].copy_from_slice(&i_bytes);
    let h_prev = Blake2s::evaluate(&prf_key, &i_array).unwrap();   // output [u8; 32]

    let plaintext = JubJub::rand(rng).into_affine();
    let v_prev = MyEnc::encrypt(&elgamal_param, &pubkey, &plaintext, &elgamal_rand).unwrap();
    let mut v_0_bytes = vec![];    // TODO: unify length to check partition later
    // let mut v_0_y_bytes = vec![];
    let mut v_1_bytes = vec![];
    // let mut v_1_y_bytes = vec![];

    v_prev.0.serialize(&mut v_0_bytes).unwrap();
    v_prev.1.serialize(&mut v_1_bytes).unwrap();
    let mut msg = vec![];
    
    // NOTE: msg ends up being 224 bytes.
    msg.extend_from_slice(&h_prev);
    msg.extend_from_slice(&v_0_bytes);        // TODO: check partitions too
    // msg.extend_from_slice(&v_0_y_bytes);
    msg.extend_from_slice(&v_1_bytes);
    // msg.extend_from_slice(&v_1_y_bytes);
    println!("schnorr msg from outside: {:?}", msg);

    let msg2 = msg.clone();
    let msg3 = msg.clone();
    
    /* Generate Poseidon hash parameters for Musig2 */
    let (ark, mds) = find_poseidon_ark_and_mds::<ConstraintF<C>> (0,2,8,31,0);

    let poseidon_params = Poseidon::<ConstraintF<C>, MyPoseidonParams> {
        params: MyPoseidonParams::default(),
        round_keys: vec![],
        mds_matrix: vec![],
    };
    
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

    // Sig should be verifiable as a standard schnorr signature
    let aggregated_pubkey: PublicKey<C> = key_agg_ctx.aggregated_pubkey();
    
    /* RESUMES NON-AGGREGATE CODE. */
    
    let schnorr_verified = Schnorr::<C>::verify(&schnorr_param, &aggregated_pubkey, &msg3, &last_sig).unwrap();
    println!("schnorr verified outside circuit {:?}", schnorr_verified);

    let mut aggregated_pubkey_bytes = vec![];
    aggregated_pubkey.serialize(&mut aggregated_pubkey_bytes);

    /* Commit to aggregated_pubkey and give it to RP. */
    let pedersen_randomness = PedersenRandomness(<JubJub as ProjectiveCurve>::ScalarField::rand(rng));
    let pedersen_params = Commitment::<JubJub, Window>::setup(rng).unwrap();
    let apk_commit: GroupAffine<EdwardsParameters> = Commitment::<JubJub, Window>::commit(&pedersen_params, &aggregated_pubkey_bytes, &pedersen_randomness).unwrap();
    // THIS IS TWISTED EDWARDS

    // let heloo: Fp256<ark_bls12_381::FrParameters> = apk_commit.x;
    /* Make current record */
    let i: u8 = 10;
    let i_bytes = i.to_le_bytes();
    let mut i_array = [0u8; 32];
    i_array[..i_bytes.len()].copy_from_slice(&i_bytes);

    let h_cur = Blake2s::evaluate(&prf_key, &i_array).unwrap();
    // let mut result = [0u64; 4]; // Array to hold the 8 resulting i32 values

    // for (i, chunk) in h_cur.chunks_exact(8).enumerate() {
    //     let array: [u8; 8] = chunk.try_into().expect("Slice with incorrect length");
    //     result[i] = u64::from_le_bytes(array);
    // }
    
    // let h_cur_biginteger = BigInteger256::new(result);

    // // let h_cur_biginteger = BigInteger256::from(result);
    // let h_cur_fe = Fp256::<ark_bls12_381::FrParameters>::new(h_cur_biginteger);

    let insert_circuit_for_setup = InsertCircuit::<W, C, GG> {
        first_login: None,
        schnorr_params: None,
        schnorr_apk: None,
        apk_commit_x: Some(apk_commit.x),
        apk_commit_y: Some(apk_commit.y),
        pedersen_params: None,
        pedersen_rand: None,
        poseidon_params: None,
        schnorr_sig: None,
        h_prev: None,
        v_prev: None,
        prf_key: None,
        h_cur: None,
        i: None,
        _curve_var: PhantomData::<GG>,
        _window_var: PhantomData::<W>,
    };

    let start = Instant::now();
    println!("before setup");
    let (pk, vk) = Groth16::<E>::circuit_specific_setup(insert_circuit_for_setup, rng).unwrap();
    println!("after setup");
    
    let setup_time = start.elapsed();

    println!("Setup time: {:?}", setup_time.as_millis());

    let start = Instant::now();
    let pvk: ark_groth16::PreparedVerifyingKey<E> = Groth16::<E>::process_vk(&vk).unwrap();
    println!("LENGTH:");
    println!("{}", pvk.vk.gamma_abc_g1.len());
    let vk_time = start.elapsed();
    println!("VK preprocessing time: {:?}", vk_time.as_millis());

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
        apk_commit_x: Some(apk_commit.x),
        apk_commit_y: Some(apk_commit.y),
        pedersen_params:  Some(pedersen_params),
        poseidon_params: Some(poseidon_params),
        pedersen_rand: Some(pedersen_randomness),
        schnorr_sig: Some(last_sig),
        h_prev: Some(h_prev),
        v_prev:  Some(v_prev),
        prf_key: Some(prf_key),
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

    println!("Proof time: {:?}", proof_time.as_millis());

    let public_inputs = [      // THESE ARE JUST FIELD ELEMENTS, NEITHER TE NOR SW
        apk_commit.x,
        apk_commit.y,
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