use ark_crypto_primitives::crh::CRHScheme;
// use ark_crypto_primitives::crh::pedersen::constraints::CRHParametersVar;
use ark_crypto_primitives_03::{SignatureScheme};
use ark_ed25519::EdwardsConfig;
use ark_std::UniformRand;
// use ark_ed25519::Fr;
// use ark_ed25519::{Bn254, FrParameters};
// use ark_crypto_primitives::signature::SignatureScheme;
// use ark_marlin::ahp::verifier;
use ark_r1cs_std::{alloc::AllocationMode, R1CSVar};
// use crate::schnorr_signature::Signature,
// use ark_crypto_primitives_03::crh::CRHGadget as CRHGadgetTrait;
// use ark_crypto_primitives::crh::poseidon::sbox::PoseidonSbox;
// use ark_crypto_primitives::crh::poseidon::PoseidonRoundParams;
use ark_crypto_primitives::crh::poseidon::{CRH, constraints::CRHParametersVar};
use ark_crypto_primitives::signature::schnorr::PublicKey;

// use super::schnorr::MyPoseidonParams;
use super::{
    // blake2s::{ROGadget, RandomOracleGadget},
    parameters_var::ParametersVar,
    public_key_var::PublicKeyVar,
    schnorr::Schnorr,
    signature_var::SignatureVar,
    // Blake2sParametersVar, 
    ConstraintF,
};
// use ark_bn254::{bn254 as E, Fr};
use ark_ff::{ BigInteger, Field, Fp256, PrimeField, Zero};
// use ark_crypto_primitives::signature::SigVerifyGadget;
use ark_ec::{CurveConfig, CurveGroup};
use ark_r1cs_std::{ToBitsGadget, ToBytesGadget};
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean, CurveVar, EqGadget, GroupOpsBounds},
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use std::ops::Mul;
use std::time::Instant;
use std::{io::Cursor, marker::PhantomData};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

type Fr = <EdwardsConfig as CurveConfig>::ScalarField;

pub trait SigVerifyGadget<F: Field, S: SignatureScheme, CF: PrimeField> {
    type ParametersVar;
    type PublicKeyVar;
    type SignatureVar;

    fn verify(
        cs: ConstraintSystemRef<Fr>,
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<CF>],
        signature: &Self::SignatureVar,
        poseidon_params: &CRHParametersVar<Fr>,
    ) -> Result<Boolean<CF>, SynthesisError>;
}

pub struct SchnorrSignatureVerifyGadget<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

// NOTE: couldn't import from schnorr.rs hence just recreate here
type MaybeScalar = <EdwardsConfig as CurveConfig>::ScalarField;

impl<C, GC> SigVerifyGadget<Fr, Schnorr<C>, ConstraintF<C>> for SchnorrSignatureVerifyGadget<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
    Namespace<<<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField>: From<ark_relations::r1cs::ConstraintSystemRef<Fr>>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;
    type SignatureVar = SignatureVar<C, GC>;

    fn verify(
        cs: ConstraintSystemRef<Fr>,
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF<C>>],
        signature: &Self::SignatureVar,
        poseidon_params: &CRHParametersVar<Fr>
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.value().unwrap_or(vec![0u8;32]).clone();

        let poseidon_params = &poseidon_params.parameters;

        let pubkey_affine = public_key.pub_key.value().unwrap_or(C::default()).into_affine();
        // let mut agg_pubkey_serialized = vec![];
        // pubkey_affine.serialize_with_mode(&mut agg_pubkey_serialized, Compress::Yes);

        // let message = message.value().unwrap_or(vec![0u8;96]);
        // // CRHParametersVar::<Fr>::new_witness(cs, || Ok(params)).unwrap();
        // let hash1 = CRH::<Fr>::evaluate(poseidon_params, &verifier_challenge).unwrap();
        // let hash2 = CRH::<Fr>::evaluate(poseidon_params, &agg_pubkey_serialized).unwrap();
        // let hash3 = CRH::<Fr>::evaluate(poseidon_params, &message).unwrap();

        let mut input_vector = vec![];

        // final_nonce_xonly.serialize_with_mode(&mut input_vector, Compress::Yes);
        let final_nonce_xonly = MaybeScalar::from_be_bytes_mod_order(&verifier_challenge);
        input_vector.clear();
        let hash1 = CRH::<Fr>::evaluate(poseidon_params, [final_nonce_xonly]).unwrap();
        
        aggregated_pubkey.serialize_with_mode(&mut input_vector, Compress::Yes);
        let aggregated_pubkey = MaybeScalar::from_be_bytes_mod_order(&input_vector);
        input_vector.clear();
        let hash2 = CRH::<Fr>::evaluate(poseidon_params, [aggregated_pubkey]).unwrap();

        // message.serialize_with_mode(&mut input_vector, Compress::Yes);
        let message = MaybeScalar::from_be_bytes_mod_order(message.as_ref());
        let hash3 = CRH::<Fr>::evaluate(poseidon_params, [message]).unwrap();

        let mut final_vector = vec![];
        let mut temp_vector = vec![];
        hash1.serialize_with_mode(&mut temp_vector, Compress::Yes).unwrap();
        final_vector.extend(&temp_vector);
        temp_vector.clear();
        hash2.serialize_with_mode(&mut temp_vector, Compress::Yes).unwrap();
        final_vector.extend(&temp_vector);
        temp_vector.clear();
        hash3.serialize_with_mode(&mut temp_vector, Compress::Yes).unwrap();
        final_vector.extend(&temp_vector);
        temp_vector.clear();

        let mut reader = Cursor::new(prover_response.value().unwrap_or([0u8;32].to_vec()));
        let prover_response_fe = C::ScalarField::deserialize_with_mode(&mut reader, Compress::Yes, Validate::No).unwrap();

        let e = C::ScalarField::from_be_bytes_mod_order(final_vector.as_slice()); 

        let verification_point = parameters.generator.value().unwrap_or(C::default()).into_affine().mul(prover_response_fe).sub(public_key.pub_key.value().unwrap_or(C::default()).into_affine().mul(e)).into_affine();
        // let mut verification_point_bytes: Vec<u8> = vec![];
        verification_point.serialize_with_mode(&mut temp_vector, Compress::Yes);            // Reuse temp_vector to minimize alloc

        let mut verification_point_wtns: Vec<UInt8<ConstraintF<C>>> = vec![];
        for coord in temp_vector {
            verification_point_wtns.push(UInt8::new_variable(cs.clone(), || Ok(coord), AllocationMode::Witness).unwrap());
        }
        
        Ok(verification_point_wtns.is_eq(&signature.verifier_challenge.clone())?)
    }
}

// let prover_response = signature.prover_response.clone();
// let verifier_challenge = signature.verifier_challenge.clone();

// let pubkey_affine = public_key.pub_key.value().unwrap_or(C::default()).into_affine();

// println!("pubkey affine {:?}", pubkey_affine);
// let mut agg_pubkey_serialized = [0u8; 32];
// pubkey_affine.serialize(&mut agg_pubkey_serialized[..]);

// let mut reader = Cursor::new(prover_response.value().unwrap_or([0u8;32].to_vec()));

// // Deserialize the bytes back into an affine point
// let prover_response_fe = C::ScalarField::deserialize(&mut reader).unwrap();

// let mut hash_var: Vec<UInt8<ConstraintF<C>>> = vec![];
// for coord in verifier_challenge.value().unwrap_or(vec![0u8;32]) {
//     // println!("coord vc {:?}", coord);
//     hash_var.push(UInt8::new_variable(cs.clone(), || Ok(coord), AllocationMode::Constant).unwrap());
// }
// for coord in agg_pubkey_serialized {
//     // println!("coord ap {:?}", coord);
//     hash_var.push(UInt8::new_variable(cs.clone(), || Ok(coord), AllocationMode::Constant).unwrap());
// }
// for coord in message.value().unwrap_or(vec![0u8;96]) {
//     // println!("coord msg {:?}", coord);
//     hash_var.push(UInt8::new_variable(cs.clone(), || Ok(coord), AllocationMode::Constant).unwrap());
// }

// // println!("hash_var {:?}", hash_var.value());

// // let b2s_params: Blake2sParametersVar = <Blake2sParametersVar as AllocVar<_, ConstraintF<C>>>::new_constant(
// //     ConstraintSystemRef::None,
// //     (),
// // )?;

// let hash = CRHGadget::evaluate(&poseidon_params, &hash_var)?;
// // println!("HASH {:?}", hash.value());

// let e = C::ScalarField::from_be_bytes_mod_order(&hash.value().unwrap_or([0u8;32]));

// let verification_point = parameters.generator.value().unwrap_or(C::default()).into_affine().mul(prover_response_fe).sub(public_key.pub_key.value().unwrap_or(C::default()).into_affine().mul(e)).into_affine();

// let mut verification_point_bytes: Vec<u8> = vec![];
// verification_point.serialize(&mut verification_point_bytes);

// let mut verification_point_var: Vec<UInt8<ConstraintF<C>>> = vec![];
// for coord in verification_point_bytes {
//     verification_point_var.push(UInt8::new_variable(cs.clone(), || Ok(coord), AllocationMode::Constant).unwrap());
// }

// // verification_point_var.enforce_equal(&verifier_challenge);
// // println!("RESULT {:?}", result.value());

// // Dummy return value
// Ok(verification_point_var.is_eq(&verifier_challenge)?)
