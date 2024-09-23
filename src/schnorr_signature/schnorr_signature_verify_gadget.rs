use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::sponge::Absorb;
// use ark_crypto_primitives::crh::pedersen::constraints::CRHParametersVar;
use ark_crypto_primitives_03::{SignatureScheme};
use ark_bn254::FrConfig;
use ark_ed_on_bn254::EdwardsConfig;
use ark_std::UniformRand;
// use ark_ed25519::ConstraintF<C>;
// use ark_ed25519::{Bn254, ConstraintF<C>Parameters};
// use ark_crypto_primitives::signature::SignatureScheme;
// use ark_marlin::ahp::verifier;
use ark_r1cs_std::{alloc::AllocationMode, R1CSVar};
// use crate::schnorr_signature::Signature,
// use ark_crypto_primitives_03::crh::CRHGadget as CRHGadgetTrait;
// use ark_crypto_primitives::crh::poseidon::sbox::PoseidonSbox;
// use ark_crypto_primitives::crh::poseidon::PoseidonRoundParams;
use ark_crypto_primitives::crh::poseidon::{CRH, constraints::CRHParametersVar};
use ark_crypto_primitives::signature::schnorr::PublicKey;

type Fr = Fp<MontBackend<FrConfig, 4>, 4>;

// use super::schnorr::MyPoseidonParams;
use super::{
    // blake2s::{ROGadget, RandomOracleGadget},
    parameters_var::ParametersVar,
    public_key_var::PublicKeyVar,
    schnorr::Schnorr,
    signature_var::SignatureVar,
    // Blake2sParametersVar, 
    // ConstraintF,
};
// use ark_bn254::{bn254 as E, ConstraintF<C>};
use ark_ff::{ BigInteger, Field, Fp, Fp256, MontBackend, PrimeField, Zero};
// use ark_crypto_primitives::signature::SigVerifyGadget;
use ark_ec::{CurveConfig, CurveGroup};
use ark_r1cs_std::{ToBitsGadget, ToBytesGadget};
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean, CurveVar, EqGadget, GroupOpsBounds},
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use std::borrow::Borrow;
use std::ops::Mul;
use std::time::Instant;
use std::{io::Cursor, marker::PhantomData};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
pub trait SigVerifyGadget<F: Field, S: SignatureScheme, C: CurveGroup>
where
    <<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField: Absorb
{
    type ParametersVar;
    type PublicKeyVar;
    type SignatureVar;
    // type ConstraintF<C> = PrimeField;
    fn verify(
        cs: ConstraintSystemRef<Fr>,
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<Fr>],
        signature: &Self::SignatureVar,
        poseidon_params: &CRHParametersVar<Fr>,
    ) -> Result<Boolean<Fr>, SynthesisError>;
}

pub struct SchnorrSignatureVerifyGadget<C: CurveGroup>
// where
//     for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    // #[doc(hidden)]
    // _group_gadget: PhantomData<*const GC>,
}

// NOTE: couldn't import ConstraintF<C>om schnorr.rs hence just recreate here
type MaybeScalar = <EdwardsConfig as CurveConfig>::ScalarField;

impl<C: CurveGroup> SigVerifyGadget<Fr, Schnorr<C>, C> for SchnorrSignatureVerifyGadget<C>
where
    C: CurveGroup ,
    // GC: CurveVar<C, ConstraintF<C>>,
    // for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
    // <<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField: CurveGroup,
    <<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField: Absorb,
    // [ark_ff::Fp<MontBackend<ark_ed25519::FrConfig, 4>, 4>; 1]: Borrow<[<<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField]>,
    // Namespace<<<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField>: ConstraintF<C>om<ark_relations::r1cs::ConstraintSystemRef<ConstraintF<C>>>,
{
    type ParametersVar = ParametersVar<C>;
    type PublicKeyVar = PublicKeyVar<C>;
    type SignatureVar = SignatureVar<C>;

    fn verify(
        cs: ConstraintSystemRef<Fr>,
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<Fr>],
        signature: &Self::SignatureVar,
        poseidon_params: &CRHParametersVar<Fr>
    ) -> Result<Boolean<Fr>, SynthesisError> {
        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.value().unwrap_or(vec![0u8;32]).clone();

        let poseidon_params = &poseidon_params.parameters;

        let pubkey_u8 = public_key.pub_key.value().unwrap_or(vec![0u8;32]);

        let message = message.value().unwrap_or(vec![0u8;96]);
        
        // let mut input_vector = vec![];

        // final_nonce_xonly.serialize_with_mode(&mut input_vector, Compress::Yes);
        let final_nonce_xonly = MaybeScalar::from_be_bytes_mod_order(&verifier_challenge);
        // input_vector.clear();
        let hash1 = CRH::<Fr>::evaluate(poseidon_params, [final_nonce_xonly]).unwrap();
        
        // pubkey_affine.serialize_with_mode(&mut input_vector, Compress::Yes);
        let aggregated_pubkey = MaybeScalar::from_be_bytes_mod_order(&pubkey_u8);
        // input_vector.clear();
        let hash2 = CRH::<Fr>::evaluate(poseidon_params, [aggregated_pubkey]).unwrap();

        // message.serialize_with_mode(&mut input_vector, Compress::Yes);
        let message = MaybeScalar::from_be_bytes_mod_order(message.as_ref());
        let hash3 = CRH::<Fr>::evaluate(poseidon_params, [message]).unwrap();

        let mut final_vector: Vec<u8> = vec![];
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

        // let prover_response_vec: Vec<u8> = prover_response.value().unwrap_or(vec![0u8;32]);
        let mut reader = Cursor::new(prover_response.value().unwrap_or([0u8;32].to_vec()));
        let prover_response_fe = C::ScalarField::deserialize_with_mode(&mut reader, Compress::Yes, Validate::No).unwrap();

        let e = C::ScalarField::from_be_bytes_mod_order(final_vector.as_slice());

        // let default_vec = vec![0u8;32];
        // let pubkey_val = public_key.pub_key.value().unwrap_or(default_vec);
        // let pubkey = C::Affine::from_base_prime_field_elems(pubkey_val);

        // let verification_point = parameters.generator.value().unwrap_or(C::default()).into_affine().mul(prover_response_fe).sub(public_key.pub_key.value().unwrap_or(C::default()).into_affine().mul(e)).into_affine();

        
        let mut generator =  Cursor::new(parameters.generator.value().unwrap_or(vec![0u8;32]));
        let generator_fe = C::Affine::deserialize_with_mode(&mut generator, Compress::Yes, Validate::Yes).unwrap();
        let mut pubkey =  Cursor::new(public_key.pub_key.value().unwrap_or(vec![0u8;32]));
        let pubkey_fe = C::Affine::deserialize_with_mode(&mut pubkey, Compress::Yes, Validate::Yes).unwrap();
        let verification_point = generator_fe.mul(prover_response_fe).sub(pubkey_fe.mul(e));

        verification_point.serialize_with_mode(&mut temp_vector, Compress::Yes);            // Reuse temp_vector to minimize alloc
        // TODO: wasteful to convert from C to Uint and back to C?
        let mut verification_point_wtns: Vec<UInt8<Fr>> = vec![];
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

// let e = C::ScalarField::ConstraintF<C>om_be_bytes_mod_order(&hash.value().unwrap_or([0u8;32]));

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
