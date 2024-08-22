use ark_r1cs_std::{alloc::AllocationMode, R1CSVar};
use super::{
    blake2s::{ROGadget, RandomOracleGadget},
    parameters_var::ParametersVar,
    public_key_var::PublicKeyVar,
    schnorr::Schnorr,
    signature_var::SignatureVar,
    Blake2sParametersVar, ConstraintF,
};
use ark_ff::{BigInteger, PrimeField};
use ark_crypto_primitives::signature::SigVerifyGadget;
use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_r1cs_std::{ToBitsGadget, ToBytesGadget};
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean, CurveVar, EqGadget, GroupOpsBounds},
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::marker::PhantomData;
use ark_serialize::CanonicalSerialize;

pub struct SchnorrSignatureVerifyGadget<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

impl<C, GC> SigVerifyGadget<Schnorr<C>, ConstraintF<C>> for SchnorrSignatureVerifyGadget<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;
    type SignatureVar = SignatureVar<C, GC>;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF<C>>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        // let prover_response = signature.prover_response.clone();
        // let verifier_challenge = signature.verifier_challenge.clone();
        // let mut claimed_prover_commitment = parameters
        //     .generator
        //     .scalar_mul_le(prover_response.to_bits_le()?.iter())?;
        // let public_key_times_verifier_challenge = public_key
        //     .pub_key
        //     .scalar_mul_le(verifier_challenge.to_bits_le()?.iter())?;
        // claimed_prover_commitment += &public_key_times_verifier_challenge;

        // let mut hash_input = Vec::new();
        // if let Some(salt) = parameters.salt.as_ref() {
        //     hash_input.extend_from_slice(salt);
        // }
        // hash_input.extend_from_slice(&public_key.pub_key.to_bytes()?);
        // hash_input.extend_from_slice(&claimed_prover_commitment.to_bytes()?);
        // hash_input.extend_from_slice(message);

        // let b2s_params = <Blake2sParametersVar as AllocVar<_, ConstraintF<C>>>::new_constant(
        //     ConstraintSystemRef::None,
        //     (),
        // )?;
        // let obtained_verifier_challenge = ROGadget::evaluate(&b2s_params, &hash_input)?.0;

        // obtained_verifier_challenge.is_eq(&verifier_challenge.to_vec());

        /* MY CODE */

        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.clone();

        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&verifier_challenge);
        hash_input.extend_from_slice(&public_key.pub_key.to_bytes()?);
        hash_input.extend_from_slice(message);

        let b2s_params = <Blake2sParametersVar as AllocVar<_, ConstraintF<C>>>::new_constant(
            ConstraintSystemRef::None,
            (),
        )?;

        // TODO: ROGadget to Poseidon?
        let hash = ROGadget::evaluate(&b2s_params, &hash_input)?.0;

        // let mut u8_vec = Vec::with_capacity(hash.len()); // Pre-allocate capacity for performance

        // // Extract the underlying u8 values
        // for uint8 in hash {
        //     if let Some(value) = uint8.value().ok() {
        //         u8_vec.push(value);
        //     } else {
        //         // Handle the case where the value is not available or not assigned
        //         // For example, you might want to return an error or a default value
        //         panic!("Value not assigned!");
        //     }
        // }

        // let e = C::ScalarField::from_be_bytes_mod_order(&u8_vec);

        // let mut u8_vec_pr = Vec::with_capacity(prover_response.len()); // Pre-allocate capacity for performance

        // // Extract the underlying u8 values
        // for uint8 in prover_response {
        //     if let Some(value) = uint8.value().ok() {
        //         u8_vec_pr.push(value);
        //     } else {
        //         panic!("Value not assigned!");
        //     }
        // }
        
        // let mut vector = vec![];
        // public_key.pub_key.into_affine().serialize(&mut vector);
        // let mut pub_key_vec = Vec::with_capacity(prover_response.len()); // Pre-allocate capacity for performance

        // // Extract the underlying u8 values
        // for uint8 in prover_response {
        //     if let Some(value) = uint8.value().ok() {
        //         u8_vec_pr.push(value);
        //     } else {
        //         panic!("Value not assigned!");
        //     }
        // }

        let verification_point = parameters.generator.scalar_mul_le(prover_response.to_bits_le()?.iter())?
                .sub(public_key
                    .pub_key
                    .scalar_mul_le(hash.to_bits_le()?.iter())?);
        
        // sub(C::from(C::Affine::from_random_bytes(public_key.pub_key.scalar_mul_le(u8_vec.into()).into()).unwrap()));
        // let mut verification_point_bytes = vec![];
        // verification_point.serialize(&mut verification_point_bytes);
        // let mut verification_point_var = vec![];
        // for byte in verification_point_bytes {
        //     verification_point_var.push(UInt8::new_variable(
        //         ConstraintSystemRef::None,
        //         || Ok(byte),
        //         AllocationMode::Constant,
        //     ).unwrap())
        // };
        println!("FAIL HERE?");

        let verification_point_affine = verification_point.value()?.into_affine();
        let mut vector_affine = vec![];
        verification_point_affine.serialize_uncompressed(&mut vector_affine);
        let mut vector_var = vec![];
        for coord in vector_affine {
            vector_var.push(UInt8::new_variable(ConstraintSystemRef::None, || Ok(coord), AllocationMode::Constant).unwrap());
        }
        vector_var.is_eq(&verifier_challenge.to_vec())
    }
}
