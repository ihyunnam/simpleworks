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

        let verification_point = parameters.generator.scalar_mul_le(prover_response.to_bits_le()?.iter())?
                .sub(public_key
                    .pub_key
                    .scalar_mul_le(hash.to_bits_le()?.iter())?);
        
        let mut vector_affine = vec![];
        let verification_point_affine = verification_point.value().unwrap_or(C::default()).into_affine();
        verification_point_affine.serialize(&mut vector_affine);
        let mut vector_var = vec![];
        for coord in vector_affine {
            vector_var.push(UInt8::new_variable(ConstraintSystemRef::None, || Ok(coord), AllocationMode::Constant).unwrap());
        }
        vector_var.is_eq(&verifier_challenge.to_vec())
    }
}
