use ark_bls12_381::FrParameters;
use ark_crypto_primitives::SignatureScheme;
use ark_marlin::ahp::verifier;
use ark_r1cs_std::{alloc::AllocationMode, R1CSVar};
use super::{
    blake2s::{ROGadget, RandomOracleGadget},
    parameters_var::ParametersVar,
    public_key_var::PublicKeyVar,
    schnorr::Schnorr,
    signature_var::SignatureVar,
    Blake2sParametersVar, ConstraintF,
};
// use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::{bytes, BigInteger, Field, Fp256, FromBytes, PrimeField};
// use ark_crypto_primitives::signature::SigVerifyGadget;
use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_r1cs_std::{ToBitsGadget, ToBytesGadget};
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean, CurveVar, EqGadget, GroupOpsBounds},
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use std::{io::Cursor, marker::PhantomData};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

pub trait SigVerifyGadget<F: Field, S: SignatureScheme, CF: Field> {
    type ParametersVar;
    type PublicKeyVar;
    type SignatureVar;

    fn verify(
        cs: ConstraintSystemRef<F>,
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<CF>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<CF>, SynthesisError>;
}

pub struct SchnorrSignatureVerifyGadget<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

impl<C, GC> SigVerifyGadget<Fp256<FrParameters>, Schnorr<C>, ConstraintF<C>> for SchnorrSignatureVerifyGadget<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
    Namespace<<<C as ProjectiveCurve>::BaseField as ark_ff::Field>::BasePrimeField>: From<ark_relations::r1cs::ConstraintSystemRef<Fp256<ark_ed_on_bls12_381::FqParameters>>>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;
    type SignatureVar = SignatureVar<C, GC>;

    fn verify(
        cs: ConstraintSystemRef<Fp256<FrParameters>>,
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF<C>>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.clone();
        
        let pubkey_affine = public_key.pub_key.value().unwrap_or(C::default()).into_affine();
        let mut agg_pubkey_serialized = [0u8; 32];
        pubkey_affine.serialize(&mut agg_pubkey_serialized[..]);
        // let hello = prover_response.value().unwrap();
        // println!("PROVER RESPONSE IN GADGET {:?}", prover_response.value().unwrap());
        // println!("VERIFIER CHALLENGE IN GADGET {:?}", verifier_challenge.value().unwrap());
        // println!("VERIFIER CHALLENGE AS SLICE {:?}", verifier_challenge.as_slice().value().unwrap());   // SAME AS VERIFIER CHALLENGE

        let mut reader = Cursor::new(prover_response.value().unwrap_or([0u8;32].to_vec()));

        // Deserialize the bytes back into an affine point
        let prover_response_fe = C::ScalarField::deserialize(&mut reader).unwrap();
        
        let mut hash_input = Vec::new();
// let hasdf = verifier_challenge.value();
        hash_input.extend_from_slice(&verifier_challenge.value().unwrap_or(vec![]));
        hash_input.extend_from_slice(&agg_pubkey_serialized);
        hash_input.extend_from_slice(&message.value().unwrap_or(vec![]));

        let mut hash_var: Vec<UInt8<ConstraintF<C>>> = vec![];
        for coord in hash_input {
            hash_var.push(UInt8::new_variable(ConstraintSystemRef::None, || Ok(coord), AllocationMode::Constant).unwrap());
        }

        let b2s_params = <Blake2sParametersVar as AllocVar<_, ConstraintF<C>>>::new_constant(
            cs.clone(),
            (),
        )?;

        println!("b2s param {:?}", b2s_params);
        // let hello = prover_response.value().unwrap();
        // TODO: ROGadget to Poseidon?
        let hash = ROGadget::evaluate(&b2s_params, &hash_var)?.0;
//         println!("hash {:?}", hash);
//         // println!("HASH VALUE {:?}", hash.value().unwrap());  // SAME
//         // let hello =  parameters.generator.value().unwrap
//         // let hello = public_key.pub_key.value().unwrap();
        let e = C::ScalarField::from_be_bytes_mod_order(&hash.value().unwrap());
//         println!("E VALUE {:?}", e);

//         // let hello = public_key.pub_key.value().unwrap();
        let verification_point = parameters.generator.value().unwrap_or(C::default()).into_affine().mul(prover_response_fe).sub(public_key.pub_key.value().unwrap_or(C::default()).into_affine().mul(e)).into_affine();
//         println!("verification_point {:?}", verification_point);

//         // let verification_point = parameters.generator.scalar_mul_le(prover_response.value().unwrap())
        let mut verification_point_bytes: Vec<u8> = vec![];
        verification_point.serialize(&mut verification_point_bytes);
//         // println!("VERIFICATION POINT BYTES {:?}", verification_point_bytes);    // DIFFERENT
//         // println!("PARAMETER GENERATOR {:?}", parameters.generator.value().unwrap().into_affine());

//         println!("verification_point_bytes {:?}", verification_point_bytes);
        let mut verification_point_var: Vec<UInt8<ConstraintF<C>>> = vec![];
        for coord in verification_point_bytes {
            verification_point_var.push(UInt8::new_variable(cs.clone(), || Ok(coord), AllocationMode::Constant).unwrap());
            // println!("VECTOR VAR VALUE {:?}", coord);
        }

//         println!("verification_point_var {:?}", verification_point_var.value());

        
        verification_point_var.is_eq(verifier_challenge.as_slice())
        // println!("RESULT {:?}", result.value());
        
        // Dummy return value
        // Ok(ark_r1cs_std::prelude::Boolean::Constant(true))

    }
}