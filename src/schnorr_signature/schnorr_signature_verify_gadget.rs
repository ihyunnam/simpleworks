use ark_std::UniformRand;
use ark_bls12_381::FrParameters;
use ark_crypto_primitives::signature::SignatureScheme;
use ark_marlin::ahp::verifier;
use ark_r1cs_std::{alloc::AllocationMode, R1CSVar};
// use crate::schnorr_signature::Signature,
use ark_crypto_primitives::crh::CRHGadget as CRHGadgetTrait;
use ark_crypto_primitives::crh::poseidon::sbox::PoseidonSbox;
use ark_crypto_primitives::crh::poseidon::PoseidonRoundParams;
use ark_crypto_primitives::crh::poseidon::{Poseidon, constraints::{PoseidonRoundParamsVar, CRHGadget}};
use ark_crypto_primitives::signature::schnorr::PublicKey;

use super::schnorr::MyPoseidonParams;
use super::{
    // blake2s::{ROGadget, RandomOracleGadget},
    parameters_var::ParametersVar,
    public_key_var::PublicKeyVar,
    schnorr::Schnorr,
    signature_var::SignatureVar,
    // Blake2sParametersVar, 
    ConstraintF,
};
// use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ff::{bytes, BigInteger, Field, Fp256, FromBytes, PrimeField, Zero};
// use ark_crypto_primitives::signature::SigVerifyGadget;
use ark_ec::{ProjectiveCurve, AffineCurve};
use ark_r1cs_std::{ToBitsGadget, ToBytesGadget};
use ark_r1cs_std::{
    prelude::{AllocVar, Boolean, CurveVar, EqGadget, GroupOpsBounds},
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use std::time::Instant;
use std::{io::Cursor, marker::PhantomData};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

pub trait SigVerifyGadget<F: Field, S: SignatureScheme, CF: PrimeField> {
    type ParametersVar;
    type PublicKeyVar;
    type SignatureVar;

    fn verify(
        cs: ConstraintSystemRef<F>,
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<CF>],
        signature: &Self::SignatureVar,
        poseidon_params: PoseidonRoundParamsVar<CF, MyPoseidonParams>,
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
        poseidon_params: PoseidonRoundParamsVar<ConstraintF<C>, MyPoseidonParams>,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        let start = Instant::now();
        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.clone();

        // let poseidon_params = poseidon_params.params;
        let poseidon_params = PoseidonRoundParamsVar::<ConstraintF<C>, MyPoseidonParams>::new_variable(
            cs.clone(),
            || Ok(poseidon_params.params),
            AllocationMode::Witness,
        )?;

        let mut hash1_var = vec![];
        for coord in verifier_challenge.value().unwrap_or(vec![0u8;32]) {
            // println!("coord vc {:?}", coord);
            hash1_var.push(UInt8::new_variable(cs.clone(), || Ok(coord), AllocationMode::Witness).unwrap());
        }

        let pubkey_affine = public_key.pub_key.value().unwrap_or(C::default()).into_affine();
        let mut agg_pubkey_serialized = [0u8; 32];
        pubkey_affine.serialize(&mut agg_pubkey_serialized[..]);

        let mut hash2_var = vec![];
        for coord in agg_pubkey_serialized {
            hash2_var.push(UInt8::new_variable(cs.clone(), || Ok(coord), AllocationMode::Witness).unwrap());
        }
        let mut hash3_var = vec![];
        for coord in message.value().unwrap_or(vec![0u8;96]) {
            // println!("coord msg {:?}", coord);
            hash3_var.push(UInt8::new_variable(cs.clone(), || Ok(coord), AllocationMode::Witness).unwrap());
        }

        let hash1 = CRHGadget::evaluate(&poseidon_params, &hash1_var).unwrap();
        let hash2 = CRHGadget::evaluate(&poseidon_params, &hash2_var).unwrap();
        let hash3 = CRHGadget::evaluate(&poseidon_params, &hash3_var).unwrap();

        let mut vector1 = vec![];
        let mut vector2 = vec![];
        let mut vector3 = vec![];

        let mut reader = Cursor::new(prover_response.value().unwrap_or([0u8;32].to_vec()));

        // Deserialize the bytes back into an affine point
        let prover_response_fe = C::ScalarField::deserialize(&mut reader).unwrap();

        let hash1 = hash1.value().unwrap_or(<<C as ProjectiveCurve>::BaseField as ark_ff::Field>::BasePrimeField::default());
        let hash2 = hash2.value().unwrap_or(<<C as ProjectiveCurve>::BaseField as ark_ff::Field>::BasePrimeField::default());
        let hash3 = hash3.value().unwrap_or(<<C as ProjectiveCurve>::BaseField as ark_ff::Field>::BasePrimeField::default());

        hash1.serialize(&mut vector1).unwrap();
        hash2.serialize(&mut vector2).unwrap();
        hash3.serialize(&mut vector3).unwrap();
        let mut final_vector = Vec::with_capacity(vector1.len() + vector2.len() + vector3.len());
        final_vector.extend(vector1.clone());
        final_vector.extend(vector2.clone());
        final_vector.extend(vector3.clone());

        let e = C::ScalarField::from_be_bytes_mod_order(final_vector.as_slice());          // to_bytes in LE
        
        // let vector1 = UInt8::<ConstraintF<C>>::new_witness_vec(cs.clone(), vector1.as_slice());
        // let vector2 = UInt8::<ConstraintF<C>>::new_witness_vec(cs.clone(), vector2.as_slice());
        // let vector3 = UInt8::<ConstraintF<C>>::new_witness_vec(cs.clone(), vector3.as_slice());

        // let verification_point = parameters.generator.mul(prover_response).sub(pubkey_affine.mul(e));

        let verification_point = parameters.generator.value().unwrap_or(C::default()).into_affine().mul(prover_response_fe).sub(public_key.pub_key.value().unwrap_or(C::default()).into_affine().mul(e)).into_affine();
        let mut verification_point_bytes: Vec<u8> = vec![];
        verification_point.serialize(&mut verification_point_bytes);
        let end = start.elapsed();
        println!("verify 4 {:?}", end);
        
        let verification_point_wtns = UInt8::<ConstraintF<C>>::new_witness_vec (
            cs.clone(),
            &verification_point_bytes
        ).unwrap();
        
        Ok(verification_point_wtns.is_eq(&verifier_challenge)?)

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

    }
}
