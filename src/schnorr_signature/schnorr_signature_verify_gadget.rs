use ark_crypto_primitives::CRH as CRHTrait;
use ark_ec::mnt4::MNT4;
use ark_std::UniformRand;
use ark_mnt4_753::Parameters;
use ark_crypto_primitives::signature::SignatureScheme;
use ark_marlin::ahp::verifier;
use ark_r1cs_std::{alloc::AllocationMode, R1CSVar};
// use crate::schnorr_signature::Signature,
use ark_crypto_primitives::crh::CRHGadget as CRHGadgetTrait;
use ark_crypto_primitives::crh::poseidon::sbox::PoseidonSbox;
use ark_crypto_primitives::crh::poseidon::PoseidonRoundParams;
use ark_crypto_primitives::crh::poseidon::{CRH, Poseidon, constraints::{PoseidonRoundParamsVar, CRHGadget}};
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
// let mnt4_753::Fr
// use ark_mnt4_753::{MNT4_753 as E, Fr};
use ark_ff::{bytes, BigInteger, Field, Fp256, FromBytes, PrimeField, Zero};
// use ark_crypto_primitives::signature::SigVerifyGadget;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
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
        poseidon_params: &PoseidonRoundParamsVar<CF, MyPoseidonParams>,
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

impl<C, GC> SigVerifyGadget<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr, Schnorr<C>, ConstraintF<C>> for SchnorrSignatureVerifyGadget<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
    Namespace<<<C as ProjectiveCurve>::BaseField as ark_ff::Field>::BasePrimeField>: From<ark_relations::r1cs::ConstraintSystemRef<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;
    type SignatureVar = SignatureVar<C, GC>;

    fn verify(
        cs: ConstraintSystemRef<<MNT4<ark_mnt4_753::Parameters> as PairingEngine>::Fr>,
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF<C>>],
        signature: &Self::SignatureVar,
        poseidon_params: &PoseidonRoundParamsVar<ConstraintF<C>, MyPoseidonParams>,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        let prover_response = signature.prover_response.clone();
        let mut input = vec![];
        let verifier_challenge = signature.verifier_challenge.value().unwrap_or(vec![0u8;32]).clone();
        // println!("verifier chal length {:?}", verifier_challenge.len());
        input.extend(verifier_challenge);
        input.extend([0u8;63]);
        let poseidon_params = &poseidon_params.params;

        let compare = UInt8::<ConstraintF<C>>::new_witness_vec(
            cs.clone(),
            &mut input
        ).unwrap();

        let pubkey_affine = public_key.pub_key.value().unwrap_or(C::default()).into_affine();
        let mut agg_pubkey_serialized = vec![];
        pubkey_affine.serialize(&mut agg_pubkey_serialized);
        // input.extend(agg_pubkey_serialized);
        let mut message = message.value().unwrap_or(vec![0u8;95]);
        message.extend([0u8;70]);
        // input.extend(message);
        // input.extend([0u8;60]);
        // println!("here1");
        let hash1 = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(poseidon_params, &input).unwrap();
        let hash2 = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(poseidon_params, &agg_pubkey_serialized).unwrap();
        // println!("here2");
        let hash3 = <CRH<ConstraintF<C>, MyPoseidonParams> as CRHTrait>::evaluate(poseidon_params, &message).unwrap();

        let mut final_vector = vec![];
        let mut temp_vector = vec![];
        // let mut temp_vector = vec![];
        hash1.serialize(&mut temp_vector).unwrap();
        final_vector.extend(&temp_vector);
        temp_vector.clear();
        hash2.serialize(&mut temp_vector).unwrap();
        final_vector.extend(&temp_vector);
        temp_vector.clear();
        hash3.serialize(&mut temp_vector).unwrap();
        final_vector.extend(&temp_vector);
        // temp_vector.clear();

        let mut reader = Cursor::new(prover_response.value().unwrap_or([0u8;95].to_vec()));
        let prover_response_fe = C::ScalarField::deserialize(&mut reader).unwrap();

        let e = C::ScalarField::from_be_bytes_mod_order(final_vector.as_slice()); 
        final_vector.clear();
        let verification_point = parameters.generator.value().unwrap_or(C::default()).into_affine().mul(prover_response_fe).sub(public_key.pub_key.value().unwrap_or(C::default()).into_affine().mul(e)).into_affine();
        // let mut verification_point_bytes: Vec<u8> = vec![];
        verification_point.serialize(&mut final_vector);            // Reuse temp_vector to minimize alloc

        let mut verification_point_wtns: Vec<UInt8<ConstraintF<C>>> = vec![];
        for coord in final_vector {
            verification_point_wtns.push(UInt8::new_variable(cs.clone(), || Ok(coord), AllocationMode::Witness).unwrap());
        }
        // println!("here?");
        // println!("verification_point_wtns length{:?}", verification_point_wtns.len());
        // let compare = UInt8::<ConstraintF<C>>::new_witness_vec(
        //     cs.clone(),
        //     &{
        //         let mut temp = signature.verifier_challenge.value().unwrap_or(vec![0u8;32]);
        //         temp.extend([0u8;63]);
        //         temp
        //     }
        // ).unwrap();
        // let input = vec![];
        // input.extend(signature.verifier_challenge);
        // let temp = [UInt8::<ConstraintF<C>>::constant(0);70];
        // input.extend();
        // println!("signature.verifier_challenge length{:?}", signature.verifier_challenge.len());
        Ok(verification_point_wtns.is_eq(&compare)?)
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
