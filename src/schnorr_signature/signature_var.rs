use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::encryption::elgamal::constraints::ConstraintF;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
// use ark_ff_03::to_bytes;
// use ark_std::simd::ToBytes::to_le_bytes;
use ark_r1cs_std::{
    prelude::{AllocVar, AllocationMode, CurveVar, GroupOpsBounds},
    uint8::UInt8,
    ToBytesGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use derivative::Derivative;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, EdwardsConfig};
use ark_bn254::Fr;
use super::schnorr::Signature;

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup"),
    Clone(bound = "C: CurveGroup")
)]
pub struct SignatureVar<C: CurveGroup>
// where
//     for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    pub(crate) prover_response: Vec<UInt8<Fr>>,
    pub(crate) verifier_challenge: Vec<UInt8<Fr>>,
    #[doc(hidden)]
    // _group: PhantomData<GC>,
    _curve: PhantomData<C>,
}

impl<C> AllocVar<Signature<C>, Fr> for SignatureVar<C>
where
    C: CurveGroup,
    // GC: CurveVar<C, ConstraintF<C>>,
    // for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    fn new_variable<T: Borrow<Signature<C>>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            // let response_bytes = to_repr![val.borrow().prover_response].unwrap();
            let response_bytes = val.borrow().prover_response.into_bigint().to_bytes_le();
            // println!("RESPONSE BYTES {:?}", response_bytes);
            let challenge_bytes = val.borrow().verifier_challenge;
            let mut prover_response = Vec::<UInt8<Fr>>::new();
            let mut verifier_challenge = Vec::<UInt8<Fr>>::new();
            for byte in &response_bytes {
                prover_response.push(UInt8::<Fr>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }
            for byte in &challenge_bytes {
                verifier_challenge.push(UInt8::<Fr>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }
            Ok(SignatureVar {
                prover_response,
                verifier_challenge,
                // _group: PhantomData,
                _curve: PhantomData,
            })
        })
    }
}

impl<C> ToBytesGadget<Fr> for SignatureVar<C>
where
    C: CurveGroup,
    // GC: CurveVar<C, ConstraintF<C>>,
    // for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        let prover_response_bytes = self.prover_response.to_bytes()?;
        let verifier_challenge_bytes = self.verifier_challenge.to_bytes()?;
        let mut bytes = Vec::<UInt8<Fr>>::new();
        bytes.extend(prover_response_bytes);
        bytes.extend(verifier_challenge_bytes);
        Ok(bytes)
    }
}
