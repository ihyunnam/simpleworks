use ark_serialize::CanonicalSerialize;
use super::schnorr::PublicKey;
// use ark_bls12_381::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed25519::{EdwardsAffine, EdwardsConfig, EdwardsProjective, FrConfig};
use ark_ff::{Field, Fp, MontBackend};
use ark_r1cs_std::{bits::uint8::UInt8, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_serialize::Compress;
use ark_std::vec::Vec;
use core::{borrow::Borrow, marker::PhantomData};
use derivative::Derivative;
type Fr = Fp<MontBackend<FrConfig, 4>, 4>;
type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup"),
    Clone(bound = "C: CurveGroup")
)]
pub struct PublicKeyVar<C: CurveGroup>
// where
    // for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    pub(crate) pub_key: Vec<UInt8<Fr>>,
    #[doc(hidden)]
    _group: PhantomData<*const C>,
}

impl<C> AllocVar<PublicKey, Fr> for PublicKeyVar<C>
where
    C: CurveGroup,
    // GC: CurveVar<C, ConstraintF<C>>,
    // for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
    // <C as CurveGroup>::Affine: From<ark_ec::twisted_edwards::Affine<ark_ed25519::EdwardsConfig>>
    C: CurveGroup<Affine = ark_ec::twisted_edwards::Affine<ark_ed25519::EdwardsConfig>>,
{
    fn new_variable<T: Borrow<PublicKey>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            // let affine_point: C::Affine = *val.borrow().into();

            // Convert the affine point to its projective representation
            // Note: this used to work
            // let pub_key_c = C::from(*val.borrow());
            let mut writer: Vec<u8> = vec![];
            val.borrow().serialize_with_mode(&mut writer, Compress::Yes);
            // let writer_slice: &[u8; 32] = writer.as_slice().try_into().expect("Expected a Vec of length 32");
            let mut pub_key = vec![];
            for byte in &writer {
                pub_key.push(UInt8::<Fr>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }

            // let pub_key: UInt8<Fp<MontBackend<FrConfig, 4>, 4>> = UInt8::<Fr>::new_variable(cs.clone(), || Ok(writer.to_vec()), mode).unwrap();
            Ok(Self {
                pub_key,
                _group: PhantomData,
            })
        }) 
    }
}

impl<C> EqGadget<Fr> for PublicKeyVar<C>
where
    C: CurveGroup,
    // GC: CurveVar<C, ConstraintF<C>>,
    // for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<Fr>, SynthesisError> {
        self.pub_key.is_eq(&other.pub_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<Fr>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_equal(&other.pub_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<Fr>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_not_equal(&other.pub_key, condition)
    }
}

impl<C> ToBytesGadget<Fr> for PublicKeyVar<C>
where
    C: CurveGroup,
    // GC: CurveVar<C, ConstraintF<C>>,
    // for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
        self.pub_key.to_bytes()
    }
}
