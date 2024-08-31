use super::schnorr::PublicKey;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed25519::{EdwardsAffine, EdwardsConfig, EdwardsProjective};
use ark_ff::Field;
use ark_r1cs_std::{bits::uint8::UInt8, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::vec::Vec;
use core::{borrow::Borrow, marker::PhantomData};
use derivative::Derivative;

type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct PublicKeyVar<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    pub(crate) pub_key: GC,
    #[doc(hidden)]
    _group: PhantomData<*const C>,
}

impl<C, GC> AllocVar<PublicKey, ConstraintF<C>> for PublicKeyVar<C, GC>
where
    // C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
    // <C as CurveGroup>::Affine: From<ark_ec::twisted_edwards::Affine<ark_ed25519::EdwardsConfig>>
    C: CurveGroup<Affine = ark_ec::twisted_edwards::Affine<ark_ed25519::EdwardsConfig>>,
{
    fn new_variable<T: Borrow<PublicKey>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            // let affine_point: C::Affine = *val.borrow().into();

            // Convert the affine point to its projective representation
            // let projective_point = EdwardsProjective::from(val.borrow().into());
            let pub_key_c = C::from(*val.borrow());
            // let pubkey_c: EdwardsProjective = EdwardsProjective(pubkey_c);
            let pub_key = GC::new_variable_omit_prime_order_check(cs, || Ok(pub_key_c), mode)?;
            Ok(Self {
                pub_key,
                _group: PhantomData,
            })
        }) 
    }
}

impl<C, GC> EqGadget<ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        self.pub_key.is_eq(&other.pub_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_equal(&other.pub_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_not_equal(&other.pub_key, condition)
    }
}

impl<C, GC> ToBytesGadget<ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: CurveGroup,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF<C>>>, SynthesisError> {
        self.pub_key.to_bytes()
    }
}
