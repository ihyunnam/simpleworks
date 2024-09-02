use std::{borrow::Borrow, marker::PhantomData};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_crypto_primitives::encryption::elgamal::constraints::ConstraintF;
use ark_ec::{short_weierstrass::Affine, AffineRepr, CurveGroup};
use ark_ed25519::{EdwardsAffine, EdwardsProjective, FrConfig};
use ark_ff::{Fp, MontBackend};
// use ark_ec::CurveGroup;
use ark_r1cs_std::{
    prelude::{AllocVar, AllocationMode, CurveVar, GroupOpsBounds},
    uint8::UInt8,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use bitvec::view::BitView;

use super::schnorr::Parameters;
type Fr = Fp<MontBackend<FrConfig, 4>, 4>;

#[derive(Clone)]
// pub struct ParametersVar<C: CurveGroup, GC: CurveVar<C, ConstraintF<C>>>
pub struct ParametersVar<C: CurveGroup>
// where
//     for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
{
    pub(crate) generator: UInt8<Fr>,
    pub(crate) salt: Option<Vec<UInt8<Fr>>>,
    _curve: PhantomData<C>,
}

impl<C> AllocVar<Parameters, Fr> for ParametersVar<C>
where
    C: CurveGroup,
    // GC: CurveVar<C, ConstraintF<C>>,
    // for<'group_ops_bounds> &'group_ops_bounds GC: GroupOpsBounds<'group_ops_bounds, C, GC>,
    <C as CurveGroup>::Affine: From<ark_ec::twisted_edwards::Affine<ark_ed25519::EdwardsConfig>>,
{
    fn new_variable<T: Borrow<Parameters>>(
        cs: impl Into<Namespace<Fr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            // Note: following 2 lines used to work for GC generator
            // let generator_c = C::from(EdwardsAffine::new_unchecked(val.borrow().generator.x, val.borrow().generator.y).into());
            // let generator = GC::new_variable_omit_prime_order_check(cs.clone(), || Ok(generator_c), mode)?;
            let mut writer: Vec<u8> = vec![];
            val.borrow().generator.serialize_with_mode(&mut writer, Compress::Yes).unwrap();

            // Convert Vec<u8> to a fixed-size array
            let writer_slice: &[u8; 32] = writer.as_slice().try_into().expect("Expected a Vec of length 32");

            // Use the array with `new_constant`
            let generator = UInt8::<Fr>::new_variable(cs.clone(), || Ok(writer), mode)?;

            let native_salt = val.borrow().salt;
            let mut constraint_salt = Vec::<UInt8<Fr>>::new();
            if let Some(native_salt_value) = native_salt {
                for i in 0..32 {
                    if let Some(native_salt_element) = native_salt_value.get(i) {
                        constraint_salt.push(UInt8::<Fr>::new_variable(
                            cs.clone(),
                            || Ok(native_salt_element),
                            mode,
                        )?);
                    }
                }
                return Ok(Self {
                    generator,
                    salt: Some(constraint_salt),
                    _curve: PhantomData,
                });
            }
            Ok(Self {
                generator,
                salt: None,
                _curve: PhantomData,
            })
        })
    }
}
