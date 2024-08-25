use ark_crypto_primitives::{
    commitment::pedersen::{Commitment, Parameters, Randomness},
    crh::pedersen::Window,
};

use ark_ec::{twisted_edwards_extended::GroupAffine, ProjectiveCurve};
use ark_ff::{
    fields::{Field, PrimeField}, to_bytes, Fp256, Zero
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use ark_r1cs_std::prelude::*;
use core::{borrow::Borrow, marker::PhantomData};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub};   // Fq2: finite field, JubJub: curve group
// use ark_secp256k1::{Fr, Fq, Projective};

type C = JubJub; 
type GG = EdwardsVar;

type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

#[derive(Clone)]
pub struct ParametersVar<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    params: Parameters<C>,
    #[doc(hidden)]
    _group_var: PhantomData<GG>,
}

#[derive(Clone, Debug)]
pub struct RandomnessVar<F: Field>(Vec<UInt8<F>>);

pub struct CommGadget<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>, W: Window>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
    #[doc(hidden)]
    _group_var: PhantomData<*const GG>,
    #[doc(hidden)]
    _window: PhantomData<*const W>,
}

impl<C, GG, W> ark_crypto_primitives::commitment::CommitmentGadget<Commitment<C, W>, ConstraintF<C>>
    for CommGadget<C, GG, W>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    W: Window,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
    ConstraintF<C>: PrimeField,
{
    type OutputVar = GG;
    type ParametersVar = ParametersVar<C, GG>;
    type RandomnessVar = RandomnessVar<ConstraintF<C>>;

    #[tracing::instrument(target = "r1cs", skip(parameters, r))]
    fn commit(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF<C>>],
        r: &Self::RandomnessVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        assert!((input.len() * 8) <= (W::WINDOW_SIZE * W::NUM_WINDOWS));        // ASSERT IS FINE

        let mut padded_input = input.to_vec();
        // Pad if input length is less than `W::WINDOW_SIZE * W::NUM_WINDOWS`.
        if (input.len() * 8) < W::WINDOW_SIZE * W::NUM_WINDOWS {
            let current_length = input.len();
            for _ in current_length..((W::WINDOW_SIZE * W::NUM_WINDOWS) / 8) {
                padded_input.push(UInt8::constant(0u8));
            }
        }

        assert_eq!(padded_input.len() * 8, W::WINDOW_SIZE * W::NUM_WINDOWS);
        assert_eq!(parameters.params.generators.len(), W::NUM_WINDOWS);

        // Allocate new variable for commitment output.
        let input_in_bits: Vec<Boolean<_>> = padded_input
            .iter()
            .flat_map(|byte| byte.to_bits_le().unwrap_or(vec![]))
            .collect();
        let input_in_bits = input_in_bits.chunks(W::WINDOW_SIZE);

        // let mut result = GG::zero();
        // Compute Σᵢ(bitᵢ * baseᵢ) for all i.
        // for (bits, bases) in input_in_bits.zip(&parameters.params.generators) {
        //     let bases: &[C]= bases.borrow();
        //     let bits = bits.to_bits_le().unwrap_or(vec![]);
        //     result.precomputed_base_scalar_mul_le(bits.iter().zip(bases))?;
        // }
        let mut result = GG::precomputed_base_multiscalar_mul_le(&parameters.params.generators, input_in_bits)?;
        // println!("result: {:?}", result.value());

        // Compute h^r
        let rand_bits: Vec<_> =
            r.0.iter()
                .flat_map(|byte| byte.to_bits_le().unwrap_or(vec![]))
                .collect();
        result.precomputed_base_scalar_mul_le(
            rand_bits
                .iter()
                .zip(&parameters.params.randomness_generator),
        )?;

        // let apk_commit_proj = C::from(GroupAffine::<ark_ed_on_bls12_381::EdwardsParameters>::new(Fp256::<ark_ed_on_bls12_381::FqParameters>::zero(), Fp256::<ark_ed_on_bls12_381::FqParameters>::zero()).into());       // THIS IS TWISTED EDWARDS
        // println!("APK COMMIT PROJ {:?}", apk_commit_proj);
        // let reconstructed_commit_var = GG::new_variable_omit_prime_order_check( // VERIFY USED TO FAIL BUT PASSES NOW
        //     cs.clone(),
        //     || Ok(apk_commit_proj),
        //     AllocationMode::Input,
        // ).unwrap();

        // println!("result allocationmode: {:?}", result);
        Ok(result)      // RESULT DETERMINISTIC. Perhaps witness?
    }
}


impl<C, GG> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        _cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let params = f()?.borrow().clone();
        Ok(ParametersVar {
            params,
            _group_var: PhantomData,
        })
    }
}

impl<C, F> AllocVar<Randomness<C>, F> for RandomnessVar<F>
where
    C: ProjectiveCurve,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Randomness<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let r = to_bytes![&f().map(|b| b.borrow().0).unwrap_or(C::ScalarField::zero())].unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
        }
    }
}