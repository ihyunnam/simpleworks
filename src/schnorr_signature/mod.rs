use std::str::FromStr;

use ark_crypto_primitives::Error;
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_377::{constraints::EdwardsVar, EdwardsProjective};
use ark_ff::{bytes::ToBytes, FftField, Field, PrimeField};
use ark_std::hash::Hash;
use ark_std::rand::Rng;

pub mod schnorr;
pub use schnorr::{Parameters, PublicKey, SecretKey, Signature};

pub mod parameters_var;
pub use parameters_var::ParametersVar;

pub mod signature_var;
pub use signature_var::SignatureVar;

pub mod public_key_var;
pub use public_key_var::PublicKeyVar;

pub mod schnorr_signature_verify_gadget;
pub use schnorr_signature_verify_gadget::SchnorrSignatureVerifyGadget;

pub mod blake2s;
pub use blake2s::ParametersVar as Blake2sParametersVar;

use self::schnorr::Schnorr;

pub type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

pub type SimpleSchnorrConstraintF =
    <<EdwardsProjective as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

pub type SimpleSchnorrParameters = Parameters<EdwardsProjective>;
pub type SimpleSchnorrPublicKey = PublicKey<EdwardsProjective>;
pub type SimpleSchnorrSignature = Signature<EdwardsProjective>;
pub type SimpleSchnorrMessage = Vec<u8>;

pub type SimpleSchnorrParametersVar = ParametersVar<EdwardsProjective, EdwardsVar>;
pub type SimpleSchnorrPublicKeyVar = PublicKeyVar<EdwardsProjective, EdwardsVar>;
pub type SimpleSchnorrSignatureVar = SignatureVar<EdwardsProjective, EdwardsVar>;

pub type SimpleSchnorr = Schnorr<EdwardsProjective>;

pub type Point = [u8;32];   // GroupAffine<EdwardsProjective> serialized

pub trait AggregateSignatureScheme {
    type Parameters: Clone + Send + Sync;
    type PublicKey: ToBytes + Hash + Eq + Clone + Default + Send + Sync;
    type SecretKey: ToBytes + Clone + Default;
    type Signature: Clone + Default + Send + Sync;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error>;

    fn sign<R: Rng>(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, Error>;

    fn verify(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error>;

    fn randomize_public_key(
        pp: &Self::Parameters,
        public_key: &Self::PublicKey,
        randomness: &[u8],
    ) -> Result<Self::PublicKey, Error>;

    fn randomize_signature(
        pp: &Self::Parameters,
        signature: &Self::Signature,
        randomness: &[u8],
    ) -> Result<Self::Signature, Error>;

    // fn compute_key_aggregation_coefficient(
    //     pk_list_hash: &[u8; 32],
    //     pubkey: &Point,
    //     pk2: Option<&Point>,
    // ) -> self::C::ScalarField;
}