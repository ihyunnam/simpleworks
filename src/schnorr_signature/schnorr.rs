use serde::Serialize;
use ark_ed_on_bls12_381::{EdwardsProjective, EdwardsParameters};

type C = EdwardsProjective;
type P = EdwardsParameters;
type Fr = <C as ProjectiveCurve>::ScalarField;
use std::collections::HashMap;

use sha2::Digest as _;
use ark_crypto_primitives::{Error, SignatureScheme};
use ark_ec::{twisted_edwards_extended::{GroupAffine, GroupProjective}, AffineCurve, ProjectiveCurve};
use ark_ff::{
    bytes::ToBytes,
    fields::{Field, PrimeField},
    to_bytes, ToConstraintField, UniformRand,
};
use ark_std::io::{Result as IoResult, Write};
use ark_std::rand::Rng;
use ark_std::{hash::Hash, marker::PhantomData, vec::Vec};
use blake2::Blake2s;
use digest::Digest;
use crate::schnorr_signature::{AggregateSignatureScheme, Point};
use musig2::{errors::KeyAggError, tagged_hashes::{KEYAGG_LIST_TAG_HASHER, KEYAGG_COEFF_TAG_HASHER}};

use derivative::Derivative;

pub struct Schnorr<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve"), Debug)]
pub struct Parameters<C: ProjectiveCurve> {
    pub generator: C::Affine,
    pub salt: Option<[u8; 32]>,
}

pub type PublicKey<C> = <C as ProjectiveCurve>::Affine;

#[derive(Clone, Default, Debug)]
pub struct SecretKey<C: ProjectiveCurve> {
    pub secret_key: C::ScalarField,
    pub public_key: PublicKey<C>,
}

impl<C: ProjectiveCurve> ToBytes for SecretKey<C> {
    #[inline]
    fn write<W: Write>(&self, writer: W) -> IoResult<()> {
        self.secret_key.write(writer)
    }
}

#[derive(Clone, Default, Debug)]
pub struct Signature<C: ProjectiveCurve> {
    pub prover_response: C::ScalarField,
    pub verifier_challenge: [u8; 32],
}

impl<C: ProjectiveCurve + Hash> SignatureScheme for Schnorr<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        let salt = None;
        let generator = C::prime_subgroup_generator().into();

        Ok(Parameters { generator, salt })
    }

    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // Secret is a random scalar x
        // the pubkey is y = xG
        let secret_key = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into();

        Ok((
            public_key,
            SecretKey {
                secret_key,
                public_key,
            },
        ))
    }
    
    fn sign<R: Rng>(
        parameters: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        // (k, e);
        let (random_scalar, verifier_challenge) = {
            // Sample a random scalar `k` from the prime scalar field.
            let random_scalar: C::ScalarField = C::ScalarField::rand(rng);
            // Commit to the random scalar via r := k · G.
            // This is the prover's first msg in the Sigma protocol.
            let prover_commitment = parameters.generator.mul(random_scalar).into_affine();

            // Hash everything to get verifier challenge.
            // e := H(salt || pubkey || r || msg);
            let mut hash_input = Vec::new();
            if let Some(salt) = parameters.salt {
                hash_input.extend_from_slice(&salt);
            }
            hash_input.extend_from_slice(&to_bytes![sk.public_key]?);
            hash_input.extend_from_slice(&to_bytes![prover_commitment]?);
            hash_input.extend_from_slice(message);

            let hash_digest = Blake2s::digest(&hash_input);
            assert!(hash_digest.len() >= 32);
            let mut verifier_challenge = [0_u8; 32];
            verifier_challenge.copy_from_slice(&hash_digest);

            (random_scalar, verifier_challenge)
        };

        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(&verifier_challenge);

        // k - xe;
        let prover_response = random_scalar - (verifier_challenge_fe * sk.secret_key);
        let signature = Signature {
            prover_response,
            verifier_challenge,
        };

        Ok(signature)
    }

    fn verify(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        let Signature {
            prover_response,
            verifier_challenge,
        } = signature;
        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(verifier_challenge);
        // sG = kG - eY
        // kG = sG + eY
        // so we first solve for kG.
        let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        let public_key_times_verifier_challenge = pk.mul(verifier_challenge_fe);
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        let claimed_prover_commitment = claimed_prover_commitment.into_affine();

        // e = H(salt, kG, msg)
        let mut hash_input = Vec::new();
        if let Some(salt) = parameters.salt {
            hash_input.extend_from_slice(&salt);
        }
        hash_input.extend_from_slice(&to_bytes![pk]?);
        hash_input.extend_from_slice(&to_bytes![claimed_prover_commitment]?);
        hash_input.extend_from_slice(message);

        // cast the hash output to get e
        let obtained_verifier_challenge = &*Blake2s::digest(&hash_input);

        // The signature is valid iff the computed verifier challenge is the same as the one
        // provided in the signature
        Ok(verifier_challenge == obtained_verifier_challenge)
    }

    // TODO: Implement
    #[allow(clippy::todo)]
    fn randomize_public_key(
        _pp: &Self::Parameters,
        _public_key: &Self::PublicKey,
        _randomness: &[u8],
    ) -> Result<Self::PublicKey, Error> {
        todo!()
    }

    // TODO: Implement
    #[allow(clippy::todo)]
    fn randomize_signature(
        _pp: &Self::Parameters,
        _signature: &Self::Signature,
        _randomness: &[u8],
    ) -> Result<Self::Signature, Error> {
        todo!()
    }
    
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0_i32..8_i32 {
            let bit = (*byte >> (8_i32 - i - 1_i32)) & 1;
            bits.push(bit == 1);
        }
    }
    bits
}

impl<ConstraintF: Field, C: ProjectiveCurve + ToConstraintField<ConstraintF>>
    ToConstraintField<ConstraintF> for Parameters<C>
{
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
        self.generator.into_projective().to_field_elements()
    }
}

/* MUSIG2 IMPLEMENTATION BY IHYUN. */

impl<C: ProjectiveCurve + Hash> AggregateSignatureScheme for Schnorr<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        let salt = None;
        let generator = C::prime_subgroup_generator().into();

        Ok(Parameters { generator, salt })
    }

    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // Secret is a random scalar x
        // the pubkey is y = xG
        let secret_key: <<C as ProjectiveCurve>::Affine as AffineCurve>::ScalarField = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into();

        Ok((
            public_key,
            SecretKey {
                secret_key,
                public_key,
            },
        ))
    }
    
    fn sign<R: Rng>(
        parameters: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        // (k, e);
        let (random_scalar, verifier_challenge) = {
            // Sample a random scalar `k` from the prime scalar field.
            let random_scalar: C::ScalarField = C::ScalarField::rand(rng);
            // Commit to the random scalar via r := k · G.
            // This is the prover's first msg in the Sigma protocol.
            let prover_commitment = parameters.generator.mul(random_scalar).into_affine();

            // Hash everything to get verifier challenge.
            // e := H(salt || pubkey || r || msg);
            let mut hash_input = Vec::new();
            if let Some(salt) = parameters.salt {
                hash_input.extend_from_slice(&salt);
            }
            hash_input.extend_from_slice(&to_bytes![sk.public_key]?);
            hash_input.extend_from_slice(&to_bytes![prover_commitment]?);
            hash_input.extend_from_slice(message);

            let hash_digest = Blake2s::digest(&hash_input);
            assert!(hash_digest.len() >= 32);
            let mut verifier_challenge = [0_u8; 32];
            verifier_challenge.copy_from_slice(&hash_digest);

            (random_scalar, verifier_challenge)
        };

        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(&verifier_challenge);

        // k - xe;
        let prover_response = random_scalar - (verifier_challenge_fe * sk.secret_key);
        let signature = Signature {
            prover_response,
            verifier_challenge,
        };

        Ok(signature)
    }

    fn verify(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        let Signature {
            prover_response,
            verifier_challenge,
        } = signature;
        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(verifier_challenge);
        // sG = kG - eY
        // kG = sG + eY
        // so we first solve for kG.
        let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        let public_key_times_verifier_challenge = pk.mul(verifier_challenge_fe);
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        let claimed_prover_commitment = claimed_prover_commitment.into_affine();

        // e = H(salt, kG, msg)
        let mut hash_input = Vec::new();
        if let Some(salt) = parameters.salt {
            hash_input.extend_from_slice(&salt);
        }
        hash_input.extend_from_slice(&to_bytes![pk]?);
        hash_input.extend_from_slice(&to_bytes![claimed_prover_commitment]?);
        hash_input.extend_from_slice(message);

        // cast the hash output to get e
        let obtained_verifier_challenge = &*Blake2s::digest(&hash_input);

        // The signature is valid iff the computed verifier challenge is the same as the one
        // provided in the signature
        Ok(verifier_challenge == obtained_verifier_challenge)
    }

    // TODO: Implement
    #[allow(clippy::todo)]
    fn randomize_public_key(
        _pp: &Self::Parameters,
        _public_key: &Self::PublicKey,
        _randomness: &[u8],
    ) -> Result<Self::PublicKey, Error> {
        todo!()
    }

    // TODO: Implement
    #[allow(clippy::todo)]
    fn randomize_signature(
        _pp: &Self::Parameters,
        _signature: &Self::Signature,
        _randomness: &[u8],
    ) -> Result<Self::Signature, Error> {
        todo!()
    }
    
}

/* MUSIG2 IMPLEMENTED BY IHYUN. SOURCE: https://github.com/conduition/musig2.git. 
    HARDCODED FOR BLS12-381. */

fn compute_key_aggregation_coefficient(
    pk_list_hash: &[u8; 32],
    pubkey: &Point,
    pk2: Option<&Point>,
) -> Fr {
    // if pk2.is_some_and(|pk2| pubkey == pk2) {
    //     return MaybeScalar::one();
    // }

    let hash: [u8; 32] = KEYAGG_COEFF_TAG_HASHER
        .clone()
        .chain_update(&pk_list_hash)
        // .chain_update(&pubkey.serialize())
        .chain_update(&pubkey)
        .finalize()
        .into();

    Fr::from_le_bytes_mod_order(hash.to_bytes_le())
}

fn hash_pubkeys<P: std::borrow::Borrow<Point>>(ordered_pubkeys: &[P]) -> [u8; 32] {
    let mut h = KEYAGG_LIST_TAG_HASHER.clone();
    for pubkey in ordered_pubkeys {
        h.update(&pubkey.borrow().serialize());
    }
    h.finalize().into()
}

#[derive(Debug, Clone)]
pub struct KeyAggContext {
    /// The aggregated pubkey point `Q`.
    pub(crate) pubkey: GroupAffine<P>,
    // pub(crate) pubkey: [u8;32],

    /// The component individual pubkeys in their original order.
    pub(crate) ordered_pubkeys: Vec<Point>,
    // pub(crate) ordered_pubkeys: Vec<[u8;32]>,

    /// A map of pubkeys to their indexes in the [`ordered_pubkeys`][Self::ordered_pubkeys]
    /// field.
    pub(crate) pubkey_indexes: HashMap<Point, usize>,
    // pub(crate) pubkey_indexes: HashMap<[u8;32], usize>,

    /// Cached key aggregation coefficients of individual pubkeys, in the
    /// same order as `ordered_pubkeys`.
    pub(crate) key_coefficients: Vec<C::ScalarField>,

    /// A cache of effective individual pubkeys, i.e. `pubkey * self.key_coefficient(pubkey)`.
    pub(crate) effective_pubkeys: Vec<GroupAffine<P>>,

    pub(crate) parity_acc: subtle::Choice, // false means g=1, true means g=n-1
    pub(crate) tweak_acc: MaybeScalar,     // None means zero.
}

impl KeyAggContext {
    pub fn new(ordered_pubkeys: Vec<Point>) -> Result<Self, KeyAggError>
    where
        // I: IntoIterator<Item = P>,
        // P: Into<[u8;32]>,
    {
        // p.into() TURNS EACH (ITERATED OVER) PUBKEY INTO A DIFFERENT FORMAT (POINT)
        // POINT IS JUST [U8;64] FOR SECP
        // let ordered_pubkeys: Vec<[u8;32]> = pubkeys.into_iter().collect();
        // assert!(ordered_pubkeys.len() > 0, "received empty set of pubkeys");
        // assert!(
        //     ordered_pubkeys.len() <= u32::MAX as usize,
        //     "max number of pubkeys is u32::MAX"
        // );

        // FIND A PUBKEY THAT'S DIFFERENT FROM THE FIRST ONE
        // SUPPOSE WE ALWAYS DO (USER, LOG). THEN PK2 IS ALWAYS &LOG_PK
        // If all pubkeys are the same, `pk2` will be set to `None`, indicating
        // that every public key `X` should be tweaked with a coefficient `H_agg(L, X)`
        // to prevent collisions (See appendix B of the musig2 paper).
        let pk2: Option<&[u8;32]> = ordered_pubkeys[1..]
            .into_iter()
            .find(|pubkey| pubkey != &&ordered_pubkeys[0]);

        let pk_list_hash = hash_pubkeys(&ordered_pubkeys);

        // TODO: maybe pubkey is not groupaffine?
        // NOTE: THIS DOESN'T CHECK FOR POINTS AT INFINITY. NOT READY FOR PRODUCTION.
        let (effective_pubkeys, key_coefficients): (Vec<GroupAffine<P>>, Vec<C::ScalarField>) =
            ordered_pubkeys
                .iter()
                .map(|&pubkey| {
                    let key_coeff =
                        compute_key_aggregation_coefficient(&pk_list_hash, &pubkey, pk2);
                    (pubkey.mul(key_coeff), key_coeff)
                })
                .unzip();

        // let aggregated_pubkey = MaybePoint::sum(&effective_pubkeys);
        let aggregated_pubkey = effective_pubkeys.into_iter().fold(GroupAffine::<P>::default(), |acc, item| acc + &item);

        let pubkey_indexes = HashMap::from_iter(
            ordered_pubkeys
                .iter()
                .copied()
                .enumerate()
                .map(|(i, pk)| (pk, i)),
        );

        Ok(KeyAggContext {
            pubkey: aggregated_pubkey,
            ordered_pubkeys,
            pubkey_indexes,
            key_coefficients,
            effective_pubkeys,
            parity_acc: subtle::Choice::from(0),
            tweak_acc: MaybeScalar::Zero,
        })
    }
}