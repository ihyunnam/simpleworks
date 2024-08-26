use std::borrow::Borrow;
use std::ops::{Add, Sub};
use ark_bls12_377::FrParameters;
// use subtle::ConstantTimeEq as _;
use ark_serialize::CanonicalSerialize;
// use serde::Serialize;
use ark_ed_on_bls12_381::{EdwardsProjective, EdwardsParameters};
use ark_bls12_381::G1Projective;
use subtle::Choice;
// use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
// type C = EdwardsProjective;
// type P = EdwardsParameters;
use std::collections::HashMap;
use ark_crypto_primitives::crh::{CRH as CRHTrait, poseidon::sbox::PoseidonSbox};
use ark_crypto_primitives::crh::poseidon::{self, PoseidonRoundParams};
use ark_crypto_primitives::crh::poseidon::{CRH, Poseidon, constraints::{PoseidonRoundParamsVar}};
use sha2::Digest as _;
use ark_crypto_primitives::{Error, SignatureScheme};
use ark_ec::{twisted_edwards_extended::GroupAffine, AffineCurve, ProjectiveCurve, TEModelParameters};
use ark_ff::{
    bytes::ToBytes, fields::{Field, PrimeField}, to_bytes, BigInteger256, Fp256, FpParameters, ToConstraintField, UniformRand
};
use ark_std::io::{Result as IoResult, Write};
use ark_std::rand::Rng;
use ark_std::{hash::Hash, marker::PhantomData, vec::Vec};
use ark_std::{One, Zero};
use blake2::Blake2s;
use digest::Digest;
// use crate::schnorr_signature::{AggregateSignatureScheme};
use musig2::{
    errors::{KeyAggError, RoundContributionError, RoundFinalizeError, SignerIndexError, SigningError, VerifyError}, tagged_hashes::{BIP0340_CHALLENGE_TAG_HASHER, KEYAGG_COEFF_TAG_HASHER, KEYAGG_LIST_TAG_HASHER, MUSIG_AUX_TAG_HASHER, MUSIG_NONCECOEF_TAG_HASHER, MUSIG_NONCE_TAG_HASHER}, AdaptorSignature, LiftedSignature, NonceSeed
};

use derivative::Derivative;

#[derive(Default, Clone, Debug)]        // TODO: MUST REMOVE DEBUG
pub struct MyPoseidonParams;

// from 0.4.0 default values: PoseidonDefaultConfigEntry::new(2, 17, 8, 31, 0),         // PARAMS_OPT_FOR_CONSTRAINTS
impl<F: PrimeField> PoseidonRoundParams<F> for MyPoseidonParams {
    const WIDTH: usize = 6; // rate in 0.4.0
    const FULL_ROUNDS_BEGINNING: usize = 4;     // full_rounds = 8. Assume mid-split.
    const FULL_ROUNDS_END: usize = 4;
    const PARTIAL_ROUNDS: usize = 57;
    
    // Define the S-Box here (can use Poseidon's recommended S-Box)
    const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);         // alpha in 0.4.0
}

// NOTE: 
// MaybePoint::<C> - point on bls12_381 (Affine, like PublicKey?)
// MaybeScalar - scalarfield element of bls12_381 (basically PrivateKey)

type MaybePoint<C> = <C as ProjectiveCurve>::Affine;
type MaybeScalar<C> = <C as ProjectiveCurve>::ScalarField; // TODO: same thing as Fr!!!!

pub struct Schnorr<C: ProjectiveCurve> {
    _group: PhantomData<C>,
}

// type Fr = <EdwardsProjective as ProjectiveCurve>::ScalarField;

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve"), Debug)]
pub struct Parameters<C: ProjectiveCurve> {
    pub generator: C::Affine,
    pub salt: Option<[u8; 32]>,
}

// type W = Window;
// type C = EdwardsProjective; 
// type GG = EdwardsVar;
type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;
// type P = PoseidonRoundParams<ConstraintF<C>>;
// type MyEnc = ElGamal<JubJub>;
pub type PublicKey<C> = <C as ProjectiveCurve>::Affine;

/* ADDED BY ME FOR MUSIG2. */
pub type Point<C> = <C as ProjectiveCurve>::Affine;

#[derive(Clone, Default)]
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

#[derive(Clone, Default, Debug)]        // TODO: MUST REMOVE DEBUG
pub struct Signature<C: ProjectiveCurve> {
    pub prover_response: C::ScalarField,        // s - scalar representing signature proof
    pub verifier_challenge: [u8; 32],           // r - point on curve (usually just the x coordinate)
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
    
    /* NOT USED */
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

            // let hash_digest = CRH::evaluate(&hash_input);

            let hash_digest = Blake2s::digest(&hash_input);
            assert!(hash_digest.len() >= 32);
            let mut verifier_challenge = [0_u8; 32];
            verifier_challenge.copy_from_slice(&hash_digest);

            (random_scalar, verifier_challenge)
        };

        let verifier_challenge_fe = C::ScalarField::from_be_bytes_mod_order(&verifier_challenge);

        // k - xe;
        let prover_response = random_scalar - (verifier_challenge_fe * sk.secret_key);
        let signature = Signature {
            prover_response,
            verifier_challenge,
        };

        Ok(signature)
    }

    /* NOT USED */
    fn verify(
        parameters: &Self::Parameters,  // (dummy) needed because using crpto-primitives SignatureScheme
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        let Signature {
            prover_response,    // s
            verifier_challenge, // rx
        } = signature;
        // let verifier_challenge_fe = C::ScalarField::from_be_bytes_mod_order(verifier_challenge);    // e
        // sG = kG - eY
        // kG = sG + eY
        // so we first solve for kG.

        println!("PROVER RESPONSE {:?}", prover_response);
        println!("VERIFIER CHALLENGE {:?}", verifier_challenge);
        /* THIS IS compute_challenge_hash_tweak() */
        let mut agg_pubkey_serialized = [0u8; 32];
        pk.serialize(&mut agg_pubkey_serialized[..]);

        // println!("PK SERIALIZED {:?}", agg_pubkey_serialized);

        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(verifier_challenge);
        hash_input.extend_from_slice(&agg_pubkey_serialized);
        hash_input.extend_from_slice(message.as_ref());
        // println!("HASH INPUT {:?}", hash_input);
// let hello = parameters.generator;
        let hash = Blake2s::digest(&hash_input);
        // println!("HASH VALUE {:?}", hash);
        let e = C::ScalarField::from_be_bytes_mod_order(&hash);
        
        println!("GENERATOR {:?}", parameters.generator);
        let verification_point = parameters.generator.mul(*prover_response).sub(pk.mul(e)).into_affine();
        let mut verification_point_bytes = vec![];
        verification_point.serialize(&mut verification_point_bytes);

        println!("VERIFICATION POINT BYTES {:?}", verification_point_bytes);

        Ok(verification_point_bytes == verifier_challenge)
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

// impl<ConstraintF: Field, C: ProjectiveCurve + ToConstraintField<ConstraintF>>
//     ToConstraintField<ConstraintF> for Parameters<C>
// {
//     #[inline]
//     fn to_field_elements(&self) -> Option<Vec<ConstraintF>> {
//         self.generator.into_projective().to_field_elements()
//     }
// }

/* MUSIG2 IMPLEMENTED BY IHYUN. SOURCE: https://github.com/conduition/musig2.git. 
    HARDCODED FOR BLS12-381. */

fn compute_key_aggregation_coefficient<C: ProjectiveCurve>(
    pk_list_hash: &[u8; 32],
    pubkey: &Point<C>,
    pk2: Option<&Point<C>>,
) -> MaybeScalar<C> {
    if pk2.is_some_and(|pk2| pubkey == pk2) {
        return MaybeScalar::<C>::one();
    }

    let mut bytes = [0u8; 32];
    pubkey.serialize(&mut bytes[..]);

    // let mut bytes = Vec::new();
    // point.serialize(&mut bytes)?;

    // // Now `bytes` is a Vec<u8> which implements AsRef<[u8]>
    // println!("Serialized point: {:?}", bytes);

    // // If you need a reference to &[u8]
    // let bytes_slice: &[u8] = bytes.as_ref();

    // let hash: [u8; 32] = tagged_hashes::KEYAGG_COEFF_TAG_HASHER
    //     .clone()
    //     .chain_update(&pk_list_hash)
    //     .chain_update(&pubkey.serialize())
    //     .finalize()
    //     .into();
    
    let hash: [u8; 32] = KEYAGG_COEFF_TAG_HASHER
        .clone()
        .chain_update(&pk_list_hash)
        .chain_update(&bytes)
        // .chain_update(&pubkey)
        .finalize()
        .into();

    MaybeScalar::<C>::from_be_bytes_mod_order(&hash.to_vec())
}

fn hash_pubkeys<C: ProjectiveCurve>(ordered_pubkeys: &[Point<C>]) -> [u8; 32] {
    let mut h = KEYAGG_LIST_TAG_HASHER.clone();
    for pubkey in ordered_pubkeys {
        let mut bytes = [0u8; 32];
        pubkey.borrow().serialize(&mut bytes[..]);
        h.update(&bytes);
    }
    h.finalize().into()
}

#[derive(Debug, Clone)]
pub struct KeyAggContext<C: ProjectiveCurve> {
    /// The aggregated pubkey point `Q`.
    pub(crate) pubkey: PublicKey<C>,
    // pub(crate) pubkey: [u8;32],

    /// The component individual pubkeys in their original order.
    pub(crate) ordered_pubkeys: Vec<Point<C>>,
    // pub(crate) ordered_pubkeys: Vec<[u8;32]>,

    /// A map of pubkeys to their indexes in the [`ordered_pubkeys`][Self::ordered_pubkeys]
    /// field.
    pub(crate) pubkey_indexes: HashMap<Point<C>, usize>,
    // pub(crate) pubkey_indexes: HashMap<[u8;32], usize>,

    /// Cached key aggregation coefficients of individual pubkeys, in the
    /// same order as `ordered_pubkeys`.
    pub(crate) key_coefficients: Vec<MaybeScalar<C>>,

    /// A cache of effective individual pubkeys, i.e. `pubkey * self.key_coefficient(pubkey)`.
    pub(crate) effective_pubkeys: Vec<MaybePoint<C>>,

    pub(crate) parity_acc: subtle::Choice, // false means g=1, true means g=n-1
    pub(crate) tweak_acc: MaybeScalar::<C>,     // None means zero.
}

impl<C> KeyAggContext<C> where 
    C: ProjectiveCurve,
{
    pub fn aggregated_pubkey<T: From<Point<C>>>(&self) -> T {
        T::from(self.pubkey)
    }

    pub fn effective_pubkey<T: From<MaybePoint::<C>>>(&self, pubkey: impl Into<Point<C>>) -> Option<T> {
        let index = self.pubkey_index(pubkey)?;
        Some(T::from(self.effective_pubkeys[index]))
    }

    pub fn new(ordered_pubkeys: Vec<Point<C>>) -> Result<Self, KeyAggError>
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
        let pk2 = ordered_pubkeys[1..]
            .into_iter()
            .find(|pubkey| pubkey != &&ordered_pubkeys[0]);
        
        // println!("pk2 {:?}", pk2);

        let pk_list_hash: [u8; 32] = hash_pubkeys::<C>(&ordered_pubkeys);
        // println!("ORDERED PUBKEYS {:?}", ordered_pubkeys);      // ORDERS ARE CORRECT
        // println!("ORDERED PUBKEY POINT AT INF? {:?}", ordered_pubkeys[0].is_zero());
        // println!("ORDERED PUBKEY POINT AT INF? {:?}", ordered_pubkeys[1].is_zero());

        // NOTE: THIS DOESN'T CHECK FOR POINTS AT INFINITY. NOT READY FOR PRODUCTION.
        let (effective_pubkeys, key_coefficients): (Vec<Point<C>>, Vec<C::ScalarField>) =
            ordered_pubkeys
                .iter()
                .map(|&pubkey| {
                    let key_coeff =
                        compute_key_aggregation_coefficient::<C>(&pk_list_hash, &pubkey, pk2);       // pk2 IS LOG PUBKEY
                    (pubkey.mul(key_coeff).into_affine(), key_coeff)
                })
                .unzip();
        println!("EFFECTIVE PUBKEY POINT AT INF? {:?}", effective_pubkeys[0].is_zero());
        println!("EFFECTIVE PUBKEY POINT AT INF? {:?}", effective_pubkeys[1].is_zero());

        println!("EFFECTIVE PUBKEYS {:?}", effective_pubkeys);
        println!("KEY COEFFICIENTS {:?}", key_coefficients);

        // let aggregated_pubkey = MaybePoint::<C>::sum(&effective_pubkeys);
        let aggregated_pubkey = effective_pubkeys.clone().into_iter().fold(PublicKey::<C>::default(), |acc, item| acc + item);      // NOTE: CHANGED FROM &item to item
        // NOTE: ORIGINAL IMPLEMENTATION JUST 'FILTERS OUT' POINTS AT INFINITY BEFORE SUMMING
        println!("AGGREGATED PUBKEY POINT AT INF? {:?}", aggregated_pubkey.is_zero());
        let pubkey_indexes = HashMap::from_iter(
            ordered_pubkeys
                .iter()
                .copied()
                .enumerate()
                .map(|(i, pk)| (pk, i)),
        );
        // println!("PUBKEY INDEXES? {:?}", pubkey_indexes);
        Ok(KeyAggContext {
            pubkey: aggregated_pubkey,
            ordered_pubkeys,
            pubkey_indexes,
            key_coefficients,
            effective_pubkeys,
            parity_acc: subtle::Choice::from(0),
            tweak_acc: MaybeScalar::<C>::zero(),     // TODO: check what this does later
        })
    }

    pub fn pubkey_index(&self, pubkey: impl Into<Point<C>>) -> Option<usize> {
        self.pubkey_indexes.get(&pubkey.into()).copied()
    }

    pub fn key_coefficient(&self, pubkey: impl Into<Point<C>>) -> Option<MaybeScalar::<C>> {
        let index = self.pubkey_index(pubkey)?;
        Some(self.key_coefficients[index])
    }
}

// TODO: MUST REMOVE DEBUG LATER
pub struct SecNonce<C: ProjectiveCurve> {
    pub(crate) k1: SecretKey<C>,
    pub(crate) k2: SecretKey<C>,
}

impl<C> SecNonce<C> where C: ProjectiveCurve {
    /// Construct a new `SecNonce` from the given individual nonce values.
    pub fn new<T: Into<SecretKey<C>>>(k1: T, k2: T) -> SecNonce<C> {
        SecNonce::<C> {
            k1: k1.into(),
            k2: k2.into(),
        }
    }

    /// Constructs a new [`SecNonceBuilder`] from the given random nonce seed.
    ///
    /// See [`SecNonceBuilder::new`].
    pub fn build<'snb>(nonce_seed: impl Into<NonceSeed>) -> SecNonceBuilder<'snb,C> {
        SecNonceBuilder::new(nonce_seed)
    }

    // generator in pubkey generation = C::prime_subgroup_generator().into()
    pub fn public_nonce(&self) -> PubNonce<C> {
        PubNonce {
            R1: C::prime_subgroup_generator().into_affine().mul(self.k1.secret_key).into_affine(),        // G IS GENERATOR POINT. Double check G1 or G2 for bls12-381.
            R2: C::prime_subgroup_generator().into_affine().mul(self.k2.secret_key).into_affine(),
        }
    }
}

pub struct SecNonceBuilder<'snb, C: ProjectiveCurve> {
    nonce_seed_bytes: [u8; 32],
    seckey: Option<SecretKey<C>>,
    pubkey: Option<Point<C>>,
    aggregated_pubkey: Option<Point<C>>,
    message: Option<&'snb [u8]>,
    extra_inputs: Vec<&'snb dyn AsRef<[u8]>>,
}

impl<'snb,C> SecNonceBuilder<'snb,C> 
where C: ProjectiveCurve {
    /// Start building a nonce, seeded with the given random data
    /// source `nonce_seed`, which should either be
    ///
    /// - 32 bytes drawn from a cryptographically secure RNG, OR
    /// - a mutable reference to a secure RNG.
    ///
    /// ```
    /// use rand::RngCore as _;
    ///
    /// # #[cfg(feature = "rand")]
    /// // Sample the seed automatically
    /// let secnonce = musig2::SecNonceBuilder::new(&mut rand::rngs::OsRng)
    ///     .with_message(b"hello world!")
    ///     .build();
    ///
    /// // Sample the seed manually
    /// let mut nonce_seed = [0u8; 32];
    /// rand::rngs::OsRng.fill_bytes(&mut nonce_seed);
    /// let secnonce = musig2::SecNonceBuilder::new(nonce_seed)
    ///     .with_message(b"hello world!")
    ///     .build();
    /// ```
    ///
    /// # WARNING
    ///
    /// It is critical for the `nonce_seed` to be **sampled randomly,** and NOT
    /// constructed deterministically based on signing session data. Otherwise,
    /// the signer can be [tricked into reusing the same nonce for concurrent
    /// signing sessions, thus exposing their secret key.](
    #[doc = "https://medium.com/blockstream/musig-dn-schnorr-multisignatures\
             -with-verifiably-deterministic-nonces-27424b5df9d6#e3b6)"]
    pub fn new(nonce_seed: impl Into<NonceSeed>) -> SecNonceBuilder<'snb,C> {
        let NonceSeed(nonce_seed_bytes) = nonce_seed.into();
        SecNonceBuilder {
            nonce_seed_bytes,
            seckey: None,
            pubkey: None,
            aggregated_pubkey: None,
            message: None,
            extra_inputs: Vec::new(),
        }
    }

    /// Salt the resulting nonce with the public key expected to be used
    /// during the signing phase.
    ///
    /// The public key will be overwritten if [`SecNonceBuilder::with_seckey`]
    /// is used after this method.
    pub fn with_pubkey(self, pubkey: impl Into<Point<C>>) -> SecNonceBuilder<'snb,C> {
        SecNonceBuilder {
            pubkey: Some(pubkey.into()),
            ..self
        }
    }

    /// Salt the resulting nonce with the secret key which the nonce should be
    /// used to protect during the signing phase.
    ///
    /// Overwrites any public key previously added by
    /// [`SecNonceBuilder::with_pubkey`], as we compute the public key
    /// of the given secret key and add it to the builder.
    // pub fn with_seckey(self, seckey: impl Into<Fr>) -> SecNonceBuilder<'snb> {
    //     let seckey: Fr = seckey.into();
    //     SecNonceBuilder {
    //         seckey: Some(seckey),
    //         pubkey: Some(seckey * G),
    //         ..self
    //     }
    // }

    /// Salt the resulting nonce with the message which we expect to be signing with
    /// the nonce.
    // pub fn with_message<M: AsRef<[u8]>>(self, msg: &'snb M) -> SecNonceBuilder<'snb> {
    //     SecNonceBuilder {
    //         message: Some(msg.as_ref()),
    //         ..self
    //     }
    // }

    /// Salt the resulting nonce with the aggregated public key which we expect to aggregate
    /// signatures for.
    pub fn with_aggregated_pubkey(
        self,
        aggregated_pubkey: impl Into<Point<C>>,
    ) -> SecNonceBuilder<'snb,C> {
        SecNonceBuilder {
            aggregated_pubkey: Some(aggregated_pubkey.into()),
            ..self
        }
    }

    /// Salt the resulting nonce with arbitrary extra input bytes. This might be context-specific
    /// data like a signing session ID, the name of the protocol, the current timestamp, whatever
    /// you want, really.
    ///
    /// This method is additive; it does not overwrite the `extra_input` values added by previous
    /// invocations of itself. This allows the caller to salt the nonce with an arbitrary amount
    /// of extra entropy as desired, up to a limit of [`u32::MAX`] bytes (about 4GB). This method
    /// will panic if the sum of all extra inputs attached to the builder would exceed that limit.
    ///
    /// ```
    /// # let nonce_seed = [0xABu8; 32];
    /// let remote_ip = [127u8, 0, 0, 1];
    ///
    /// let secnonce = musig2::SecNonceBuilder::new(nonce_seed)
    ///     .with_extra_input(b"MyApp")
    ///     .with_extra_input(&remote_ip)
    ///     .with_extra_input(&String::from("What's up buttercup?"))
    ///     .build();
    /// ```
    // pub fn with_extra_input<E: AsRef<[u8]>>(
    //     mut self,
    //     extra_input: &'snb E,
    // ) -> SecNonceBuilder<'snb> {
    //     self.extra_inputs.push(extra_input);
    //     extra_input_length_check(&self.extra_inputs);
    //     self
    // }

    /// Sprinkles in a set of [`SecNonceSpices`] to this nonce builder. Extra inputs in
    /// `spices` are appended to the builder (see [`SecNonceBuilder::with_extra_input`]).
    /// All other parameters will be merged with those in `spices`, preferring parameters
    /// in `spices` if they are present.
    // pub fn with_spices(mut self, spices: SecNonceSpices<'snb>) -> SecNonceBuilder<'snb> {
    //     self.seckey = spices.seckey.or(self.seckey);
    //     self.message = spices.message.map(|msg| msg.as_ref()).or(self.message);

    //     let mut new_extra_inputs = spices.extra_inputs;
    //     self.extra_inputs.append(&mut new_extra_inputs);
    //     extra_input_length_check(&self.extra_inputs);

    //     self
    // }

    /// Build the secret nonce by hashing all of the builder's inputs into two
    /// byte arrays, and reducing those byte arrays modulo the curve order into
    /// two scalars `k1` and `k2`. These form the `SecNonce` as the tuple `(k1, k2)`.
    ///
    /// If the reduction results in an output of zero for either scalar,
    /// we use a nonce of 1 instead for that scalar.
    ///
    /// This method matches the standard nonce generation algorithm specified in
    /// [BIP327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki),
    /// except in the extremely unlikely case of a hash reducing to zero.
    pub fn build(self) -> SecNonce<C> {
        let seckey_bytes = match self.seckey {
            Some(seckey) => {
                let mut bytes = [0u8; 32];
                seckey.secret_key.serialize(&mut bytes[..]);
                bytes
            },
            None => [0u8; 32],
        };

        let nonce_seed_hash: [u8; 32] = MUSIG_AUX_TAG_HASHER
            .clone()
            .chain_update(&self.nonce_seed_bytes)
            .finalize()
            .into();

        let mut hasher = MUSIG_NONCE_TAG_HASHER
            .clone()
            .chain_update(&xor_bytes(&seckey_bytes, &nonce_seed_hash));

        // BIP327 doesn't allow the public key to be an optional argument,
        // but there is no hard reason for that other than 'the RNG might fail'.
        // For ergonomics we allow the pubkey to be omitted here in the same
        // fashion as the aggregated pubkey.
        match self.pubkey {
            None => hasher.update(&[0]),
            Some(pubkey) => {
                hasher.update(&[33]); // individual pubkey len
                let mut bytes = [0u8; 32];
                pubkey.serialize(&mut bytes[..]);
                hasher.update(&bytes);
            }
        }

        match self.aggregated_pubkey {
            None => hasher.update(&[0]),
            Some(aggregated_pubkey) => {
                hasher.update(&[32]); // aggregated pubkey len
                // hasher.update(&aggregated_pubkey.serialize_xonly()); // THIS SERIALIZES ONLY THE X COORDINATE OF PUBKEY (AFFINE)
                let mut bytes = [0u8; 32];
                aggregated_pubkey.serialize(&mut bytes[..]);
                hasher.update(&bytes);
            }
        };

        match self.message {
            None => hasher.update(&[0]),
            Some(message) => {
                hasher.update(&[1]);
                hasher.update(&(message.len() as u64).to_be_bytes());
                hasher.update(message);
            }
        };

        // We still write the extra input length if the caller provided empty extra info.
        if self.extra_inputs.len() > 0 {
            let extra_input_total_len: usize = self
                .extra_inputs
                .iter()
                .map(|extra_in| extra_in.as_ref().len())
                .sum();

            hasher.update(&(extra_input_total_len as u32).to_be_bytes());
            for extra_input in self.extra_inputs {
                hasher.update(extra_input.as_ref());
            }
        }

        // Cloning the hash engine state reduces the computations needed.
        let hash1 = <[u8; 32]>::from(hasher.clone().chain_update(&[0]).finalize());
        let hash2 = <[u8; 32]>::from(hasher.clone().chain_update(&[1]).finalize());

        let k1: MaybeScalar::<C> = MaybeScalar::<C>::from_be_bytes_mod_order(&hash1);
        let k1: MaybeScalar::<C> = if k1.is_zero() {
            MaybeScalar::<C>::one()
        } else {
            k1
        };
        let k2: MaybeScalar::<C> = MaybeScalar::<C>::from_be_bytes_mod_order(&hash2);
        let k2: MaybeScalar::<C> = if k2.is_zero() {
            MaybeScalar::<C>::one()
        } else {
            k2
        };

        let seckey1 = SecretKey {secret_key: k1, public_key: PublicKey::<C>::default()};
        let seckey2 = SecretKey {secret_key: k2, public_key: PublicKey::<C>::default()};
        SecNonce { k1: seckey1, k2: seckey2 }
    }
}

struct Slots<T: Clone + Eq> {
    slots: Vec<Option<T>>,
    open_slots: Vec<usize>,
}

impl<T: Clone + Eq> Slots<T> {
    /// Create a new set of slots.
    fn new(expected_size: usize) -> Slots<T> {
        let mut slots = Vec::new();
        slots.resize(expected_size, None);
        let open_slots = Vec::from_iter(0..expected_size);
        // let open_slots = vec![]; // NOTE: CHANGED TO 0 TO DISABLE 'WAITING FOR NONCES'
        Slots { slots, open_slots }
    }

    /// Add an item to a specific slot, returning an error if the
    /// slot is already taken by a different item. Idempotent.
    fn place(&mut self, value: T, index: usize) -> Result<(), RoundContributionError> {
        if index >= self.slots.len() {
            return Err(RoundContributionError::out_of_range(
                index,
                self.slots.len(),
            ));
        }

        // Support idempotence. Callers can place the same value into the same
        // slot index, which should be a no-op.
        if let Some(ref existing) = self.slots[index] {
            if &value == existing {
                return Ok(());
            } else {
                return Err(RoundContributionError::inconsistent_contribution(index));
            }
        }

        self.slots[index] = Some(value);
        self.open_slots
            .remove(self.open_slots.binary_search(&index).unwrap());
        Ok(())
    }

    /// Returns the full array of slot values in order.
    /// Returns `None` if any slot is not yet filled.
    fn finalize(self) -> Result<Vec<T>, RoundFinalizeError> {
        self.slots
            .into_iter()
            .map(|opt| opt.ok_or(RoundFinalizeError::Incomplete))
            .collect()
    }
}

// #[derive(Debug, Eq, PartialEq, Clone, Hash, Ord, PartialOrd)]
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct PubNonce<C: ProjectiveCurve> {
    pub R1: Point<C>,
    pub R2: Point<C>,
}


/// A state machine which manages the first round of a MuSig2 signing session.
///
/// Its task is to collect [`PubNonce`]s one by one until all signers have provided
/// one, at which point a partial signature can be created on a message using an
/// internally cached [`SecNonce`].
///
/// By preventing cloning or copying, and by consuming itself after creating a
/// partial signature, `FirstRound`'s API is written to encourage that a
/// [`SecNonce`] should **never be reused.** Take care not to shoot yourself in
/// the foot by attempting to work around this restriction.
pub struct FirstRound<C: ProjectiveCurve> {
    key_agg_ctx: KeyAggContext<C>,
    signer_index: usize, // Our key's index in `key_agg_ctx`
    secnonce: SecNonce<C>,  // Our secret nonce.
    // pubnonce_slots: Slots<PubNonce>,
}

impl<C> FirstRound<C> where 
C: ProjectiveCurve
{
    pub fn our_public_nonce(&self) -> PubNonce<C> {
        self.secnonce.public_nonce()
    }
    
    /// Start the first round of a MuSig2 signing session.
    ///
    /// Generates the nonce using the given random seed value, which can
    /// be any type that converts to `NonceSeed`. Usually this would
    /// either be a `[u8; 32]` or any type that implements [`rand::RngCore`]
    /// and [`rand::CryptoRng`], such as [`rand::rngs::OsRng`].
    /// If a static byte array is used as the seed, it should be generated
    /// using a cryptographically secure RNG and discarded after the `FirstRound`
    /// is created. Prefer using a [`rand::CryptoRng`] if possible, so that
    /// there is no possibility of reusing the same nonce seed in a new signing
    /// session.
    ///
    /// Returns an error if the given signer index is out of range.
    pub fn new(
        key_agg_ctx: KeyAggContext<C>,
        nonce_seed: impl Into<NonceSeed>,
        signer_index: usize,
        // spices: SecNonceSpices<'_>,
    ) -> Result<FirstRound<C>, SignerIndexError> {
        let signer_pubkey: Point<C> = key_agg_ctx
            .ordered_pubkeys[signer_index];
            // .ok_or_else(|| SignerIndexError::new(signer_index, key_agg_ctx.ordered_pubkeys.len()))?;
        let aggregated_pubkey: Point<C> = key_agg_ctx.aggregated_pubkey();

        let secnonce: SecNonce<C> = SecNonce::build(nonce_seed)
            .with_pubkey(signer_pubkey)
            .with_aggregated_pubkey(aggregated_pubkey)
            // .with_extra_input(&(signer_index as u32).to_be_bytes())  // SEEMS EXTRA
            // .with_spices(spices)     // SEEMS EXTRA
            .build();

        // let pubnonce = secnonce.public_nonce();
        // println!("PUBLIC NONCE COMPUTED INSIDE NEW {:?}", pubnonce);

        // let mut pubnonce_slots = Slots::new(key_agg_ctx.ordered_pubkeys.len());
        // pubnonce_slots.place(pubnonce, signer_index).unwrap(); // never fails

        // println!("MY SECNONCE {:?}", secnonce);
        Ok(FirstRound {
            key_agg_ctx,
            secnonce,
            signer_index,
            // pubnonce,
        })
    }

    // NOTE: WE ONLY PASS IN ONE SECKEY (LOG AND USER INDIVIDUALLY) AND ORIGINALLY THIS IS INSIDE VEC ITERATOR SO IT WORKS FINE
    pub fn finalize<M>(
        self,
        seckey: SecretKey<C>,
        message: M,
        pubnonces: Vec<PubNonce<C>>,
        poseidon_params: &Poseidon<ConstraintF<C>, MyPoseidonParams>,
    ) -> Result<SecondRound<M,C>, RoundFinalizeError>
    where
        M: AsRef<[u8]>,
    {
        self.finalize_adaptor(seckey, message, pubnonces, &poseidon_params)
    }

    /// Finishes the first round once all nonces are received, combining nonces
    /// into an aggregated nonce, and creating a partial adaptor signature using
    /// `seckey` on a given `message`, both of which are stored in the returned
    /// `SecondRound`.
    ///
    /// The `adaptor_point` is used to verifiably encrypt the partial signature, so that
    /// the final aggregated signature will need to be adapted with the discrete log
    /// of `adaptor_point` before the signature can be considered valid. All signers
    /// must agree on and use the same adaptor point for the final signature to be valid.
    ///
    /// See [`SecondRound::aggregated_nonce`] to access the aggregated nonce,
    /// and [`SecondRound::our_signature`] to access the partial signature.
    ///
    /// This method intentionally consumes the `FirstRound`, to avoid accidentally
    /// reusing a secret-nonce.
    ///
    /// This method should only be invoked once [`is_complete`][Self::is_complete]
    /// returns true, otherwise it will fail. Can also return an error if partial
    /// signing fails, probably because the wrong secret key was given.
    ///
    /// For all partial signatures to be valid, everyone must naturally be signing the
    /// same message.
    pub fn finalize_adaptor<M>(
        self,
        seckey: SecretKey<C>,
        // adaptor_point: MaybePoint::<C>,
        message: M,
        pubnonces: Vec<PubNonce<C>>,
        poseidon_params: &Poseidon<ConstraintF<C>, MyPoseidonParams>,
    ) -> Result<SecondRound<M,C>, RoundFinalizeError>
    where
        M: AsRef<[u8]>,
    {
        // let adaptor_point: MaybePoint::<C> = adaptor_point.into();
        // let pubnonces: Vec<PubNonce> = self.pubnonce_slots.finalize()?; // NOT RELATED TO ADAPTOR
        let aggnonce_r1 = pubnonces.clone().into_iter().fold(C::Affine::default(), |acc, item| acc + item.R1);      // NOTE: CHANGED FROM &item to item
        let aggnonce_r2 = pubnonces.clone().into_iter().fold(C::Affine::default(), |acc, item| acc + item.R2);
        let aggnonce = AggNonce::<C> { R1: aggnonce_r1, R2: aggnonce_r2 };

        // let aggnonce = pubnonces.iter().sum();
        // println!("MY SECNONCE {:?}", self.secnonce);
        let partial_signature: PartialSignature<C> = sign_partial_adaptor::<_, PartialSignature<C>,C>(
            &self.key_agg_ctx,
            seckey,
            self.secnonce,
            &aggnonce,
            // adaptor_point,
            &message,
            poseidon_params,
        )?;

        // println!("PARTIAL SIGNATURE CREATED {:?} FOR {:?}", partial_signature, self.signer_index);
        let mut partial_signature_slots = Slots::new(pubnonces.len());
        // println!("SLOTS SIZE {:?}", pubnonces.len());    // SLOTS SIZE 2 AS REQUIRED
        partial_signature_slots
            .place(partial_signature, self.signer_index)
            .unwrap(); // never fails

        // println!("AGGNONCE INSIDE FINALIZE ADAPTOR {:?}", aggnonce); // NOTE: AGGNONCE EQUAL AS REQUIRED
        // println!("MESSAGE INSIDE PARTIAL SIGNATURE{:?}", message);
        let second_round = SecondRound::<M,C> {
            key_agg_ctx: self.key_agg_ctx,
            signer_index: self.signer_index,
            pubnonces,
            aggnonce,
            // adaptor_point,
            message,
            partial_signature_slots,
        };

        Ok(second_round)
    }
}

pub fn xor_bytes<const SIZE: usize>(a: &[u8; SIZE], b: &[u8; SIZE]) -> [u8; SIZE] {
    let mut out = [0; SIZE];
    for i in 0..SIZE {
        out[i] = a[i] ^ b[i]
    }
    out
}

pub type PartialSignature<C> = <C as ProjectiveCurve>::ScalarField;

pub struct SecondRound<M: AsRef<[u8]>, C:ProjectiveCurve> {
    key_agg_ctx: KeyAggContext<C>,
    signer_index: usize,
    pubnonces: Vec<PubNonce<C>>,
    aggnonce: AggNonce<C>,
    // adaptor_point: MaybePoint::<C>,
    message: M,
    partial_signature_slots: Slots<PartialSignature<C>>,
}

impl<M: AsRef<[u8]>, C:ProjectiveCurve> SecondRound<M,C> {
    /// Returns the aggregated nonce built from the nonces provided in the first round.
    /// Signers who find themselves in an aggregator role can distribute this aggregated
    /// nonce to other signers to that they can produce an aggregated signature without
    /// 1:1 communication between every pair of signers.
    pub fn aggregated_nonce(&self) -> &AggNonce<C> {
        &self.aggnonce
    }

    /// Returns the partial signature created during finalization of the first round.
    pub fn our_signature<T: From<PartialSignature<C>>>(&self) -> T {
        self.partial_signature_slots.slots[self.signer_index]
            .map(T::from)
            .unwrap() // never fails
    }

    /// Returns a slice of all signer indexes from whom we have yet to receive a
    /// [`PartialSignature`]. Note that since our signature was constructed
    /// at the end of the first round, this slice will never contain the signer
    /// index provided to [`FirstRound::new`].
    // pub fn holdouts(&self) -> &[usize] {
    //     self.partial_signature_slots.remaining()
    // }

    /// Adds a [`PartialSignature`] to the internal state, registering it to a specific
    /// signer at a given index. Returns an error if the signature is not valid, or if
    /// the given signer index is out of range, or if we already have a different partial
    /// signature on-file for that signer.
    // pub fn receive_signature(
    //     &mut self,
    //     signer_index: usize,
    //     partial_signature: impl Into<PartialSignature>,
    // ) -> Result<(), RoundContributionError> {
    //     let partial_signature: PartialSignature = partial_signature.into();
    //     let signer_pubkey: Point = self.key_agg_ctx.get_pubkey(signer_index).ok_or_else(|| {
    //         RoundContributionError::out_of_range(signer_index, self.key_agg_ctx.pubkeys().len())
    //     })?;

    //     musig2::adaptor::verify_partial(
    //         &self.key_agg_ctx,
    //         partial_signature,
    //         &self.aggnonce,
    //         // self.adaptor_point,
    //         signer_pubkey,
    //         &self.pubnonces[signer_index],
    //         &self.message,
    //     )
    //     .map_err(|_| RoundContributionError::invalid_signature(signer_index))?;

    //     self.partial_signature_slots
    //         .place(partial_signature, signer_index)?;

    //     Ok(())
    // }

    // /// Returns true once we have all partial signatures from the group.
    // pub fn is_complete(&self) -> bool {
    //     self.holdouts().len() == 0
    // }

    /// Finishes the second round once all partial signatures are received,
    /// combining signatures into an aggregated signature on the `message`
    /// given to [`FirstRound::finalize`].
    ///
    /// This method should only be invoked once [`is_complete`][Self::is_complete]
    /// returns true, otherwise it will fail. Can also return an error if partial
    /// signature aggregation fails, but if [`receive_signature`][Self::receive_signature]
    /// didn't complain, then finalizing will succeed with overwhelming probability.
    ///
    /// If the [`FirstRound`] was finalized with [`FirstRound::finalize_adaptor`], then
    /// the second round must also be finalized with [`SecondRound::finalize_adaptor`],
    /// otherwise this method will return [`RoundFinalizeError::InvalidAggregatedSignature`].
    pub fn finalize(self, partial_signatures: Vec<PartialSignature<C>>, poseidon_params: &Poseidon<ConstraintF<C>, MyPoseidonParams>) -> Result<Signature<C>, RoundFinalizeError>
    // where
    //     T: From<LiftedSignature>,
    {
        let sig = self
            .finalize_adaptor(partial_signatures, poseidon_params)?;
            // .adapt(MaybeScalar::<C>::Zero)    // WHAT THIS DOES: Adapts the signature into a lifted signature with a given adaptor secret.
            // .expect("finalizing with empty adaptor should never result in an adaptor failure");

        Ok(sig)
    }

    /// Finishes the second round once all partial adaptor signatures are received,
    /// combining signatures into an aggregated adaptor signature on the `message`
    /// given to [`FirstRound::finalize`].
    ///
    /// To make this signature valid, it must then be adapted with the discrete log
    /// of the adaptor point given to [`FirstRound::finalize`].
    ///
    /// This method should only be invoked once [`is_complete`][Self::is_complete]
    /// returns true, otherwise it will fail. Can also return an error if partial
    /// signature aggregation fails, but if [`receive_signature`][Self::receive_signature]
    /// didn't complain, then finalizing will succeed with overwhelming probability.
    ///
    /// If this signing session did not use adaptor signatures, the signature returned by
    /// this method will be a valid signature which can be adapted with `MaybeScalar::<C>::Zero`.
    pub fn finalize_adaptor(self, partial_signatures: Vec<PartialSignature<C>>, poseidon_params: &Poseidon<ConstraintF<C>, MyPoseidonParams>) -> Result<Signature<C>, RoundFinalizeError> {
        // let partial_signatures: Vec<PartialSignature<C>> = self.partial_signature_slots.finalize()?;   // FINALIZE UNRELATED TO ADAPTOR
        let final_signature = aggregate_partial_signatures(
            &self.key_agg_ctx,
            &self.aggnonce,
            partial_signatures,
            &self.message,
            poseidon_params,
        )?;
        Ok(final_signature)
    }
}

// #[derive(Debug, Eq, PartialEq, Clone, Hash, Ord, PartialOrd)]
// NOTE: Ord and PartialOrd are for comparisons. If needed, do manual coordinate-wise comparisons.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct AggNonce<C: ProjectiveCurve> {
    #[allow(missing_docs)]
    pub R1: MaybePoint::<C>,
    #[allow(missing_docs)]
    pub R2: MaybePoint::<C>,
}

impl<C> AggNonce<C> where 
C: ProjectiveCurve
{
    /// Construct a new `AggNonce` from the given pair of public nonce points.

    pub fn sum<T, I>(nonces: I) -> AggNonce<C>
    where
        T: std::borrow::Borrow<PubNonce<C>>,
        I: IntoIterator<Item = T>,
    {
        let (r1s, r2s): (Vec<Point<C>>, Vec<Point<C>>) = nonces
            .into_iter()
            .map(|pubnonce| (pubnonce.borrow().R1, pubnonce.borrow().R2))
            .unzip();

        let sum_r1 = r1s.into_iter().fold(Point::<C>::zero(), |acc, point| acc.add(point));     // NOTE: Changed from &point to point
        let sum_r2 = r2s.into_iter().fold(Point::<C>::zero(), |acc, point| acc.add(point));

        AggNonce {
            R1: sum_r1,        // result is MaybePoint::<C>
            R2: sum_r2,
        }
    }

    /// Computes the nonce coefficient `b`, used to create the final nonce and signatures.
    ///
    /// Most use-cases will not need to invoke this method. Instead use
    /// [`sign_solo`][crate::sign_solo] or [`sign_partial`][crate::sign_partial]
    /// to create signatures.
    pub fn nonce_coefficient<S>(
        &self,
        aggregated_pubkey: Point<C>,
        message: impl AsRef<[u8]>,
    ) -> S
    where
        S: From<MaybeScalar::<C>>,
    {
        let mut r1_bytes = vec![];
        self.R1.serialize(&mut r1_bytes);
        let mut r2_bytes = vec![];
        self.R2.serialize(&mut r2_bytes);
        let mut aggregated_pubkey_bytes = vec![];
        aggregated_pubkey.serialize(&mut aggregated_pubkey_bytes);
        
        let hash: [u8; 32] = MUSIG_NONCECOEF_TAG_HASHER
            .clone()
            .chain_update(&r1_bytes)     // R1 = Point i.e. PublicKey
            .chain_update(&r2_bytes)
            .chain_update(&aggregated_pubkey_bytes) // NOTE: CHANGED FROM XONLY
            .chain_update(message.as_ref())
            .finalize()
            .into();

        S::from(MaybeScalar::<C>::from_be_bytes_mod_order(&hash))
    }

    /// Computes the final public nonce point, published with the aggregated signature.
    /// If this point winds up at infinity (probably due to a mischevious signer), we
    /// instead return the generator point `G`.
    ///
    /// Most use-cases will not need to invoke this method. Instead use
    /// [`sign_solo`][crate::sign_solo] or [`sign_partial`][crate::sign_partial]
    /// to create signatures.
    pub fn final_nonce(&self, nonce_coeff: impl Into<MaybeScalar::<C>>) -> Point<C> // NOTE: changed from generic point parameter P
    // where
    //     P: From<Point>,
    {
        let nonce_coeff: MaybeScalar::<C> = nonce_coeff.into();
        let aggnonce_sum = self.R1 + (self.R2.mul(nonce_coeff).into_affine());
        // P::from(match aggnonce_sum {
        //     MaybePoint::<C>::Infinity => Point::generator(),
        //     MaybePoint::<C>::Valid(p) => p,
        // })

        println!("AGGNONCE SUM {:?}", aggnonce_sum);
        aggnonce_sum
    }
}

impl<P,C> std::iter::Sum<P> for AggNonce<C>
where
    P: std::borrow::Borrow<PubNonce<C>>,
    C: ProjectiveCurve,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = P>,
    {
        let refs = iter.collect::<Vec<P>>();
        AggNonce::sum(refs.iter().map(|nonce| nonce.borrow()))
    }
}

pub fn sign_partial_adaptor<S: From<MaybeScalar::<C>>, T: From<PartialSignature<C>>, C: ProjectiveCurve>(
    key_agg_ctx: &KeyAggContext<C>,
    seckey: SecretKey<C>,
    secnonce: SecNonce<C>,
    aggregated_nonce: &AggNonce<C>,
    // adaptor_point: impl Into<MaybePoint::<C>>,
    message: impl AsRef<[u8]>,
    poseidon_params: &Poseidon<ConstraintF<C>, MyPoseidonParams>, 
) -> Result<T, SigningError> {
    // let adaptor_point: MaybePoint::<C> = adaptor_point.into();
    // let seckey: Scalar = seckey.into(); // TODO: JUST EXTRACT THE SCALAR OUT OF SECKEY
    let pubkey = seckey.public_key;     // CORRECTLY RECONSTRUCTS PUBKEY FROM OUTSIDE 
    // println!("PUBKEY INSIDE SIGN PARTIAL ADAPTOR {:?}", pubkey);
    let seckey = seckey.secret_key;
    // let pubkey = seckey.base_point_mul();

    // As a side-effect, looking up the cached key coefficient also confirms
    // the individual key is indeed part of the aggregated key.
    let key_coeff = key_agg_ctx
        .key_coefficient(pubkey)
        .ok_or(SigningError::UnknownKey)?;

    let aggregated_pubkey = key_agg_ctx.pubkey;
    let pubnonce = secnonce.public_nonce();

    let b: MaybeScalar::<C> = aggregated_nonce.nonce_coefficient(aggregated_pubkey, &message);
    let final_nonce: Point<C> = aggregated_nonce.final_nonce(b);
    // let adapted_nonce = final_nonce + adaptor_point;

    // TODO: DOES PARITY LOGIC STILL STAND FOR BLS12-381?
    // `d` is negated if only one of the parity accumulator OR the aggregated pubkey
    // has odd parity.
    // let d = seckey.negate_if(aggregated_pubkey.parity() ^ key_agg_ctx.parity_acc);
    let d = seckey;
    // if aggregated_pubkey.parity() ^ key_agg_ctx.parity_acc {     // NOTE: TOOK OUT PARITY CHECK
    //     d.neg();    
    // }
    // println!("D SUPPOSED TO BE SAME {:?}", d);
    // let nonce_x_bytes = adapted_nonce.serialize_xonly();
    let mut nonce_x_bytes = vec![];     // TODO: INEFFICIENT (also look into affine addition - inefficient)
    final_nonce.serialize(&mut nonce_x_bytes);
    let mut array = [0u8; 32];
    array.copy_from_slice(&nonce_x_bytes[..32]);
    let e: MaybeScalar::<C> = compute_challenge_hash_tweak::<C::ScalarField,C>(&array, &aggregated_pubkey, &message, poseidon_params);

    // if has_even_Y(R):
    //   k = k1 + b*k2
    // else:
    //   k = (n-k1) + b(n-k2)
    //     = n - (k1 + b*k2)
    // NOTE: I THINK USING Y-COORDINATE PARITY IS STILL FINE FOR BLS12-381 BECAUSE
    // POINTS HAVE 2 REPRESENTATIONS FOR POSITIVE AND NEGATIVE Y-COORDINATES STILL APPLY
    // AND THE POINT OF NEGATING IS FOR CONSISTENCY IN GENERATED SIGNATURES ACROSS SIGNERS
    let secnonce_sum = secnonce.k1.secret_key + b * secnonce.k2.secret_key;

    // NOTE: I'M TAKING OUT THE PARITY CONSISTENCY CHECK BECAUSE WE ONLY HAVE LOG & USER BUT BRING IT BACK IN IF TROUBLE LATER
    // if final_nonce. {       // TODO: where is is_even, is_odd?
    //     secnonce_sum.secret_key.neg();
    // }

    // s = k + e*a*d
    let partial_signature: C::ScalarField = secnonce_sum + (e * key_coeff * d);

    verify_partial_adaptor::<C::ScalarField, C>(
        key_agg_ctx,
        partial_signature,
        aggregated_nonce,
        // adaptor_point,
        pubkey,
        &pubnonce,
        &message,
        poseidon_params,
    )?;

    Ok(T::from(partial_signature))
}

/// Computes the challenge hash `e` for for a signature. You probably don't need
/// to call this directly. Instead use [`sign_solo`][crate::sign_solo] or
/// [`sign_partial`][crate::sign_partial].
pub fn compute_challenge_hash_tweak<S, C: ProjectiveCurve>(
    final_nonce_xonly: &[u8; 32],
    aggregated_pubkey: &Point<C>,
    message: impl AsRef<[u8]>,
    poseidon_params: &Poseidon<ConstraintF<C>, MyPoseidonParams>,
) -> S 
where
    S: From<MaybeScalar::<C>>,
    // C: ProjectiveCurve,
    {
    let mut agg_pubkey_serialized = vec![];
    aggregated_pubkey.serialize(&mut agg_pubkey_serialized);
    // let mut bytes = [0u8; 32];
    // aggregated_pubkey.serialize(&mut bytes[..]);
    // let agg_pubkey_copy = agg_pubkey_serialized.clone();
    // let hash: [u8; 32] = BIP0340_CHALLENGE_TAG_HASHER
    //     .clone()
    //     .chain_update(final_nonce_xonly)
    //     .chain_update(&agg_pubkey_serialized)
    //     .chain_update(message.as_ref())
    //     .finalize()
    //     .into();

    // let hash_input = final_nonce_xonly;
    // let mut hash_input: Vec<u8> = Vec::new();
    // hash_input.extend_from_slice(final_nonce_xonly);
    // hash_input.extend_from_slice(&bytes);
    // hash_input.extend_from_slice(message.as_ref());
    
    // println!("HASH INPUT INSIDE TWEAK() {:?}", hash_input.len());       // length is 160
    // let poseidon_params = Poseidon::<ConstraintF<C>, PoseidonRoundParams<F>> {
    //     params: MyPoseidonParams::default(),
    //     round_keys: vec![],
    //     mds_matrix: vec![],     // TODO: generate mds matrix
    // };

    println!("HASH INPUT INSIDE TWEAK() {:?}", final_nonce_xonly);
    println!("HASH INPUT INSIDE TWEAK() {:?}", agg_pubkey_serialized);
    println!("HASH INPUT INSIDE TWEAK() {:?}", message.as_ref());

    let mut vector1 = vec![];
    let mut vector2 = vec![];
    let mut vector3 = vec![];

    // println!("PARAMS INSIDE TWEAK {:?}", poseidon_params);

    let hash1 = CRH::<ConstraintF<C>,MyPoseidonParams>::evaluate(poseidon_params, final_nonce_xonly).unwrap();
    println!("HASH1 INSIDE TWEAK {:?}", hash1);
    let hash2 = CRH::<ConstraintF<C>,MyPoseidonParams>::evaluate(poseidon_params, &agg_pubkey_serialized).unwrap();
    println!("HASH2 INSIDE TWEAK {:?}", hash2);
    let hash3 = CRH::<ConstraintF<C>,MyPoseidonParams>::evaluate(poseidon_params, message.as_ref()).unwrap();
    println!("HASH3 INSIDE TWEAK {:?}", hash3);
    // Serialize each hash into its own vector
    hash1.serialize(&mut vector1).unwrap();
    hash2.serialize(&mut vector2).unwrap();
    hash3.serialize(&mut vector3).unwrap();

    // Concatenate the vectors
    let mut final_vector = Vec::with_capacity(vector1.len() + vector2.len() + vector3.len());
    final_vector.extend(vector1);
    final_vector.extend(vector2);
    final_vector.extend(vector3);

    println!("VECTOR LENGTH {:?}", final_vector.len());

    println!("FINAL VECTOR INSIDE TWEAK {:?}", final_vector);
    S::from(MaybeScalar::<C>::from_be_bytes_mod_order(&final_vector))
}


/// Verify a partial signature, usually from an untrusted co-signer,
/// which has been encrypted under an adaptor point.
///
/// If `verify_partial_adaptor` succeeds for every signature in
/// a signing session, the resulting aggregated signature is guaranteed
/// to be valid once it is adapted with the discrete log (secret key)
/// of `adaptor_point`.
///
/// Returns an error if the given public key doesn't belong to the
/// `key_agg_ctx`, or if the signature is invalid.
pub fn verify_partial_adaptor<S: From<MaybeScalar::<C>>, C: ProjectiveCurve>(
    key_agg_ctx: &KeyAggContext<C>,
    partial_signature: PartialSignature<C>,
    aggregated_nonce: &AggNonce<C>,
    // adaptor_point: impl Into<MaybePoint::<C>>,
    individual_pubkey: impl Into<Point<C>>,
    individual_pubnonce: &PubNonce<C>,
    message: impl AsRef<[u8]>,
    poseidon_params: &Poseidon<ConstraintF<C>, MyPoseidonParams>,
) -> Result<(), VerifyError> {
    // let partial_signature: MaybeScalar::<C> = partial_signature.into();

    // As a side-effect, looking up the cached effective key also confirms
    // the individual key is indeed part of the aggregated key.
    let effective_pubkey: MaybePoint::<C> = key_agg_ctx
        .effective_pubkey(individual_pubkey)
        .ok_or(VerifyError::UnknownKey)?;

    let aggregated_pubkey = key_agg_ctx.pubkey;

    let b: MaybeScalar::<C> = aggregated_nonce.nonce_coefficient(aggregated_pubkey, &message);
    let final_nonce: Point<C> = aggregated_nonce.final_nonce(b);
    // let adapted_nonce = final_nonce + adaptor_point.into();

    let effective_nonce = individual_pubnonce.R1 + individual_pubnonce.R2.mul(b).into_affine();

    // Don't need constant time ops here as adapted_nonce is public.
    // if final_nonce.has_odd_y() {         // NOTE: TOOK OUT PARITY CHECK
    //     effective_nonce = -effective_nonce;
    // }

    // TODO: ORIGINAL CODE HAS PARITY CHECK
    //     if adapted_nonce.has_odd_y() {
    //     effective_nonce = -effective_nonce;
    // }

    let mut nonce_x_bytes = vec![];
    final_nonce.serialize(&mut nonce_x_bytes);
    let mut array = [0u8; 32];
    array.copy_from_slice(&nonce_x_bytes[..32]);    // TODO: CHECK 32 RANGE BOUND
    let e: MaybeScalar::<C> = compute_challenge_hash_tweak::<C::ScalarField,C>(&array, &aggregated_pubkey, &message, poseidon_params);

    // s * G == R + (g * gacc * e * a * P)
    // let challenge_parity = aggregated_pubkey.parity() ^ key_agg_ctx.parity_acc;
    let challenge_point = effective_pubkey.mul(e).into_affine();
    // if challenge_parity {
    //     challenge_point.neg();
    // }

    // TODO: double check G1 or G2
    if C::prime_subgroup_generator().into_affine().mul(partial_signature).into_affine() != effective_nonce + challenge_point {
        return Err(VerifyError::BadSignature);
    }

    Ok(())
}

/// Aggregate a collection of partial adaptor signatures together into a final
/// adaptor signature on a given `message`, under the aggregated public key in
/// `key_agg_ctx`.
///
/// The resulting signature will not be valid unless adapted with the discrete log
/// of the `adaptor_point`.
///
/// Returns an error if the resulting signature would not be valid.
pub fn aggregate_partial_adaptor_signatures<S: Into<PartialSignature<C>>, C: ProjectiveCurve> (
    key_agg_ctx: &KeyAggContext<C>,
    aggregated_nonce: &AggNonce<C>,
    // adaptor_point: impl Into<MaybePoint::<C>>,
    partial_signatures: impl IntoIterator<Item = S>,
    message: impl AsRef<[u8]>,
    poseidon_params: &Poseidon<ConstraintF<C>, MyPoseidonParams>,
) -> Result<Signature<C>, VerifyError> {
    // let adaptor_point: MaybePoint::<C> = adaptor_point.into();
    let aggregated_pubkey = key_agg_ctx.pubkey;

    let b: MaybeScalar::<C> = aggregated_nonce.nonce_coefficient(aggregated_pubkey, &message);
    let final_nonce: Point<C> = aggregated_nonce.final_nonce(b);
    // let adapted_nonce = final_nonce + adaptor_point;
    let mut nonce_x_bytes = vec![];
    final_nonce.serialize(&mut nonce_x_bytes);
    // NOTE: FOR BLS12-381, X COORDINATE DOESN'T UNIQUELY IDENTIFY THE POINT ON CURVE SO SERIALIZE ENTIRE AFFINE
    let mut array = [0u8; 32];
    array.copy_from_slice(&nonce_x_bytes[..32]);    // TODO: CHECK 32 RANGE BOUND
    // let nonce_x_bytes = final_nonce.x.serialize();
    let e: MaybeScalar::<C> = compute_challenge_hash_tweak::<C::ScalarField,C>(&array, &aggregated_pubkey, &message, poseidon_params);

    let elem = e * key_agg_ctx.tweak_acc;
    // if aggregated_pubkey.parity() {  // NOTE: TOOK OUT PARITY CHECK
    //     elem.neg();
    // }
    let aggregated_signature = partial_signatures
        .into_iter()
        .map(|sig| sig.into())
        .sum::<PartialSignature<C>>()
        + elem;

    // let effective_nonce = if final_nonce.has_even_y() {
    //     final_nonce
    // } else {
    //     -final_nonce
    // };

    // NOTE: TAKEN OUT FOR ACTUAL SECURITY IMPLEMENTATION
    // Ensure the signature will verify as valid.
    // if aggregated_signature * G != effective_nonce + e * aggregated_pubkey.to_even_y() {
    //     return Err(VerifyError::BadSignature);
    // }

    let agg_sig = Signature {
        prover_response: aggregated_signature,        // s - scalar representing signature proof
        verifier_challenge: array,      // bytes of finalnonce
    };

    Ok(agg_sig)
}

/// Aggregate a collection of partial signatures together into a final
/// signature on a given `message`, valid under the aggregated public
/// key in `key_agg_ctx`.
///
/// Returns an error if the resulting signature would not be valid.
pub fn aggregate_partial_signatures<S, C: ProjectiveCurve>(
    key_agg_ctx: &KeyAggContext<C>,
    aggregated_nonce: &AggNonce<C>,
    partial_signatures: impl IntoIterator<Item = S>,
    message: impl AsRef<[u8]>,
    poseidon_params: &Poseidon<ConstraintF<C>, MyPoseidonParams>,
) -> Result<Signature<C>, VerifyError>
where
    S: Into<PartialSignature<C>>,
//     T: From<LiftedSignature>,
{
    let sig = aggregate_partial_adaptor_signatures(
        key_agg_ctx,
        aggregated_nonce,
        // MaybePoint::<C>::Infinity,
        partial_signatures,
        message,
        poseidon_params,
    )?;
    // .adapt(MaybeScalar::Zero)
    // .map(T::from)
    // .expect("aggregating with empty adaptor should never result in an adaptor failure");

    Ok(sig)
}