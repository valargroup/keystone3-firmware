//! Timing of hash-based signature schemes on the device.
//!
//! Each run derives a key from fixed seeds, signs a fixed message and verifies the
//! signature, timing each of the three steps. Inputs are fixed so runs repeat exactly
//! and match the laptop benchmark in zakura-core/common (`pq_schemes`). Every
//! signature is verified, so a broken build fails instead of reporting fast numbers.
//!
//! The caller supplies the clock, so the same code times the device and the simulator.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::ffi::CStr;
use core::marker::PhantomData;

use pq_crypto::{fors, wots, MessageDigest, PublicSeed, SecretSeed};

/// The schemes in the order the C side lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Wots,
    Fors,
    SlhDsa128s,
    SlhDsa128f,
    SlhDsa256s,
}

impl Scheme {
    pub const ALL: [Scheme; 5] = [
        Scheme::Wots,
        Scheme::Fors,
        Scheme::SlhDsa128s,
        Scheme::SlhDsa128f,
        Scheme::SlhDsa256s,
    ];

    /// A short name that fits a table row on the device screen, NUL-terminated for C.
    pub fn name(self) -> &'static CStr {
        match self {
            Scheme::Wots => c"WOTS+",
            Scheme::Fors => c"FORS-256f",
            Scheme::SlhDsa128s => c"SLH-128s",
            Scheme::SlhDsa128f => c"SLH-128f",
            Scheme::SlhDsa256s => c"SLH-256s",
        }
    }

    /// Iterations for a default run: one for the SLH-DSA "s" sets, whose signing takes
    /// tens of seconds on the device, so a full pass stays within a few minutes.
    pub fn default_iterations(self) -> u32 {
        match self {
            Scheme::SlhDsa128s | Scheme::SlhDsa256s => 1,
            Scheme::Wots | Scheme::Fors | Scheme::SlhDsa128f => 5,
        }
    }

    /// Runs `iterations` key generations, signatures and verifications.
    pub fn run(self, iterations: u32, now_ns: &mut dyn FnMut() -> u64) -> Result<Report, Error> {
        match self {
            Scheme::Wots => measure::<Wots>(iterations, now_ns),
            Scheme::Fors => measure::<Fors>(iterations, now_ns),
            Scheme::SlhDsa128s => measure::<SlhDsa<slh_dsa::Sha2_128s>>(iterations, now_ns),
            Scheme::SlhDsa128f => measure::<SlhDsa<slh_dsa::Sha2_128f>>(iterations, now_ns),
            Scheme::SlhDsa256s => measure::<SlhDsa<slh_dsa::Sha2_256s>>(iterations, now_ns),
        }
    }
}

/// Times for one operation across the iterations, in nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub median_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub iterations: u32,
    pub keygen: Stats,
    pub sign: Stats,
    pub verify: Stats,
    pub signature_bytes: usize,
    pub public_key_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NoIterations,
    /// A signature the scheme just produced did not verify.
    VerifyFailed,
}

/// Fixed message the signatures cover; FORS signs a 40-byte digest, the others 32 bytes.
const MESSAGE: [u8; 40] = *b"keystone pq signature benchmark message.";
/// SLH-DSA context string, as in zakura-core/common.
const SLH_DSA_CONTEXT: &[u8] = b"Zcash/PQ/spend/v1";

trait Bench {
    type SigningKey;
    type VerifyingKey;
    type Signature;
    const SIGNATURE_BYTES: usize;
    const PUBLIC_KEY_BYTES: usize;

    /// Derives a signing key from fixed seeds and computes its public key.
    fn keygen(iteration: u32) -> (Self::SigningKey, Self::VerifyingKey);
    fn sign(key: Self::SigningKey) -> Self::Signature;
    fn verify(key: &Self::VerifyingKey, signature: &Self::Signature) -> bool;
}

/// 32 seed bytes that differ per iteration and per seed role.
fn seed(role: u8, iteration: u32) -> [u8; 32] {
    let counter = iteration.to_le_bytes();
    core::array::from_fn(|i| role ^ counter[i % 4] ^ (i as u8).wrapping_mul(29))
}

struct Wots;

impl Bench for Wots {
    type SigningKey = wots::SigningKey;
    type VerifyingKey = wots::VerifyingKey;
    type Signature = wots::Signature;
    const SIGNATURE_BYTES: usize = wots::SIGNATURE_BYTES;
    const PUBLIC_KEY_BYTES: usize = wots::VERIFYING_KEY_BYTES;

    fn keygen(iteration: u32) -> (Self::SigningKey, Self::VerifyingKey) {
        let key = wots::SigningKey::from_seeds(
            SecretSeed::from_bytes(seed(1, iteration)),
            PublicSeed::from_bytes(seed(2, iteration)),
        )
        .expect("the secret and public seeds differ");
        let public = key.verifying_key();
        (key, public)
    }

    fn sign(key: Self::SigningKey) -> Self::Signature {
        key.sign_digest(&wots_digest())
    }

    fn verify(key: &Self::VerifyingKey, signature: &Self::Signature) -> bool {
        key.verify_digest(&wots_digest(), signature).is_ok()
    }
}

fn wots_digest() -> MessageDigest {
    MessageDigest::from_bytes(core::array::from_fn(|i| MESSAGE[i]))
}

struct Fors;

impl Bench for Fors {
    type SigningKey = fors::SigningKey;
    type VerifyingKey = fors::VerifyingKey;
    type Signature = fors::Signature;
    const SIGNATURE_BYTES: usize = fors::SIGNATURE_BYTES;
    const PUBLIC_KEY_BYTES: usize = fors::VERIFYING_KEY_BYTES;

    fn keygen(iteration: u32) -> (Self::SigningKey, Self::VerifyingKey) {
        let key = fors::SigningKey::from_seeds(
            SecretSeed::from_bytes(seed(3, iteration)),
            PublicSeed::from_bytes(seed(4, iteration)),
        )
        .expect("the secret and public seeds differ");
        let public = key.verifying_key();
        (key, public)
    }

    fn sign(key: Self::SigningKey) -> Self::Signature {
        key.sign_digest(&fors::IndexDigest::from_bytes(MESSAGE))
    }

    fn verify(key: &Self::VerifyingKey, signature: &Self::Signature) -> bool {
        key.verify_digest(&fors::IndexDigest::from_bytes(MESSAGE), signature)
            .is_ok()
    }
}

/// Encoded sizes of the SLH-DSA parameter sets (FIPS 205, Table 2).
trait SlhDsaSizes: slh_dsa::ParameterSet {
    const N: usize;
    const SIGNATURE_BYTES: usize;
}

impl SlhDsaSizes for slh_dsa::Sha2_128s {
    const N: usize = 16;
    const SIGNATURE_BYTES: usize = 7_856;
}

impl SlhDsaSizes for slh_dsa::Sha2_128f {
    const N: usize = 16;
    const SIGNATURE_BYTES: usize = 17_088;
}

impl SlhDsaSizes for slh_dsa::Sha2_256s {
    const N: usize = 32;
    const SIGNATURE_BYTES: usize = 29_792;
}

struct SlhDsa<P>(PhantomData<P>);

impl<P: SlhDsaSizes> Bench for SlhDsa<P> {
    type SigningKey = slh_dsa::SigningKey<P>;
    type VerifyingKey = slh_dsa::VerifyingKey<P>;
    type Signature = slh_dsa::Signature<P>;
    const SIGNATURE_BYTES: usize = P::SIGNATURE_BYTES;
    const PUBLIC_KEY_BYTES: usize = 2 * P::N;

    fn keygen(iteration: u32) -> (Self::SigningKey, Self::VerifyingKey) {
        let key = slh_dsa::SigningKey::<P>::slh_keygen_internal(
            &seed(5, iteration)[..P::N],
            &seed(6, iteration)[..P::N],
            &seed(7, iteration)[..P::N],
        );
        let public = key.as_ref().clone();
        (key, public)
    }

    fn sign(key: Self::SigningKey) -> Self::Signature {
        key.try_sign_with_context(&MESSAGE[..32], SLH_DSA_CONTEXT, None)
            .expect("the context is shorter than 256 bytes")
    }

    fn verify(key: &Self::VerifyingKey, signature: &Self::Signature) -> bool {
        key.try_verify_with_context(&MESSAGE[..32], SLH_DSA_CONTEXT, signature)
            .is_ok()
    }
}

fn measure<B: Bench>(iterations: u32, now_ns: &mut dyn FnMut() -> u64) -> Result<Report, Error> {
    if iterations == 0 {
        return Err(Error::NoIterations);
    }
    let count = iterations as usize;
    let (mut keygen, mut sign, mut verify) = (
        Vec::with_capacity(count),
        Vec::with_capacity(count),
        Vec::with_capacity(count),
    );
    for iteration in 0..iterations {
        let start = now_ns();
        let (key, public) = B::keygen(iteration);
        let generated = now_ns();
        let signature = B::sign(key);
        let signed = now_ns();
        let valid = B::verify(&public, &signature);
        let verified = now_ns();
        if !valid {
            return Err(Error::VerifyFailed);
        }
        keygen.push(generated - start);
        sign.push(signed - generated);
        verify.push(verified - signed);
    }
    Ok(Report {
        iterations,
        keygen: stats(&mut keygen),
        sign: stats(&mut sign),
        verify: stats(&mut verify),
        signature_bytes: B::SIGNATURE_BYTES,
        public_key_bytes: B::PUBLIC_KEY_BYTES,
    })
}

fn stats(samples: &mut [u64]) -> Stats {
    samples.sort_unstable();
    let middle = samples.len() / 2;
    let median_ns = if samples.len() % 2 == 0 {
        (samples[middle - 1] + samples[middle]) / 2
    } else {
        samples[middle]
    };
    Stats {
        median_ns,
        min_ns: samples[0],
        max_ns: samples[samples.len() - 1],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock that advances 1 µs per reading, so every step takes 1 µs.
    fn fake_clock() -> impl FnMut() -> u64 {
        let mut ticks = 0;
        move || {
            ticks += 1_000;
            ticks
        }
    }

    #[test]
    fn every_scheme_signs_and_verifies() {
        for scheme in Scheme::ALL {
            let report = scheme.run(2, &mut fake_clock()).unwrap();
            assert_eq!(report.iterations, 2, "{:?}", scheme.name());
            assert_eq!(report.sign.median_ns, 1_000, "{:?}", scheme.name());
        }
    }

    #[test]
    fn sizes_match_the_encodings() {
        let (_, public) = SlhDsa::<slh_dsa::Sha2_128s>::keygen(0);
        let signature =
            SlhDsa::<slh_dsa::Sha2_128s>::sign(SlhDsa::<slh_dsa::Sha2_128s>::keygen(0).0);
        assert_eq!(public.to_bytes().len(), 32);
        assert_eq!(signature.to_bytes().len(), 7_856);

        let (_, public) = SlhDsa::<slh_dsa::Sha2_256s>::keygen(0);
        let signature =
            SlhDsa::<slh_dsa::Sha2_256s>::sign(SlhDsa::<slh_dsa::Sha2_256s>::keygen(0).0);
        assert_eq!(public.to_bytes().len(), 64);
        assert_eq!(signature.to_bytes().len(), 29_792);

        let signature =
            SlhDsa::<slh_dsa::Sha2_128f>::sign(SlhDsa::<slh_dsa::Sha2_128f>::keygen(0).0);
        assert_eq!(signature.to_bytes().len(), 17_088);
    }

    #[test]
    fn median_of_even_count_averages_the_middle_pair() {
        assert_eq!(stats(&mut [4, 1, 3, 2]).median_ns, 2);
        assert_eq!(stats(&mut [5, 1, 3]).median_ns, 3);
    }
}
