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
    /// FORS shapes, named by the SLH-DSA parameter set that uses them.
    Fors256f,
    Fors256s,
    Fors192f,
    Fors192s,
    /// 16 trees of height 16 with 32-byte hashes; no SLH-DSA set uses it.
    Fors16x16,
    Fors128s,
    SlhDsa128s,
    SlhDsa128f,
    SlhDsa192s,
    SlhDsa192f,
    SlhDsa256s,
}

impl Scheme {
    pub const ALL: [Scheme; 12] = [
        Scheme::Wots,
        Scheme::Fors256f,
        Scheme::Fors256s,
        Scheme::Fors192f,
        Scheme::Fors192s,
        Scheme::Fors16x16,
        Scheme::Fors128s,
        Scheme::SlhDsa128s,
        Scheme::SlhDsa128f,
        Scheme::SlhDsa192s,
        Scheme::SlhDsa192f,
        Scheme::SlhDsa256s,
    ];

    /// A short name that fits a table row on the device screen, NUL-terminated for C.
    pub fn name(self) -> &'static CStr {
        match self {
            Scheme::Wots => c"WOTS+",
            Scheme::Fors256f => c"FORS-256f",
            Scheme::Fors256s => c"FORS-256s",
            Scheme::Fors192f => c"FORS-192f",
            Scheme::Fors192s => c"FORS-192s",
            Scheme::Fors16x16 => c"FORS-16x16",
            Scheme::Fors128s => c"FORS-128s",
            Scheme::SlhDsa128s => c"SLH-128s",
            Scheme::SlhDsa128f => c"SLH-128f",
            Scheme::SlhDsa192s => c"SLH-192s",
            Scheme::SlhDsa192f => c"SLH-192f",
            Scheme::SlhDsa256s => c"SLH-256s",
        }
    }

    /// Runs `iterations` key generations, signatures and verifications. `progress` is called
    /// before each step, outside the timed part.
    pub fn run(
        self,
        iterations: u32,
        now_ns: &mut dyn FnMut() -> u64,
        progress: &mut dyn FnMut(Step, u32),
    ) -> Result<Report, Error> {
        match self {
            Scheme::Wots => measure::<Wots>(iterations, now_ns, progress),
            Scheme::Fors256f => measure::<Fors<35, 9, 32, 40>>(iterations, now_ns, progress),
            Scheme::Fors256s => measure::<Fors<22, 14, 32, 39>>(iterations, now_ns, progress),
            Scheme::Fors192f => measure::<Fors<33, 8, 24, 33>>(iterations, now_ns, progress),
            Scheme::Fors192s => measure::<Fors<17, 14, 24, 30>>(iterations, now_ns, progress),
            Scheme::Fors16x16 => measure::<Fors<16, 16, 32, 32>>(iterations, now_ns, progress),
            Scheme::Fors128s => measure::<Fors<14, 12, 16, 21>>(iterations, now_ns, progress),
            Scheme::SlhDsa128s => {
                measure::<SlhDsa<slh_dsa::Sha2_128s>>(iterations, now_ns, progress)
            }
            Scheme::SlhDsa128f => {
                measure::<SlhDsa<slh_dsa::Sha2_128f>>(iterations, now_ns, progress)
            }
            Scheme::SlhDsa192s => {
                measure::<SlhDsa<slh_dsa::Sha2_192s>>(iterations, now_ns, progress)
            }
            Scheme::SlhDsa192f => {
                measure::<SlhDsa<slh_dsa::Sha2_192f>>(iterations, now_ns, progress)
            }
            Scheme::SlhDsa256s => {
                measure::<SlhDsa<slh_dsa::Sha2_256s>>(iterations, now_ns, progress)
            }
        }
    }
}

/// The step a run is about to start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Step {
    Keygen = 0,
    Sign = 1,
    Verify = 2,
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

/// Fixed message the signatures cover. FORS signs its first ceil(K * A / 8) bytes (at most
/// 40), the others the first 32.
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

/// FORS with `K` trees of height `A` and `N`-byte hashes, signing an `L`-byte digest
/// (`L` must be ceil(K * A / 8); another value fails to compile).
struct Fors<const K: usize, const A: usize, const N: usize, const L: usize>;

impl<const K: usize, const A: usize, const N: usize, const L: usize> Fors<K, A, N, L> {
    fn digest() -> fors::IndexDigest<K, A> {
        fors::IndexDigest::from_bytes::<L>(core::array::from_fn(|i| MESSAGE[i]))
    }
}

impl<const K: usize, const A: usize, const N: usize, const L: usize> Bench for Fors<K, A, N, L> {
    type SigningKey = fors::SigningKey<K, A, N>;
    type VerifyingKey = fors::VerifyingKey<K, A, N>;
    type Signature = fors::Signature<K, A, N>;
    const SIGNATURE_BYTES: usize = fors::Signature::<K, A, N>::BYTES;
    const PUBLIC_KEY_BYTES: usize = fors::VerifyingKey::<K, A, N>::BYTES;

    fn keygen(iteration: u32) -> (Self::SigningKey, Self::VerifyingKey) {
        let (secret, public) = (seed(3, iteration), seed(4, iteration));
        let key = fors::SigningKey::from_seeds(
            SecretSeed::from_bytes(core::array::from_fn(|i| secret[i])),
            PublicSeed::from_bytes(core::array::from_fn(|i| public[i])),
        )
        .expect("the secret and public seeds differ");
        let public = key.verifying_key();
        (key, public)
    }

    fn sign(key: Self::SigningKey) -> Self::Signature {
        key.sign_digest(&Self::digest())
    }

    fn verify(key: &Self::VerifyingKey, signature: &Self::Signature) -> bool {
        key.verify_digest(&Self::digest(), signature).is_ok()
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

impl SlhDsaSizes for slh_dsa::Sha2_192s {
    const N: usize = 24;
    const SIGNATURE_BYTES: usize = 16_224;
}

impl SlhDsaSizes for slh_dsa::Sha2_192f {
    const N: usize = 24;
    const SIGNATURE_BYTES: usize = 35_664;
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

fn measure<B: Bench>(
    iterations: u32,
    now_ns: &mut dyn FnMut() -> u64,
    progress: &mut dyn FnMut(Step, u32),
) -> Result<Report, Error> {
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
        progress(Step::Keygen, iteration);
        let start = now_ns();
        let (key, public) = B::keygen(iteration);
        keygen.push(now_ns() - start);

        progress(Step::Sign, iteration);
        let start = now_ns();
        let signature = B::sign(key);
        sign.push(now_ns() - start);

        progress(Step::Verify, iteration);
        let start = now_ns();
        let valid = B::verify(&public, &signature);
        verify.push(now_ns() - start);
        if !valid {
            return Err(Error::VerifyFailed);
        }
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
            let mut steps = Vec::new();
            let report = scheme
                .run(2, &mut fake_clock(), &mut |step, iteration| {
                    steps.push((step, iteration))
                })
                .unwrap();
            assert_eq!(report.iterations, 2, "{:?}", scheme.name());
            assert_eq!(report.sign.median_ns, 1_000, "{:?}", scheme.name());
            assert_eq!(steps.len(), 6, "{:?}", scheme.name());
            assert_eq!(steps[4], (Step::Sign, 1), "{:?}", scheme.name());
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

        let (key, public) = SlhDsa::<slh_dsa::Sha2_192s>::keygen(0);
        assert_eq!(public.to_bytes().len(), 48);
        assert_eq!(
            SlhDsa::<slh_dsa::Sha2_192s>::sign(key).to_bytes().len(),
            16_224
        );
        let (key, public) = SlhDsa::<slh_dsa::Sha2_192f>::keygen(0);
        assert_eq!(public.to_bytes().len(), 48);
        assert_eq!(
            SlhDsa::<slh_dsa::Sha2_192f>::sign(key).to_bytes().len(),
            35_664
        );
    }

    #[test]
    fn fors_shapes_have_the_expected_sizes() {
        assert_eq!(<Fors<35, 9, 32, 40> as Bench>::SIGNATURE_BYTES, 11_200);
        assert_eq!(<Fors<22, 14, 32, 39> as Bench>::SIGNATURE_BYTES, 10_560);
        assert_eq!(<Fors<33, 8, 24, 33> as Bench>::SIGNATURE_BYTES, 7_128);
        assert_eq!(<Fors<17, 14, 24, 30> as Bench>::SIGNATURE_BYTES, 6_120);
        assert_eq!(<Fors<16, 16, 32, 32> as Bench>::SIGNATURE_BYTES, 8_704);
        assert_eq!(<Fors<14, 12, 16, 21> as Bench>::SIGNATURE_BYTES, 2_912);
        assert_eq!(<Fors<35, 9, 32, 40> as Bench>::PUBLIC_KEY_BYTES, 64);
        assert_eq!(<Fors<33, 8, 24, 33> as Bench>::PUBLIC_KEY_BYTES, 48);
        assert_eq!(<Fors<14, 12, 16, 21> as Bench>::PUBLIC_KEY_BYTES, 32);
    }

    #[test]
    fn median_of_even_count_averages_the_middle_pair() {
        assert_eq!(stats(&mut [4, 1, 3, 2]).median_ns, 2);
        assert_eq!(stats(&mut [5, 1, 3]).median_ns, 3);
    }
}
