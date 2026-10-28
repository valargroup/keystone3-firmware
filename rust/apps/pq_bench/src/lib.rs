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

/// The schemes in the order the C side lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    SlhDsa192s,
    SlhDsa192f,
}

impl Scheme {
    pub const ALL: [Scheme; 2] = [Scheme::SlhDsa192s, Scheme::SlhDsa192f];

    /// A short name that fits a line on the device screen, NUL-terminated for C.
    pub fn name(self) -> &'static CStr {
        match self {
            Scheme::SlhDsa192s => c"SLH-192s",
            Scheme::SlhDsa192f => c"SLH-192f",
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
            Scheme::SlhDsa192s => {
                measure::<SlhDsa<slh_dsa::Sha2_192s>>(iterations, now_ns, progress)
            }
            Scheme::SlhDsa192f => {
                measure::<SlhDsa<slh_dsa::Sha2_192f>>(iterations, now_ns, progress)
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

/// Fixed message the signatures cover.
const MESSAGE: [u8; 32] = *b"keystone pq signature benchmark ";
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

/// Encoded sizes of the SLH-DSA parameter sets (FIPS 205, Table 2).
trait SlhDsaSizes: slh_dsa::ParameterSet {
    const N: usize;
    const SIGNATURE_BYTES: usize;
}

impl SlhDsaSizes for slh_dsa::Sha2_192s {
    const N: usize = 24;
    const SIGNATURE_BYTES: usize = 16_224;
}

impl SlhDsaSizes for slh_dsa::Sha2_192f {
    const N: usize = 24;
    const SIGNATURE_BYTES: usize = 35_664;
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
        key.try_sign_with_context(&MESSAGE, SLH_DSA_CONTEXT, None)
            .expect("the context is shorter than 256 bytes")
    }

    fn verify(key: &Self::VerifyingKey, signature: &Self::Signature) -> bool {
        key.try_verify_with_context(&MESSAGE, SLH_DSA_CONTEXT, signature)
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
        type S = SlhDsa<slh_dsa::Sha2_192s>;
        type F = SlhDsa<slh_dsa::Sha2_192f>;
        let (key, public) = S::keygen(0);
        assert_eq!(public.to_bytes().len(), 48);
        assert_eq!(S::sign(key).to_bytes().len(), 16_224);
        let (key, public) = F::keygen(0);
        assert_eq!(public.to_bytes().len(), 48);
        assert_eq!(F::sign(key).to_bytes().len(), 35_664);
    }

    #[test]
    fn median_of_even_count_averages_the_middle_pair() {
        assert_eq!(stats(&mut [4, 1, 3, 2]).median_ns, 2);
        assert_eq!(stats(&mut [5, 1, 3]).median_ns, 3);
    }
}
