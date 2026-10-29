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

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ffi::CStr;
use core::marker::PhantomData;

/// The schemes in the order the C side lists them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// Not a signature: [`HASH_BLOCKS`] SHA-256 compressions, the operation that dominates every
    /// scheme here, so the time per block shows how fast the device hashes on its own.
    Sha256,
    SlhDsa128s,
    SlhDsa128f,
    SlhDsa192s,
    SlhDsa192f,
    SlhDsa256s,
    /// leanSphincs over SHA-256 with one tree of height `h`, pruned to a kept subtree of height
    /// `kept`, or with `kept == 0` a three-layer hypertree. The configurations are those
    /// sphincs.art shows for a hardware wallet at its lowest and highest lifetime, 2^26 (`h = 22`)
    /// and 2^32 (`h = 28`): "Uniform" (layered) and "Pruning" with the Ledger's subtree of 2^12.
    LeanSphincs {
        h: u8,
        kept: u8,
    },
}

impl Scheme {
    pub const ALL: [Scheme; 10] = [
        Scheme::Sha256,
        Scheme::SlhDsa128s,
        Scheme::SlhDsa128f,
        Scheme::SlhDsa192s,
        Scheme::SlhDsa192f,
        Scheme::SlhDsa256s,
        Scheme::LeanSphincs { h: 22, kept: 12 },
        Scheme::LeanSphincs { h: 22, kept: 0 },
        Scheme::LeanSphincs { h: 28, kept: 12 },
        Scheme::LeanSphincs { h: 28, kept: 0 },
    ];

    /// A short name that fits a table row on the device screen, NUL-terminated for C.
    pub fn name(self) -> &'static CStr {
        match self {
            Scheme::Sha256 => c"SHA-256 block",
            Scheme::SlhDsa128s => c"SLH-128s",
            Scheme::SlhDsa128f => c"SLH-128f",
            Scheme::SlhDsa192s => c"SLH-192s",
            Scheme::SlhDsa192f => c"SLH-192f",
            Scheme::SlhDsa256s => c"SLH-256s",
            Scheme::LeanSphincs { h: 22, kept: 12 } => c"lean h22 b12",
            Scheme::LeanSphincs { h: 22, kept: 0 } => c"lean h22 layer",
            Scheme::LeanSphincs { h: 28, kept: 12 } => c"lean h28 b12",
            Scheme::LeanSphincs { h: 28, kept: 0 } => c"lean h28 layer",
            Scheme::LeanSphincs { .. } => c"lean (unlisted)",
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
            Scheme::Sha256 => measure(&Sha256Blocks, iterations, now_ns, progress),
            Scheme::SlhDsa128s => measure(
                &SlhDsa::<slh_dsa::Sha2_128s>::new(),
                iterations,
                now_ns,
                progress,
            ),
            Scheme::SlhDsa128f => measure(
                &SlhDsa::<slh_dsa::Sha2_128f>::new(),
                iterations,
                now_ns,
                progress,
            ),
            Scheme::SlhDsa192s => measure(
                &SlhDsa::<slh_dsa::Sha2_192s>::new(),
                iterations,
                now_ns,
                progress,
            ),
            Scheme::SlhDsa192f => measure(
                &SlhDsa::<slh_dsa::Sha2_192f>::new(),
                iterations,
                now_ns,
                progress,
            ),
            Scheme::SlhDsa256s => measure(
                &SlhDsa::<slh_dsa::Sha2_256s>::new(),
                iterations,
                now_ns,
                progress,
            ),
            Scheme::LeanSphincs { h, kept } => {
                measure(&LeanSphincs::new(h, kept), iterations, now_ns, progress)
            }
        }
    }
}

/// SHA-256 compressions the [`Scheme::Sha256`] row times in its sign step.
pub const HASH_BLOCKS: u32 = 10_000;

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

    fn signature_bytes(&self) -> usize;
    fn public_key_bytes(&self) -> usize;
    /// Derives a signing key from fixed seeds and computes its public key.
    fn keygen(&self, iteration: u32) -> (Self::SigningKey, Self::VerifyingKey);
    fn sign(&self, key: Self::SigningKey) -> Self::Signature;
    fn verify(&self, key: &Self::VerifyingKey, signature: &Self::Signature) -> bool;
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

impl<P> SlhDsa<P> {
    fn new() -> Self {
        Self(PhantomData)
    }
}

impl<P: SlhDsaSizes> Bench for SlhDsa<P> {
    type SigningKey = slh_dsa::SigningKey<P>;
    type VerifyingKey = slh_dsa::VerifyingKey<P>;
    /// On the heap: the signature is up to 35 KB, and slh-dsa signs into it in place, so the
    /// stack only needs room for one hypertree layer at a time.
    type Signature = Box<slh_dsa::Signature<P>>;

    fn signature_bytes(&self) -> usize {
        P::SIGNATURE_BYTES
    }

    fn public_key_bytes(&self) -> usize {
        2 * P::N
    }

    fn keygen(&self, iteration: u32) -> (Self::SigningKey, Self::VerifyingKey) {
        let key = slh_dsa::SigningKey::<P>::slh_keygen_internal(
            &seed(5, iteration)[..P::N],
            &seed(6, iteration)[..P::N],
            &seed(7, iteration)[..P::N],
        );
        let public = key.as_ref().clone();
        (key, public)
    }

    fn sign(&self, key: Self::SigningKey) -> Self::Signature {
        let mut signature = zeroed_signature::<P>();
        key.try_sign_with_context_into(&MESSAGE, SLH_DSA_CONTEXT, None, &mut signature)
            .expect("the context is shorter than 256 bytes");
        signature
    }

    fn verify(&self, key: &Self::VerifyingKey, signature: &Self::Signature) -> bool {
        key.try_verify_with_context(&MESSAGE, SLH_DSA_CONTEXT, signature)
            .is_ok()
    }
}

/// A signature of all zero bytes, allocated straight on the heap. `Box::new` could build it on
/// the stack first, which is what this avoids.
fn zeroed_signature<P: slh_dsa::ParameterSet>() -> Box<slh_dsa::Signature<P>> {
    let layout = Layout::new::<slh_dsa::Signature<P>>();
    // SAFETY: a signature is nested arrays of bytes with no other fields, so all zero bytes is a
    // valid value; a null pointer is handled before `from_raw`.
    unsafe {
        let pointer = alloc::alloc::alloc_zeroed(layout) as *mut slh_dsa::Signature<P>;
        if pointer.is_null() {
            alloc::alloc::handle_alloc_error(layout);
        }
        Box::from_raw(pointer)
    }
}

/// [`HASH_BLOCKS`] SHA-256 compressions, with the same implementation slh-dsa uses.
struct Sha256Blocks;

impl Bench for Sha256Blocks {
    type SigningKey = [u32; 8];
    type VerifyingKey = [u32; 8];
    type Signature = [u32; 8];

    fn signature_bytes(&self) -> usize {
        0
    }

    fn public_key_bytes(&self) -> usize {
        0
    }

    fn keygen(&self, _iteration: u32) -> (Self::SigningKey, Self::VerifyingKey) {
        (SHA256_IV, SHA256_IV)
    }

    fn sign(&self, mut state: Self::SigningKey) -> Self::Signature {
        let block = sha2::digest::generic_array::GenericArray::from([0x5a; 64]);
        for _ in 0..HASH_BLOCKS {
            sha2::compress256(&mut state, core::slice::from_ref(&block));
        }
        state
    }

    /// Checks the hashing actually ran, so a compiler that skipped it could not report 0.
    fn verify(&self, initial: &Self::VerifyingKey, state: &Self::Signature) -> bool {
        state != initial
    }
}

const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

struct LeanSphincs {
    config: sphincs::Config,
    /// 4,212 bytes at `h = 22` for a pruned key, 6,268 for a layered one, 16 more per unit of `h`.
    signature_bytes: usize,
}

impl LeanSphincs {
    /// `kept == 0` is the layered (hypertree) shape.
    fn new(h: u8, kept: u8) -> Self {
        let (h, kept) = (h as usize, kept as usize);
        let (shape, base) = match kept {
            0 => (sphincs::Shape::Layered, 6_268),
            b => (sphincs::Shape::Pruned { b }, 4_212),
        };
        Self {
            config: sphincs::Config::new(sphincs::HashFn::Sha256, h, shape),
            signature_bytes: base + 16 * (h - 22),
        }
    }
}

impl Bench for LeanSphincs {
    type SigningKey = sphincs::SecretKey;
    type VerifyingKey = sphincs::PublicKey;
    type Signature = sphincs::Signature;

    fn signature_bytes(&self) -> usize {
        self.signature_bytes
    }

    fn public_key_bytes(&self) -> usize {
        sphincs::PUB_KEY_SIZE
    }

    fn keygen(&self, iteration: u32) -> (Self::SigningKey, Self::VerifyingKey) {
        sphincs::key_gen(&self.config, &seed(8, iteration))
    }

    fn sign(&self, key: Self::SigningKey) -> Self::Signature {
        sphincs::sign(&key, &MESSAGE)
    }

    fn verify(&self, key: &Self::VerifyingKey, signature: &Self::Signature) -> bool {
        sphincs::verify(&self.config, key, &MESSAGE, signature).is_ok()
    }
}

fn measure<B: Bench>(
    bench: &B,
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
        let (key, public) = bench.keygen(iteration);
        keygen.push(now_ns() - start);

        progress(Step::Sign, iteration);
        let start = now_ns();
        let signature = bench.sign(key);
        sign.push(now_ns() - start);

        progress(Step::Verify, iteration);
        let start = now_ns();
        let valid = bench.verify(&public, &signature);
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
        signature_bytes: bench.signature_bytes(),
        public_key_bytes: bench.public_key_bytes(),
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
        let (_, public) = SlhDsa::<slh_dsa::Sha2_128s>::new().keygen(0);
        let signature = SlhDsa::<slh_dsa::Sha2_128s>::new()
            .sign(SlhDsa::<slh_dsa::Sha2_128s>::new().keygen(0).0);
        assert_eq!(public.to_bytes().len(), 32);
        assert_eq!(signature.to_bytes().len(), 7_856);

        let (_, public) = SlhDsa::<slh_dsa::Sha2_256s>::new().keygen(0);
        let signature = SlhDsa::<slh_dsa::Sha2_256s>::new()
            .sign(SlhDsa::<slh_dsa::Sha2_256s>::new().keygen(0).0);
        assert_eq!(public.to_bytes().len(), 64);
        assert_eq!(signature.to_bytes().len(), 29_792);

        let signature = SlhDsa::<slh_dsa::Sha2_128f>::new()
            .sign(SlhDsa::<slh_dsa::Sha2_128f>::new().keygen(0).0);
        assert_eq!(signature.to_bytes().len(), 17_088);

        let (key, public) = SlhDsa::<slh_dsa::Sha2_192s>::new().keygen(0);
        assert_eq!(public.to_bytes().len(), 48);
        assert_eq!(
            SlhDsa::<slh_dsa::Sha2_192s>::new()
                .sign(key)
                .to_bytes()
                .len(),
            16_224
        );
        let (key, public) = SlhDsa::<slh_dsa::Sha2_192f>::new().keygen(0);
        assert_eq!(public.to_bytes().len(), 48);
        assert_eq!(
            SlhDsa::<slh_dsa::Sha2_192f>::new()
                .sign(key)
                .to_bytes()
                .len(),
            35_664
        );
    }

    #[test]
    fn lean_sphincs_sizes_match_the_encodings() {
        for scheme in Scheme::ALL {
            let Scheme::LeanSphincs { h, kept } = scheme else {
                continue;
            };
            let bench = LeanSphincs::new(h, kept);
            let (key, public) = bench.keygen(0);
            assert_eq!(public.to_bytes().len(), 32, "{:?}", scheme.name());
            let signature = bench.sign(key).to_bytes();
            assert_eq!(
                signature.len(),
                bench.signature_bytes(),
                "{:?}",
                scheme.name()
            );
        }
        assert_eq!(LeanSphincs::new(22, 10).signature_bytes(), 4_212);
    }

    #[test]
    fn every_scheme_has_its_own_name() {
        for (i, a) in Scheme::ALL.iter().enumerate() {
            assert_ne!(a.name(), c"lean (unlisted)");
            for b in &Scheme::ALL[i + 1..] {
                assert_ne!(a.name(), b.name());
            }
        }
    }

    #[test]
    fn median_of_even_count_averages_the_middle_pair() {
        assert_eq!(stats(&mut [4, 1, 3, 2]).median_ns, 2);
        assert_eq!(stats(&mut [5, 1, 3]).median_ns, 3);
    }
}
