use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use bitcoin::secp256k1;
use keystore::algorithms::{
    secp256k1::{get_private_key_by_seed, get_public_key_by_seed},
    zcash::calculate_seed_fingerprint,
};
use zcash_vendor::{
    pczt::{
        orchard::MemoKind,
        roles::{
            low_level_signer,
            redactor::{orchard::OrchardRedactor, Redactor},
            updater::Updater,
        },
        Pczt,
    },
    transparent,
};

#[cfg(feature = "cypherpunk")]
use zcash_vendor::orchard;

#[cfg(any(feature = "cypherpunk", feature = "multi_coins"))]
use zcash_vendor::{
    pczt_ext::{self, PcztSigner},
    transparent::sighash::SignableInput,
};

#[cfg(feature = "cypherpunk")]
use {blake2b_simd::Hash, core::cell::Cell, core::cell::RefCell, rand_core::OsRng};

use crate::{errors::ZcashError, version::KEYSTONE_FW_VERSION};

/// `global.proprietary` key stamped into every signed PCZT response.
/// Value is 3 bytes `[major, minor, build]`. Wallets read this to check
/// whether the device meets their minimum version requirements.
const PROP_KEY_FW_VERSION: &str = "keystone:fw_version";

#[cfg(all(feature = "multi_coins", not(feature = "cypherpunk")))]
struct SeedSigner<'a> {
    seed: &'a [u8],
}

#[cfg(all(feature = "multi_coins", not(feature = "cypherpunk")))]
impl PcztSigner for SeedSigner<'_> {
    type Error = ZcashError;

    fn sign_transparent<F>(
        &self,
        index: usize,
        input: &mut transparent::pczt::Input,
        hash: F,
    ) -> Result<(), Self::Error>
    where
        F: FnOnce(SignableInput) -> [u8; 32],
    {
        if let Some(path) = transparent_key_path_for_input(self.seed, input)? {
            let sk = get_private_key_by_seed(self.seed, &path).map_err(|e| {
                ZcashError::SigningError(format!("failed to get private key: {e:?}"))
            })?;
            let secp = secp256k1::Secp256k1::new();
            input
                .sign(index, hash, &sk, &secp)
                .map_err(|e| ZcashError::SigningError(format!("failed to sign input: {e:?}")))?;
        }

        Ok(())
    }
}

#[cfg(not(feature = "cypherpunk"))]
pub fn sign_pczt(pczt: Pczt, seed: &[u8]) -> crate::Result<Vec<u8>> {
    super::validate_supported_pczt(&pczt)?;
    reject_legacy_unsupported_pczt(&pczt)?;

    let request_memo_kinds = RequestMemoKinds::capture(&pczt);
    let signer = low_level_signer::Signer::new(pczt);

    #[cfg(feature = "multi_coins")]
    let signer = pczt_ext::sign_transparent(signer, &SeedSigner { seed })
        .map_err(|e| ZcashError::SigningError(e.to_string()))?;

    stamp_and_redact(signer.finish(), &request_memo_kinds)
        .serialize()
        .map_err(|e| ZcashError::InvalidPczt(alloc::format!("pczt serialize: {e:?}")))
}

#[cfg(not(feature = "cypherpunk"))]
fn reject_legacy_unsupported_pczt(pczt: &Pczt) -> Result<(), ZcashError> {
    #[cfg(zcash_unstable = "nu6.3")]
    {
        // The legacy helper below carries the pre-NU6.3 transparent sighash implementation.
        // It must not be used for shielded (Sapling/Orchard/Ironwood) or V6 PCZTs.
        if super::pczt_requires_cypherpunk_support(pczt) {
            return Err(ZcashError::SigningError(
                "Shielded or V6 PCZTs require cypherpunk signing support".to_string(),
            ));
        }
    }
    Ok(())
}

/// Lean signer for the cypherpunk path. Drives the shallow `low_level_signer` and
/// derives keys / signs each action in place, instead of materializing a full
/// `RoleSigner` (which reconstructs the whole transaction to compute the sighash and
/// blows the task stack). The sighash itself is the byte-level
/// `pczt_ext::shielded_sig_commitment`, proven bit-exact against `RoleSigner` by the
/// `test_lean_sighash_*` oracle tests.
#[cfg(feature = "cypherpunk")]
struct SeedSigner<'a> {
    seed: &'a [u8],
    seed_fingerprint: [u8; 32],
    pool: ShieldedPool,
    /// Batch mode restricts signing to a single account. `Some(account)`
    /// (`for_batch_account`): only spends tagged for that account are signed;
    /// spends tagged for a different account of the same seed are refused. `None`
    /// (`new`): ordinary signing — any account derivable from the seed.
    selected_account: Option<zcash_vendor::zip32::AccountId>,
    /// Per-account spend authorizing key cache. The seed fingerprint and the account
    /// key depend only on (seed, account), not on the action, so a bundle with many
    /// actions for one account derives once. Interior mutability because the
    /// `PcztSigner` trait signs through `&self`.
    ask_cache: RefCell<
        Vec<(
            zcash_vendor::zip32::AccountId,
            orchard::keys::SpendAuthorizingKey,
        )>,
    >,
    /// Number of authorizations produced, so `sign_pczt` can distinguish "nothing of
    /// ours to sign" (`PcztNoMyInputs`) from a successful signing.
    signed: Cell<usize>,
}

#[cfg(feature = "cypherpunk")]
impl<'a> SeedSigner<'a> {
    fn new(seed: &'a [u8], seed_fingerprint: [u8; 32], pool: ShieldedPool) -> Self {
        Self {
            seed,
            seed_fingerprint,
            pool,
            selected_account: None,
            ask_cache: RefCell::new(Vec::new()),
            signed: Cell::new(0),
        }
    }

    fn for_batch_account(
        seed: &'a [u8],
        seed_fingerprint: [u8; 32],
        pool: ShieldedPool,
        selected_account: zcash_vendor::zip32::AccountId,
    ) -> Self {
        Self {
            seed,
            seed_fingerprint,
            pool,
            selected_account: Some(selected_account),
            ask_cache: RefCell::new(Vec::new()),
            signed: Cell::new(0),
        }
    }

    fn spend_authorizing_key(
        &self,
        account_index: zcash_vendor::zip32::AccountId,
    ) -> Result<orchard::keys::SpendAuthorizingKey, ZcashError> {
        if let Some((_, ask)) = self
            .ask_cache
            .borrow()
            .iter()
            .find(|(cached, _)| *cached == account_index)
        {
            return Ok(ask.clone());
        }
        let osk = orchard::keys::SpendingKey::from_zip32_seed(self.seed, 133, account_index)
            .map_err(|e| {
                ZcashError::SigningError(format!(
                    "failed to derive {} spending key: {e:?}",
                    self.pool.label()
                ))
            })?;
        let ask = orchard::keys::SpendAuthorizingKey::from(&osk);
        self.ask_cache
            .borrow_mut()
            .push((account_index, ask.clone()));
        Ok(ask)
    }
}

#[cfg(feature = "cypherpunk")]
impl PcztSigner for SeedSigner<'_> {
    type Error = ZcashError;

    fn sign_transparent<F>(
        &self,
        index: usize,
        input: &mut transparent::pczt::Input,
        hash: F,
    ) -> Result<(), Self::Error>
    where
        F: FnOnce(SignableInput) -> [u8; 32],
    {
        if let Some(path) = transparent_key_path_for_input(self.seed, input)? {
            let sk = get_private_key_by_seed(self.seed, &path).map_err(|e| {
                ZcashError::SigningError(format!("failed to get private key: {e:?}"))
            })?;
            let secp = secp256k1::Secp256k1::new();
            input
                .sign(index, hash, &sk, &secp)
                .map_err(|e| ZcashError::SigningError(format!("failed to sign input: {e:?}")))?;
            self.signed.set(self.signed.get() + 1);
        }
        Ok(())
    }

    fn sign_orchard(
        &self,
        action: &mut orchard::pczt::Action,
        hash: Hash,
    ) -> Result<(), Self::Error> {
        // Strict per-action validation, ported verbatim from the previous
        // collect_orchard_bundle_signing_keys so the lean signer keeps identical
        // skip/reject semantics to the RoleSigner path.
        let pool_label = self.pool.label();
        if action.spend().spend_auth_sig().is_some() {
            return Ok(());
        }
        if action.spend().dummy_sk().is_some() {
            match action.spend().value().map(|value| value.inner()) {
                Some(0) | None => return Ok(()),
                Some(_) => {
                    return Err(ZcashError::InvalidPczt(format!(
                        "{pool_label} spend dummy_sk is only valid for dummy spends"
                    )));
                }
            }
        }
        let Some(value) = action.spend().value() else {
            return if self.selected_account.is_some() {
                Err(ZcashError::InvalidPczt(format!(
                    "missing {pool_label} spend value"
                )))
            } else {
                Ok(())
            };
        };
        // Ownership decides signing, never the value: post-NU6.3 restricted bundles
        // pair each change output with a fabricated wallet-controlled zero-value spend
        // that must be signed by the account spend authorizing key (see
        // pczt_ext::sign_orchard_action: we "must NOT pre-filter by value").
        let Some(account_index) = super::matching_seed_supported_orchard_account(
            &self.seed_fingerprint,
            action.spend().zip32_derivation().as_ref(),
            133,
            self.pool,
        )?
        else {
            // Not derivable from this seed. Ordinary PCZT signing ignores it. A
            // reviewed batch tolerates untagged zero-value spends (IO Finalizer-signed
            // dummies whose signatures the wallet strips for the QR round trip) but
            // must otherwise contain only selected-account spends.
            return if self.selected_account.is_some() && value.inner() != 0 {
                Err(ZcashError::PcztNoMyInputs)
            } else {
                Ok(())
            };
        };
        if let Some(selected_account) = self.selected_account {
            if account_index != selected_account {
                return Err(ZcashError::PcztNoMyInputs);
            }
        }

        let ask = self.spend_authorizing_key(account_index)?;
        action
            .sign(
                hash.as_bytes().try_into().expect("sighash is 32 bytes"),
                &ask,
                OsRng,
            )
            .map_err(|e| {
                ZcashError::SigningError(format!("failed to sign {pool_label} action: {e:?}"))
            })?;
        self.signed.set(self.signed.get() + 1);
        Ok(())
    }
}

// Ordinary and batch signing share one core, `sign_pczt_with_seed_fingerprint_inner`,
// which threads an optional selected account (None = ordinary, Some = batch/restricted).
// The three wrappers exist so callers can enter at the right level:
//   sign_pczt                          -> public ordinary entry; computes the seed fingerprint
//   sign_pczt_with_seed_fingerprint    -> ordinary, fingerprint already known (avoids recomputing)
//   sign_batch_pczt_with_seed_fingerprint -> batch; restricts signing to `account_index`
// The batch path already holds the fingerprint (validated during review), so it skips recomputing it.

/// Public ordinary (non-batch) signing entry: signs every action derivable from
/// the seed. Computes the seed fingerprint, then delegates to the shared core.
#[cfg(feature = "cypherpunk")]
pub fn sign_pczt(pczt: Pczt, seed: &[u8]) -> crate::Result<Vec<u8>> {
    let seed_fingerprint =
        calculate_seed_fingerprint(seed).map_err(|e| ZcashError::SigningError(e.to_string()))?;

    sign_pczt_with_seed_fingerprint(pczt, seed, seed_fingerprint)
}

/// Ordinary signing with a precomputed seed fingerprint (no account restriction).
#[cfg(feature = "cypherpunk")]
pub(crate) fn sign_pczt_with_seed_fingerprint(
    pczt: Pczt,
    seed: &[u8],
    seed_fingerprint: [u8; 32],
) -> crate::Result<Vec<u8>> {
    sign_pczt_with_seed_fingerprint_inner(pczt, seed, seed_fingerprint, None)
}

/// Batch signing: restricts signing to `account_index` (the device-selected
/// account); spends tagged for another account of the same seed are refused.
#[cfg(feature = "cypherpunk")]
pub(crate) fn sign_batch_pczt_with_seed_fingerprint(
    pczt: Pczt,
    seed: &[u8],
    seed_fingerprint: [u8; 32],
    account_index: zcash_vendor::zip32::AccountId,
) -> crate::Result<Vec<u8>> {
    sign_pczt_with_seed_fingerprint_inner(pczt, seed, seed_fingerprint, Some(account_index))
}

/// Shared signing core for both ordinary and batch paths. `selected_account`
/// distinguishes them: `None` signs any of the seed's accounts, `Some` restricts
/// to that one.
#[cfg(feature = "cypherpunk")]
fn sign_pczt_with_seed_fingerprint_inner(
    mut pczt: Pczt,
    seed: &[u8],
    seed_fingerprint: [u8; 32],
    selected_account: Option<zcash_vendor::zip32::AccountId>,
) -> crate::Result<Vec<u8>> {
    super::validate_supported_pczt(&pczt)?;

    // Capture the wallet's per-output memo-kind tags before `fill_derived_fields`
    // consumes them; the response redaction echoes them (see `RequestMemoKinds`).
    let request_memo_kinds = RequestMemoKinds::capture(&pczt);

    if let Some(account_index) = selected_account {
        fill_selected_account_spend_fvks(&mut pczt, seed, &seed_fingerprint, account_index)?;
    }

    // Recompute and fill any Orchard/Ironwood derived fields a wallet omitted to keep the
    // request QR small (cv_net, nullifier, rk, cmx, ephemeral_key, enc_ciphertext; an
    // elided anchor refills as the empty-tree placeholder). The lean sighash below reads
    // these directly off the PCZT, so they must be present; this is a no-op for a full
    // PCZT. The redactor strips them again from the response.
    pczt.fill_derived_fields()
        .map_err(|e| ZcashError::InvalidPczt(format!("failed to fill derived fields: {e:?}")))?;

    #[cfg(zcash_unstable = "nu6.3")]
    let process_ironwood = super::pczt_should_process_ironwood(&pczt);

    // The orchard signer handles both the transparent inputs and the Orchard bundle
    // (the pool only changes error labels for shielded actions). Ironwood gets its own.
    let orchard_signer = if let Some(account_index) = selected_account {
        SeedSigner::for_batch_account(seed, seed_fingerprint, ShieldedPool::Orchard, account_index)
    } else {
        SeedSigner::new(seed, seed_fingerprint, ShieldedPool::Orchard)
    };

    // Propagate the signer error directly (it is already a ZcashError): the strict
    // validation in SeedSigner::sign_orchard returns ZcashError::InvalidPczt for bad
    // ZIP 32 paths, which callers/tests distinguish from generic SigningError.
    let signer = low_level_signer::Signer::new(pczt);
    let signer = pczt_ext::sign_transparent(signer, &orchard_signer)?;
    let signer = pczt_ext::sign_orchard(signer, &orchard_signer)?;

    #[cfg(zcash_unstable = "nu6.3")]
    let ironwood_signer = if let Some(account_index) = selected_account {
        SeedSigner::for_batch_account(
            seed,
            seed_fingerprint,
            ShieldedPool::Ironwood,
            account_index,
        )
    } else {
        SeedSigner::new(seed, seed_fingerprint, ShieldedPool::Ironwood)
    };
    #[cfg(zcash_unstable = "nu6.3")]
    let signer = if process_ironwood {
        pczt_ext::sign_ironwood(signer, &ironwood_signer)?
    } else {
        signer
    };

    let mut signed = orchard_signer.signed.get();
    #[cfg(zcash_unstable = "nu6.3")]
    {
        signed += ironwood_signer.signed.get();
    }
    if signed == 0 {
        return Err(ZcashError::PcztNoMyInputs);
    }

    stamp_and_redact(signer.finish(), &request_memo_kinds)
        .serialize()
        .map_err(|e| ZcashError::InvalidPczt(alloc::format!("pczt serialize: {e:?}")))
}

#[cfg(feature = "cypherpunk")]
fn fill_selected_account_spend_fvks(
    pczt: &mut Pczt,
    seed: &[u8],
    seed_fingerprint: &[u8; 32],
    account_index: zcash_vendor::zip32::AccountId,
) -> crate::Result<()> {
    const ZCASH_COIN_TYPE: u32 = 133;

    let osk = orchard::keys::SpendingKey::from_zip32_seed(seed, ZCASH_COIN_TYPE, account_index)
        .map_err(|e| {
            ZcashError::SigningError(format!(
                "failed to derive selected account Orchard FVK: {e:?}"
            ))
        })?;
    let fvk = orchard::keys::FullViewingKey::from(&osk).to_bytes();
    let account_child: zcash_vendor::zip32::ChildIndex = account_index.into();
    let derivation_path = [
        zcash_vendor::zip32::ChildIndex::hardened(32).index(),
        zcash_vendor::zip32::ChildIndex::hardened(ZCASH_COIN_TYPE).index(),
        account_child.index(),
    ];

    pczt.fill_missing_spend_fvks_for_zip32_path(seed_fingerprint, &derivation_path, fvk);
    Ok(())
}

/// The per-output [`MemoKind`] tags carried by the inbound request's Orchard-shaped
/// bundles, captured before `fill_derived_fields` consumes them. `orchard[i]` /
/// `ironwood[i]` is the tag the wallet recorded when it elided action `i`'s
/// `enc_ciphertext`, or `None` if the request carried the ciphertext.
///
/// The response redaction echoes these tags: re-eliding a response ciphertext under
/// the wallet's own (wallet-verified) tag keeps the response mergeable with the
/// request (`memo_kind` merges by equality in the pczt `Combiner`, so a differing tag
/// would make the postflight recombine fail), and the device never invents a tag for
/// an output whose memo it has not verified.
struct RequestMemoKinds {
    orchard: Vec<Option<MemoKind>>,
    #[cfg(zcash_unstable = "nu6.3")]
    ironwood: Vec<Option<MemoKind>>,
}

impl RequestMemoKinds {
    /// Captures the memo-kind tags of both Orchard-shaped bundles; see the type doc.
    fn capture(pczt: &Pczt) -> Self {
        let capture_bundle = |bundle: &zcash_vendor::pczt::orchard::Bundle| {
            bundle
                .actions()
                .iter()
                .map(|action| *action.output().memo_kind())
                .collect()
        };
        Self {
            orchard: capture_bundle(pczt.orchard()),
            #[cfg(zcash_unstable = "nu6.3")]
            ironwood: capture_bundle(pczt.ironwood()),
        }
    }
}

fn stamp_and_redact(pczt: Pczt, request_memo_kinds: &RequestMemoKinds) -> Pczt {
    // Stamp the firmware version into `global.proprietary` so the wallet can
    // tell exactly which version of Keystone firmware produced this signature.
    // The Redactor below intentionally does not touch `global`, so this value
    // survives the redaction pass into the returned bytes.
    let stamped_pczt = Updater::new(pczt)
        .update_global_with(|mut g| {
            g.set_proprietary(
                PROP_KEY_FW_VERSION.into(),
                KEYSTONE_FW_VERSION.encode().to_vec(),
            );
        })
        .finish();

    // Now that we've created the signature, remove optional fields that the
    // signing response does not need. This keeps the QR round trip small while
    // preserving signatures and global proprietary fields for the wallet.
    let redactor = Redactor::new(stamped_pczt)
        .redact_orchard_with(|r| redact_orchard_bundle(r, &request_memo_kinds.orchard));
    #[cfg(zcash_unstable = "nu6.3")]
    let redactor =
        redactor.redact_ironwood_with(|r| redact_orchard_bundle(r, &request_memo_kinds.ironwood));

    redactor
        .redact_sapling_with(|mut r| {
            r.redact_spends(|mut sr| {
                sr.clear_zkproof();
                sr.clear_recipient();
                sr.clear_value();
                sr.clear_rcm();
                sr.clear_rseed();
                sr.clear_rcv();
                sr.clear_proof_generation_key();
                sr.clear_witness();
                sr.clear_alpha();
                sr.clear_zip32_derivation();
                sr.clear_dummy_ask();
            });
            r.redact_outputs(|mut or| {
                or.clear_zkproof();
                or.clear_recipient();
                or.clear_value();
                or.clear_rseed();
                or.clear_rcv();
                or.clear_ock();
                or.clear_zip32_derivation();
                or.clear_user_address();
            });
            r.clear_bsk();
        })
        .redact_transparent_with(|mut r| {
            r.redact_inputs(|mut ir| {
                ir.clear_redeem_script();
                ir.clear_bip32_derivation();
                ir.clear_ripemd160_preimages();
                ir.clear_sha256_preimages();
                ir.clear_hash160_preimages();
                ir.clear_hash256_preimages();
            });
            r.redact_outputs(|mut or| {
                or.clear_redeem_script();
                or.clear_bip32_derivation();
                or.clear_user_address();
            });
        })
        .finish()
}

/// Strips the response fields the wallet refills from its own copy. An output's
/// `enc_ciphertext` is re-elided only under the request's own memo-kind tag
/// (`request_memo_kinds[i]`, wallet-verified); when the request carried the
/// ciphertext the response keeps it, since the device cannot attest a tag for a
/// memo it has not seen. See [`RequestMemoKinds`].
fn redact_orchard_bundle(mut r: OrchardRedactor<'_>, request_memo_kinds: &[Option<MemoKind>]) {
    r.redact_actions(|mut ar| {
        ar.clear_spend_recipient();
        ar.clear_spend_value();
        ar.clear_spend_rho();
        ar.clear_spend_rseed();
        ar.clear_spend_fvk();
        ar.clear_spend_witness();
        ar.clear_spend_alpha();
        ar.clear_spend_zip32_derivation();
        ar.clear_spend_dummy_sk();
        ar.clear_output_recipient();
        ar.clear_output_value();
        ar.clear_output_rseed();
        ar.clear_output_ock();
        ar.clear_output_zip32_derivation();
        ar.clear_output_user_address();
        ar.clear_rcv();
        ar.clear_cv_net();
        ar.clear_nullifier();
        ar.clear_rk();
        ar.clear_cmx();
        ar.clear_ephemeral_key();
    });
    for (index, memo_kind) in request_memo_kinds.iter().enumerate() {
        if let Some(memo_kind) = *memo_kind {
            r.redact_action(index, |mut ar| ar.clear_enc_ciphertext(memo_kind));
        }
    }
    r.clear_zkproof();
    r.clear_bsk();
}

#[cfg(any(
    feature = "cypherpunk",
    all(feature = "multi_coins", not(feature = "cypherpunk"))
))]
fn transparent_key_path_for_input(
    seed: &[u8],
    input: &transparent::pczt::Input,
) -> Result<Option<String>, ZcashError> {
    let fingerprint =
        calculate_seed_fingerprint(seed).map_err(|e| ZcashError::SigningError(e.to_string()))?;

    for (pubkey, path) in input.bip32_derivation().iter() {
        let path_fingerprint = *path.seed_fingerprint();
        if fingerprint != path_fingerprint {
            continue;
        }

        let path = {
            let mut ret = "m".to_string();
            for i in path.derivation_path().iter() {
                if i.is_hardened() {
                    ret.push_str(&format!("/{}'", i.index()));
                } else {
                    ret.push_str(&format!("/{}", i.index()));
                }
            }
            ret
        };

        match get_public_key_by_seed(seed, &path) {
            Ok(my_pubkey) if my_pubkey.serialize().to_vec().eq(pubkey) => return Ok(Some(path)),
            Err(e) => return Err(ZcashError::SigningError(e.to_string())),
            _ => {}
        }
    }

    Ok(None)
}

#[cfg(feature = "cypherpunk")]
use super::ShieldedPool;

#[cfg(all(test, feature = "cypherpunk"))]
mod tests {
    use super::*;
    // RoleSigner is the upstream reference signer; tests use its sighash as the
    // bit-exact oracle for the lean pczt_ext::shielded_sig_commitment.
    use zcash_vendor::pczt::roles::signer::Signer as RoleSigner;

    fn assert_invalid_pczt_message<T: core::fmt::Debug>(result: crate::Result<T>, expected: &str) {
        match result {
            Err(ZcashError::InvalidPczt(message)) if message == expected => {}
            other => panic!("unexpected InvalidPczt result: {other:?}"),
        }
    }

    #[cfg(zcash_unstable = "nu6.3")]
    fn signable_sample_pczt() -> crate::pczt::test_support::SamplePczt {
        crate::pczt::test_support::sample_ironwood_pczt()
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_sign_pczt_invalid_seed_fingerprint() {
        let sample = signable_sample_pczt();
        let pczt = Pczt::parse(&sample.bytes).unwrap();
        let mismatched_seed = [9u8; 32];

        let result = sign_pczt(pczt, &mismatched_seed);
        assert!(matches!(result, Err(ZcashError::PcztNoMyInputs)));
    }

    // Consensus guard: the lean byte-level sighash (pczt_ext::shielded_sig_commitment) MUST
    // equal the upstream RoleSigner sighash for every shielded shape we sign. These assert it
    // bit-exact for an Orchard-only tx, a dual-pool Orchard->Ironwood migration, and an
    // Ironwood spend, so any upstream sighash change turns CI red instead of silently
    // producing wrong signatures on-device.
    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_lean_sighash_control_orchard_only() {
        let sample = crate::pczt::test_support::sample_orchard_change_pczt();
        let pczt = Pczt::parse(&sample.bytes).unwrap();
        let oracle = RoleSigner::new(pczt.clone()).unwrap().shielded_sighash();
        let lean: [u8; 32] = zcash_vendor::pczt_ext::shielded_sig_commitment(&pczt, 0, None)
            .as_bytes()
            .try_into()
            .unwrap();
        assert_eq!(
            lean, oracle,
            "orchard-only: lean 4-node sighash should already equal RoleSigner"
        );
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_lean_sighash_migration_dualpool() {
        let sample = crate::pczt::test_support::sample_migration_pczt();
        let pczt = Pczt::parse(&sample.bytes).unwrap();
        let oracle = RoleSigner::new(pczt.clone()).unwrap().shielded_sighash();
        let lean: [u8; 32] = zcash_vendor::pczt_ext::shielded_sig_commitment(&pczt, 0, None)
            .as_bytes()
            .try_into()
            .unwrap();
        assert_eq!(
            lean, oracle,
            "migration: lean sighash must match RoleSigner v6 (Ironwood) sighash"
        );
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_lean_sighash_ironwood_spend() {
        // Exercises a populated Ironwood bundle with a real spend action.
        let sample = crate::pczt::test_support::sample_ironwood_pczt();
        let pczt = Pczt::parse(&sample.bytes).unwrap();
        let oracle = RoleSigner::new(pczt.clone()).unwrap().shielded_sighash();
        let lean: [u8; 32] = zcash_vendor::pczt_ext::shielded_sig_commitment(&pczt, 0, None)
            .as_bytes()
            .try_into()
            .unwrap();
        assert_eq!(
            lean, oracle,
            "ironwood-spend: lean sighash must match RoleSigner v6 sighash"
        );
    }

    // End-to-end consume-side proof for elidable-field requests: a migration request
    // with every derived field, both anchors, and every enc_ciphertext elided (tagged
    // with the wallet's memo kinds) must check, parse, and sign; the spend
    // authorization must commit to the same sighash as a never-elided request; the
    // response must re-elide each ciphertext under the request's own tag; and the
    // redacted response must recombine with the elided request (the device postflight
    // path in rust_c).
    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_sign_elided_migration_request_echoes_memo_kinds() {
        use zcash_vendor::pczt::roles::{combiner::Combiner, redactor::orchard::OrchardRedactor};

        let sample = crate::pczt::test_support::sample_migration_pczt();
        let full = Pczt::parse(&sample.bytes).unwrap();
        let full_sighash = RoleSigner::new(full.clone())
            .expect("full migration PCZT signer should initialize")
            .shielded_sighash();

        // The wallet may only elide an enc_ciphertext it has verified to be the
        // deterministic encryption under one of the two memo constants: probe each
        // output by re-eliding a clone under each tag and refilling, keeping the tag
        // exactly when the reconstruction is byte-identical. In this sample the pure
        // dummy Orchard output reconstructs under `Zero` and the Ironwood migration
        // output (built with the ZIP 302 empty memo) under `Empty`. The migrated
        // Orchard note is internal-scope, so both Orchard zero-valued outputs
        // recompute under `Zero`.
        fn elidable_memo_kinds(
            full: &Pczt,
            bundle_of: fn(&Pczt) -> &zcash_vendor::pczt::orchard::Bundle,
            redact_with: fn(Redactor, fn(OrchardRedactor<'_>)) -> Redactor,
        ) -> Vec<Option<MemoKind>> {
            let original: Vec<_> = bundle_of(full)
                .actions()
                .iter()
                .map(|action| action.output().enc_ciphertext().clone())
                .collect();
            let mut tags = alloc::vec![None; original.len()];
            for (kind, probe_all) in [
                (
                    MemoKind::Zero,
                    (|mut r: OrchardRedactor<'_>| {
                        r.redact_actions(|mut ar| ar.clear_enc_ciphertext(MemoKind::Zero));
                    }) as fn(OrchardRedactor<'_>),
                ),
                (MemoKind::Empty, |mut r: OrchardRedactor<'_>| {
                    r.redact_actions(|mut ar| ar.clear_enc_ciphertext(MemoKind::Empty));
                }),
            ] {
                let mut probe = redact_with(Redactor::new(full.clone()), probe_all).finish();
                probe
                    .fill_derived_fields()
                    .expect("probe reconstruction must fill");
                for (index, action) in bundle_of(&probe).actions().iter().enumerate() {
                    if tags[index].is_none() && action.output().enc_ciphertext() == &original[index]
                    {
                        tags[index] = Some(kind);
                    }
                }
            }
            tags
        }
        let orchard_tags = elidable_memo_kinds(
            &full,
            |pczt| pczt.orchard(),
            |redactor, f| redactor.redact_orchard_with(f),
        );
        let ironwood_tags = elidable_memo_kinds(
            &full,
            |pczt| pczt.ironwood(),
            |redactor, f| redactor.redact_ironwood_with(f),
        );
        assert!(!orchard_tags.is_empty());
        assert!(
            orchard_tags.iter().all(|tag| *tag == Some(MemoKind::Zero)),
            "internal migration Orchard outputs must all recompute under the zero memo"
        );
        assert_eq!(ironwood_tags, alloc::vec![Some(MemoKind::Empty)]);

        // Elide the request the way the optimizing wallet does: the six derived
        // fields, the bundle anchor, and each *verified* enc_ciphertext under its tag.
        fn elide_request_bundle(mut r: OrchardRedactor<'_>, memo_kinds: &[Option<MemoKind>]) {
            r.redact_actions(|mut ar| {
                ar.clear_cv_net();
                ar.clear_nullifier();
                ar.clear_rk();
                ar.clear_cmx();
                ar.clear_ephemeral_key();
            });
            for (index, memo_kind) in memo_kinds.iter().enumerate() {
                if let Some(memo_kind) = *memo_kind {
                    r.redact_action(index, |mut ar| ar.clear_enc_ciphertext(memo_kind));
                }
            }
            r.clear_anchor();
        }
        let elided_request = Redactor::new(full.clone())
            .redact_orchard_with(|r| elide_request_bundle(r, &orchard_tags))
            .redact_ironwood_with(|r| elide_request_bundle(r, &ironwood_tags))
            .finish();
        let elided_bytes = elided_request
            .clone()
            .serialize()
            .expect("elided request must serialize");
        assert!(
            elided_bytes.len() < sample.bytes.len(),
            "eliding must shrink the request",
        );

        // The device-side check and parse paths accept the elided request (the fill
        // recomputes byte-identical fields, so decryption and cv_net checks pass).
        crate::check_pczt_cypherpunk(
            &crate::pczt::test_support::Nu6_3Network,
            &elided_bytes,
            &sample.ufvk_text,
            &sample.seed_fingerprint,
            0,
        )
        .expect("elided migration request must pass the pre-sign checks");
        crate::parse_pczt_cypherpunk(
            &crate::pczt::test_support::Nu6_3Network,
            &elided_bytes,
            &sample.ufvk_text,
            &sample.seed_fingerprint,
        )
        .expect("elided migration request must parse for display");

        let signed = sign_pczt(elided_request.clone(), &sample.seed)
            .expect("elided migration request must sign");
        let response = Pczt::parse(&signed).expect("signed response must parse");

        // The response re-elides each enc_ciphertext under the request's own tag.
        for (bundle, tags) in [
            (response.orchard(), &orchard_tags),
            (response.ironwood(), &ironwood_tags),
        ] {
            for (action, tag) in bundle.actions().iter().zip(tags) {
                assert_eq!(action.output().memo_kind(), tag);
                assert_eq!(action.output().enc_ciphertext().is_none(), tag.is_some());
            }
        }

        // The Orchard spend authorization commits to the never-elided sighash: the
        // recompute-on-receive fill is byte-identical to the elided values.
        let mut filled = full;
        filled
            .fill_derived_fields()
            .expect("full migration PCZT should fill");
        let mut verified = 0;
        for (action, filled_action) in response
            .orchard()
            .actions()
            .iter()
            .zip(filled.orchard().actions())
        {
            if let Some(sig) = action.spend().spend_auth_sig() {
                let rk_bytes = filled_action
                    .spend()
                    .rk()
                    .expect("filled PCZT must carry rk");
                let rk = orchard::primitives::redpallas::VerificationKey::<
                    orchard::primitives::redpallas::SpendAuth,
                >::try_from(rk_bytes)
                .expect("randomized validating key must parse");
                let sig: orchard::primitives::redpallas::Signature<
                    orchard::primitives::redpallas::SpendAuth,
                > = (*sig).into();
                rk.verify(&full_sighash, &sig)
                    .expect("elided-request signature must match the full-request sighash");
                verified += 1;
            }
        }
        assert!(verified > 0, "the Orchard spend must be authorized");

        // The device postflight recombines the redacted response with the (elided)
        // original request; the echoed tags merge by equality.
        let combined = Combiner::new(alloc::vec![elided_request, response])
            .combine()
            .expect("response must recombine with the elided request")
            .serialize()
            .expect("recombined PCZT must serialize");
        crate::ensure_owned_supported_shielded_actions_are_signed(
            &crate::pczt::test_support::Nu6_3Network,
            &elided_bytes,
            &combined,
            &sample.seed_fingerprint,
            0,
        )
        .expect("postflight must confirm the signature on the recombined PCZT");
    }

    // End-to-end: an Orchard->Ironwood migration signs the Orchard spend and leaves the
    // output-only Ironwood bundle unsigned.
    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_sign_pczt_migration_signs_orchard_only() {
        let sample = crate::pczt::test_support::sample_migration_pczt();
        let signed = sign_pczt(Pczt::parse(&sample.bytes).unwrap(), &sample.seed)
            .expect("migration PCZT should sign");
        let parsed = Pczt::parse(&signed).expect("signed migration PCZT must parse");
        assert!(
            parsed
                .orchard()
                .actions()
                .iter()
                .any(|a| a.spend().spend_auth_sig().is_some()),
            "migration Orchard spend must be authorized",
        );
        assert!(
            parsed
                .ironwood()
                .actions()
                .iter()
                .all(|a| a.spend().spend_auth_sig().is_none()),
            "output-only Ironwood bundle must not be authorized",
        );
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_sign_pczt_ironwood_spend() {
        let sample = crate::pczt::test_support::sample_ironwood_pczt();
        let pczt = Pczt::parse(&sample.bytes).unwrap();

        let base_sighash = RoleSigner::new(pczt.clone())
            .expect("Ironwood PCZT signer should initialize")
            .shielded_sighash();
        // Elide the Ironwood anchor with the Redactor and refill it: the receiver
        // installs the fixed empty-tree placeholder, which differs from the sample's
        // real anchor, so this exercises signing with a changed anchor.
        let mut anchor_swapped_pczt = Redactor::new(pczt.clone())
            .redact_ironwood_with(|mut r| r.clear_anchor())
            .finish();
        assert_eq!(anchor_swapped_pczt.ironwood().anchor(), &None);
        anchor_swapped_pczt
            .fill_derived_fields()
            .expect("anchor-elided Ironwood PCZT should refill");
        assert_ne!(
            pczt.ironwood().anchor(),
            anchor_swapped_pczt.ironwood().anchor()
        );
        assert_eq!(
            base_sighash,
            RoleSigner::new(anchor_swapped_pczt)
                .expect("anchor-swapped Ironwood PCZT signer should initialize")
                .shielded_sighash(),
            "v6 Ironwood spend signatures must not commit to the anchor"
        );

        // The signing response redacts `rk` (see `redact_orchard_bundle`), so source each
        // action's randomized validating key from the filled unsigned PCZT, matched by
        // index to the corresponding signed action below.
        let mut filled = pczt.clone();
        filled
            .fill_derived_fields()
            .expect("derived fields should fill for the sample Ironwood PCZT");
        let rks: Vec<Option<[u8; 32]>> = filled
            .ironwood()
            .actions()
            .iter()
            .map(|action| *action.spend().rk())
            .collect();

        let signed_pczt_bytes = sign_pczt(pczt, &sample.seed).expect("Ironwood PCZT should sign");
        let parsed = Pczt::parse(&signed_pczt_bytes).expect("signed PCZT must parse");

        let stamp = parsed
            .global()
            .proprietary()
            .get(PROP_KEY_FW_VERSION)
            .expect("firmware version stamp must be present");
        assert_eq!(stamp, &KEYSTONE_FW_VERSION.encode().to_vec());
        assert!(
            parsed
                .ironwood()
                .actions()
                .iter()
                .any(|action| action.spend().spend_auth_sig().is_some()),
            "Ironwood spend authorization signature must be present",
        );
        for (index, action) in parsed.ironwood().actions().iter().enumerate() {
            if let Some(sig) = action.spend().spend_auth_sig() {
                let rk_bytes = rks[index].expect("filled unsigned PCZT must carry rk");
                let rk = orchard::primitives::redpallas::VerificationKey::<
                    orchard::primitives::redpallas::SpendAuth,
                >::try_from(rk_bytes)
                .expect("Ironwood randomized validating key must parse");
                let sig: orchard::primitives::redpallas::Signature<
                    orchard::primitives::redpallas::SpendAuth,
                > = (*sig).into();

                rk.verify(&base_sighash, &sig)
                    .expect("Ironwood spend authorization signature must match v6 sighash");
            }
        }
        assert!(
            signed_pczt_bytes.len() < sample.bytes.len(),
            "signed response should be redacted",
        );
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_sign_pczt_ironwood_spend_rejects_unsupported_zip32_path() {
        let sample = crate::pczt::test_support::sample_ironwood_pczt();
        for path in crate::pczt::test_support::unsupported_orchard_spend_paths() {
            let pczt = crate::pczt::test_support::ironwood_pczt_with_spend_derivation(
                &sample.bytes,
                sample.seed_fingerprint,
                path,
            );

            assert_invalid_pczt_message(
                sign_pczt(Pczt::parse(&pczt).unwrap(), &sample.seed),
                "unsupported Ironwood spend ZIP 32 derivation path",
            );
        }
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_sign_pczt_ironwood_spend_ignores_dummy_zip32_metadata() {
        let sample = crate::pczt::test_support::sample_ironwood_pczt();
        let pczt = crate::pczt::test_support::ironwood_pczt_with_dummy_spend_derivation(
            &sample.bytes,
            sample.seed_fingerprint,
            crate::pczt::test_support::orchard_spend_path_for_account(1),
        );

        let signed = sign_pczt(Pczt::parse(&pczt).unwrap(), &sample.seed)
            .expect("dummy spend ZIP 32 metadata must not block signing real spends");
        let parsed = Pczt::parse(&signed).expect("signed PCZT must parse");
        assert!(
            parsed
                .ironwood()
                .actions()
                .iter()
                .any(|action| action.spend().spend_auth_sig().is_some()),
            "Ironwood spend authorization signature must be present",
        );
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_sign_pczt_orchard_change_output_spend() {
        let sample = crate::pczt::test_support::sample_orchard_change_pczt();
        let pczt = Pczt::parse(&sample.bytes).unwrap();

        let signed =
            sign_pczt(pczt, &sample.seed).expect("Orchard change output spend should sign");
        let parsed = Pczt::parse(&signed).expect("signed PCZT must parse");
        let signed_actions = parsed
            .orchard()
            .actions()
            .iter()
            .filter(|action| action.spend().spend_auth_sig().is_some())
            .count();
        assert_eq!(
            signed_actions, 2,
            "real spend and wallet controlled zero value spend must be signed",
        );
    }

    #[cfg(zcash_unstable = "nu6.3")]
    fn pczt_with_min_version(min_version: &[u8]) -> Pczt {
        let sample = signable_sample_pczt();
        let base = Pczt::parse(&sample.bytes).unwrap();
        let min_version = min_version.to_vec();
        Updater::new(base)
            .update_global_with(|mut g| {
                g.set_proprietary("test:min_fw_version".to_string(), min_version);
            })
            .finish()
    }

    #[cfg(zcash_unstable = "nu6.3")]
    fn test_seed() -> Vec<u8> {
        [7u8; 32].to_vec()
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn firmware_equal_version_stamps_response() {
        let pczt = pczt_with_min_version(&KEYSTONE_FW_VERSION.encode());
        let signed = sign_pczt(pczt, &test_seed()).expect("equal-version PCZT should sign");
        let parsed = Pczt::parse(&signed).expect("signed PCZT must parse");

        let stamp = parsed
            .global()
            .proprietary()
            .get(PROP_KEY_FW_VERSION)
            .expect("firmware version stamp must be present");
        assert_eq!(stamp, &KEYSTONE_FW_VERSION.encode().to_vec());

        let request_min = parsed
            .global()
            .proprietary()
            .get("test:min_fw_version")
            .expect("request min-version should round-trip");
        assert_eq!(request_min, &KEYSTONE_FW_VERSION.encode().to_vec());
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn firmware_older_min_version_still_stamps_response() {
        let pczt = pczt_with_min_version(&[1, 0, 0]);
        let signed = sign_pczt(pczt, &test_seed()).expect("older-min PCZT should sign");
        let parsed = Pczt::parse(&signed).expect("signed PCZT must parse");

        let stamp = parsed
            .global()
            .proprietary()
            .get(PROP_KEY_FW_VERSION)
            .expect("firmware version stamp must be present");
        assert_eq!(stamp, &KEYSTONE_FW_VERSION.encode().to_vec());
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn malformed_min_version_round_trips_and_stamps() {
        let pczt = pczt_with_min_version(&[1, 2]);
        let signed =
            sign_pczt(pczt, &test_seed()).expect("malformed min bytes must not block signing");
        let parsed = Pczt::parse(&signed).expect("signed PCZT must parse");

        let stamp = parsed
            .global()
            .proprietary()
            .get(PROP_KEY_FW_VERSION)
            .expect("firmware version stamp must be present");
        assert_eq!(stamp, &KEYSTONE_FW_VERSION.encode().to_vec());

        let request_min = parsed
            .global()
            .proprietary()
            .get("test:min_fw_version")
            .expect("wallet-set min key must survive round trip");
        assert_eq!(request_min.as_slice(), &[1u8, 2][..]);
    }
}

#[cfg(all(test, feature = "multi_coins", not(feature = "cypherpunk")))]
mod legacy_tests {
    use super::*;
    use zcash_vendor::{
        pczt::roles::creator::Creator,
        zcash_protocol::consensus::{BranchId, MainNetwork, NetworkConstants},
    };

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn legacy_signing_rejects_v6_pczt() {
        let pczt = Creator::new(
            BranchId::Nu6_3.into(),
            10,
            MainNetwork.coin_type(),
            [0; 32],
            [0; 32],
        )
        .unwrap()
        .with_ironwood_anchor([1; 32])
        .unwrap()
        .build();

        let result = sign_pczt(pczt, &[7u8; 32]);

        assert!(matches!(
            result,
            Err(ZcashError::SigningError(msg))
                if msg == "Shielded or V6 PCZTs require cypherpunk signing support"
        ));
    }
}
