use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use bitcoin::secp256k1;
#[cfg(all(feature = "multi_coins", not(feature = "cypherpunk")))]
use keystore::algorithms::secp256k1::get_public_key_by_seed;
use keystore::algorithms::{secp256k1::get_private_key_by_seed, zcash::calculate_seed_fingerprint};
use zcash_vendor::{
    pczt::{
        roles::{
            low_level_signer,
            redactor::{orchard::OrchardRedactor, Redactor},
            updater::Updater,
        },
        Pczt,
    },
    transparent, zip32,
};

#[cfg(feature = "cypherpunk")]
use zcash_vendor::{
    orchard,
    pczt::roles::signer::Signer as RoleSigner,
    ripemd::Ripemd160,
    sha2::{Digest, Sha256},
    transparent::{address::TransparentAddress, keys::AccountPrivKey},
    zcash_protocol::consensus::{MainNetwork, Parameters},
};

#[cfg(all(feature = "multi_coins", not(feature = "cypherpunk")))]
use zcash_vendor::{
    pczt_ext::{self, PcztSigner as LegacyPcztSigner},
    transparent::sighash::SignableInput,
};

use crate::{errors::ZcashError, version::KEYSTONE_FW_VERSION};

/// `global.proprietary` key stamped into every signed PCZT response.
/// Value is 3 bytes `[major, minor, build]`. Wallets read this to check
/// whether the device meets their minimum version requirements.
const PROP_KEY_FW_VERSION: &str = "keystone:fw_version";

#[derive(Debug)]
#[cfg(feature = "cypherpunk")]
enum SigningKeyCollectionError {
    Zcash(ZcashError),
    TransparentParse(transparent::pczt::ParseError),
    #[cfg(feature = "cypherpunk")]
    OrchardParse(orchard::pczt::ParseError),
    OrchardBundleParse(zcash_vendor::pczt::orchard::BundleParseError),
}

#[cfg(feature = "cypherpunk")]
impl SigningKeyCollectionError {
    fn into_zcash(self) -> ZcashError {
        match self {
            SigningKeyCollectionError::Zcash(e) => e,
            SigningKeyCollectionError::TransparentParse(e) => {
                ZcashError::SigningError(format!("failed to parse transparent bundle: {e:?}"))
            }
            #[cfg(feature = "cypherpunk")]
            SigningKeyCollectionError::OrchardParse(e) => {
                ZcashError::SigningError(format!("failed to parse shielded bundle: {e:?}"))
            }
            SigningKeyCollectionError::OrchardBundleParse(e) => {
                ZcashError::SigningError(format!("failed to parse shielded bundle: {e:?}"))
            }
        }
    }
}

#[cfg(feature = "cypherpunk")]
impl From<ZcashError> for SigningKeyCollectionError {
    fn from(e: ZcashError) -> Self {
        SigningKeyCollectionError::Zcash(e)
    }
}

#[cfg(feature = "cypherpunk")]
impl From<transparent::pczt::ParseError> for SigningKeyCollectionError {
    fn from(e: transparent::pczt::ParseError) -> Self {
        SigningKeyCollectionError::TransparentParse(e)
    }
}

#[cfg(feature = "cypherpunk")]
impl From<orchard::pczt::ParseError> for SigningKeyCollectionError {
    fn from(e: orchard::pczt::ParseError) -> Self {
        SigningKeyCollectionError::OrchardParse(e)
    }
}

#[cfg(feature = "cypherpunk")]
impl From<zcash_vendor::pczt::orchard::BundleParseError> for SigningKeyCollectionError {
    fn from(e: zcash_vendor::pczt::orchard::BundleParseError) -> Self {
        SigningKeyCollectionError::OrchardBundleParse(e)
    }
}

#[cfg(all(feature = "multi_coins", not(feature = "cypherpunk")))]
struct SeedSigner<'a> {
    seed: &'a [u8],
    account_index: zip32::AccountId,
}

#[cfg(all(feature = "multi_coins", not(feature = "cypherpunk")))]
impl LegacyPcztSigner for SeedSigner<'_> {
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
        if let Some(path) = transparent_key_path_for_input(self.seed, self.account_index, input)? {
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
pub fn sign_pczt(
    pczt: Pczt,
    seed: &[u8],
    account_index: zip32::AccountId,
) -> crate::Result<Vec<u8>> {
    super::validate_supported_pczt(&pczt)?;
    reject_legacy_unsupported_pczt(&pczt)?;

    let signer = low_level_signer::Signer::new(pczt);

    #[cfg(feature = "multi_coins")]
    let signer = pczt_ext::sign_transparent(
        signer,
        &SeedSigner {
            seed,
            account_index,
        },
    )
    .map_err(|e| ZcashError::SigningError(e.to_string()))?;

    Ok(stamp_and_redact(signer.finish()).serialize())
}

#[cfg(not(feature = "cypherpunk"))]
fn reject_legacy_unsupported_pczt(pczt: &Pczt) -> Result<(), ZcashError> {
    #[cfg(zcash_unstable = "nu7")]
    {
        // The legacy helper below carries the pre-NU7 transparent sighash implementation.
        // It must not be used for V6/Ironwood PCZTs.
        if super::pczt_requires_cypherpunk_support(pczt) {
            return Err(ZcashError::SigningError(
                "V6 or Ironwood PCZTs require cypherpunk signing support".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "cypherpunk")]
pub fn sign_pczt(
    pczt: Pczt,
    seed: &[u8],
    account_index: zip32::AccountId,
) -> crate::Result<Vec<u8>> {
    sign_pczt_with_network(&MainNetwork, pczt, seed, account_index)
}

/// Signs a PCZT using the supplied Zcash network parameters.
///
/// Transparent signing depends on the network coin type, so cypherpunk callers
/// that support testnet must pass the selected network instead of using the
/// mainnet wrapper.
#[cfg(feature = "cypherpunk")]
pub fn sign_pczt_with_network<P: Parameters>(
    params: &P,
    pczt: Pczt,
    seed: &[u8],
    account_index: zip32::AccountId,
) -> crate::Result<Vec<u8>> {
    super::validate_supported_pczt(&pczt)?;
    let transparent_keys = collect_transparent_signing_keys(params, &pczt, seed, account_index)?;
    let orchard_keys =
        collect_orchard_signing_keys(&pczt, seed, account_index, ShieldedPool::Orchard)?;
    #[cfg(zcash_unstable = "nu7")]
    let ironwood_keys =
        collect_orchard_signing_keys(&pczt, seed, account_index, ShieldedPool::Ironwood)?;

    let signature_count = transparent_keys.len() + orchard_keys.len();
    #[cfg(zcash_unstable = "nu7")]
    let signature_count = signature_count + ironwood_keys.len();
    if signature_count == 0 {
        return Err(ZcashError::PcztNoMyInputs);
    }

    let mut signer = RoleSigner::new(pczt)
        .map_err(|e| ZcashError::SigningError(format!("failed to prepare PCZT signer: {e:?}")))?;

    for (index, sk) in transparent_keys {
        signer
            .sign_transparent(index, &sk)
            .map_err(|e| ZcashError::SigningError(format!("failed to sign input: {e:?}")))?;
    }

    for (index, ask) in orchard_keys {
        signer.sign_orchard(index, &ask).map_err(|e| {
            ZcashError::SigningError(format!("failed to sign Orchard action: {e:?}"))
        })?;
    }

    #[cfg(zcash_unstable = "nu7")]
    for (index, ask) in ironwood_keys {
        signer.sign_ironwood(index, &ask).map_err(|e| {
            ZcashError::SigningError(format!("failed to sign Ironwood action: {e:?}"))
        })?;
    }

    Ok(stamp_and_redact(signer.finish()).serialize())
}

fn stamp_and_redact(pczt: Pczt) -> Pczt {
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
    let redactor = Redactor::new(stamped_pczt).redact_orchard_with(redact_orchard_bundle);
    #[cfg(zcash_unstable = "nu7")]
    let redactor = redactor.redact_ironwood_with(redact_orchard_bundle);

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

fn redact_orchard_bundle(mut r: OrchardRedactor<'_>) {
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
    });
    r.clear_zkproof();
    r.clear_bsk();
}

#[cfg(all(feature = "multi_coins", not(feature = "cypherpunk")))]
fn transparent_key_path_for_input(
    seed: &[u8],
    account_index: zip32::AccountId,
    input: &transparent::pczt::Input,
) -> Result<Option<String>, ZcashError> {
    let fingerprint =
        calculate_seed_fingerprint(seed).map_err(|e| ZcashError::SigningError(e.to_string()))?;

    for (pubkey, path) in input.bip32_derivation().iter() {
        let path_fingerprint = *path.seed_fingerprint();
        if fingerprint != path_fingerprint {
            continue;
        }

        if !legacy_transparent_path_matches_selected_account(path.derivation_path(), account_index)?
        {
            return Err(ZcashError::InvalidPczt(
                "transparent input bip32 derivation path invalid".to_string(),
            ));
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

#[cfg(all(feature = "multi_coins", not(feature = "cypherpunk")))]
fn legacy_transparent_path_matches_selected_account(
    path: &[zcash_vendor::bip32::ChildNumber],
    account_index: zip32::AccountId,
) -> Result<bool, ZcashError> {
    let unsupported_path =
        || ZcashError::InvalidPczt("transparent input bip32 derivation path invalid".to_string());

    let [purpose, coin_type, account, ..] = path else {
        return Err(unsupported_path());
    };

    if !purpose.is_hardened()
        || purpose.index() != 44
        || !coin_type.is_hardened()
        || coin_type.index() != 133
        || !account.is_hardened()
    {
        return Err(unsupported_path());
    }

    zip32::AccountId::try_from(account.index())
        .map(|path_account| path_account == account_index)
        .map_err(|_| unsupported_path())
}

#[cfg(feature = "cypherpunk")]
fn transparent_derivation_path_string(path: &[zcash_vendor::bip32::ChildNumber]) -> String {
    let mut ret = "m".to_string();
    for i in path.iter() {
        if i.is_hardened() {
            ret.push_str(&format!("/{}'", i.index()));
        } else {
            ret.push_str(&format!("/{}", i.index()));
        }
    }
    ret
}

#[cfg(feature = "cypherpunk")]
fn transparent_key_path_for_selected_account<P: Parameters>(
    params: &P,
    seed: &[u8],
    account_index: zip32::AccountId,
    input: &transparent::pczt::Input,
) -> Result<Option<String>, ZcashError> {
    let fingerprint =
        calculate_seed_fingerprint(seed).map_err(|e| ZcashError::SigningError(e.to_string()))?;
    let account = AccountPrivKey::from_seed(params, seed, account_index).map_err(|e| {
        ZcashError::SigningError(format!("failed to derive transparent account key: {e:?}"))
    })?;
    let xpub = account.to_account_pubkey();

    for (pubkey, derivation) in input.bip32_derivation().iter() {
        if fingerprint != *derivation.seed_fingerprint() {
            continue;
        }

        let target = xpub
            .derive_pubkey_at_bip32_path(params, account_index, derivation.derivation_path())
            .map_err(|_| {
                ZcashError::InvalidPczt(
                    "transparent input bip32 derivation path invalid".to_string(),
                )
            })?;
        if &target.serialize() != pubkey {
            return Err(ZcashError::InvalidPczt(
                "transparent input script pubkey mismatch".to_string(),
            ));
        }

        match TransparentAddress::from_script_from_chain(&input.script_pubkey().clone()) {
            Some(TransparentAddress::PublicKeyHash(hash)) => {
                if hash[..] != Ripemd160::digest(Sha256::digest(pubkey))[..] {
                    return Err(ZcashError::InvalidPczt(
                        "transparent input script pubkey mismatch".to_string(),
                    ));
                }
            }
            _ => {
                return Err(ZcashError::InvalidPczt(
                    "transparent input script pubkey is not a public key hash".to_string(),
                ))
            }
        }

        return Ok(Some(transparent_derivation_path_string(
            derivation.derivation_path(),
        )));
    }

    Ok(None)
}

#[cfg(feature = "cypherpunk")]
fn collect_transparent_signing_keys<P: Parameters>(
    params: &P,
    pczt: &Pczt,
    seed: &[u8],
    account_index: zip32::AccountId,
) -> Result<Vec<(usize, secp256k1::SecretKey)>, ZcashError> {
    let mut keys = Vec::new();
    low_level_signer::Signer::new(pczt.clone())
        .sign_transparent_with(|_pczt, bundle, _tx_modifiable| {
            for (index, input) in bundle.inputs_mut().iter().enumerate() {
                if let Some(path) =
                    transparent_key_path_for_selected_account(params, seed, account_index, input)?
                {
                    let sk = get_private_key_by_seed(seed, &path).map_err(|e| {
                        ZcashError::SigningError(format!("failed to get private key: {e:?}"))
                    })?;
                    keys.push((index, sk));
                }
            }
            Ok::<_, SigningKeyCollectionError>(())
        })
        .map_err(SigningKeyCollectionError::into_zcash)?;
    Ok(keys)
}

#[cfg(feature = "cypherpunk")]
#[derive(Clone, Copy)]
enum ShieldedPool {
    Orchard,
    #[cfg(zcash_unstable = "nu7")]
    Ironwood,
}

#[cfg(feature = "cypherpunk")]
impl ShieldedPool {
    fn label(self) -> &'static str {
        match self {
            ShieldedPool::Orchard => "Orchard",
            #[cfg(zcash_unstable = "nu7")]
            ShieldedPool::Ironwood => "Ironwood",
        }
    }
}

#[cfg(feature = "cypherpunk")]
fn collect_orchard_signing_keys(
    pczt: &Pczt,
    seed: &[u8],
    account_index: zip32::AccountId,
    pool: ShieldedPool,
) -> Result<Vec<(usize, orchard::keys::SpendAuthorizingKey)>, ZcashError> {
    let mut keys = Vec::new();

    match pool {
        ShieldedPool::Orchard => {
            low_level_signer::Signer::new(pczt.clone())
                .sign_orchard_with(|_pczt, bundle, _tx_modifiable| {
                    collect_orchard_bundle_signing_keys(
                        &mut keys,
                        seed,
                        account_index,
                        pool,
                        bundle,
                    )
                })
                .map_err(SigningKeyCollectionError::into_zcash)?;
        }
        #[cfg(zcash_unstable = "nu7")]
        ShieldedPool::Ironwood => {
            low_level_signer::Signer::new(pczt.clone())
                .sign_ironwood_with(|_pczt, bundle, _tx_modifiable| {
                    collect_orchard_bundle_signing_keys(
                        &mut keys,
                        seed,
                        account_index,
                        pool,
                        bundle,
                    )
                })
                .map_err(SigningKeyCollectionError::into_zcash)?;
        }
    }

    Ok(keys)
}

#[cfg(feature = "cypherpunk")]
fn collect_orchard_bundle_signing_keys(
    keys: &mut Vec<(usize, orchard::keys::SpendAuthorizingKey)>,
    seed: &[u8],
    account_index: zip32::AccountId,
    pool: ShieldedPool,
    bundle: &mut orchard::pczt::Bundle,
) -> Result<(), SigningKeyCollectionError> {
    for (index, action) in bundle.actions().iter().enumerate() {
        let pool_label = pool.label();
        if action.spend().spend_auth_sig().is_some() {
            continue;
        }
        if action.spend().dummy_sk().is_some() {
            match action.spend().value().map(|value| value.inner()) {
                Some(0) | None => continue,
                Some(_) => {
                    return Err(ZcashError::InvalidPczt(format!(
                        "{pool_label} spend dummy_sk is only valid for dummy spends"
                    ))
                    .into());
                }
            }
        }
        if action.spend().value().is_none() {
            continue;
        }
        if let Some(ask) =
            spend_authorizing_key_for_action(seed, account_index, action, pool_label)?
        {
            keys.push((index, ask));
        }
    }
    Ok(())
}

#[cfg(feature = "cypherpunk")]
fn spend_authorizing_key_for_action(
    seed: &[u8],
    account_index: zip32::AccountId,
    action: &orchard::pczt::Action,
    pool_label: &str,
) -> Result<Option<orchard::keys::SpendAuthorizingKey>, ZcashError> {
    const HARDENED_FLAG: u32 = 1 << 31;
    const ZIP32_PURPOSE: u32 = 32;
    const ZCASH_MAINNET_COIN_TYPE: u32 = 133;
    const ZCASH_TESTNET_COIN_TYPE: u32 = 1;

    let fingerprint =
        calculate_seed_fingerprint(seed).map_err(|e| ZcashError::SigningError(e.to_string()))?;
    let derivation = match action.spend().zip32_derivation().as_ref() {
        Some(derivation) if &fingerprint == derivation.seed_fingerprint() => derivation,
        _ => return Ok(None),
    };

    let unsupported_path = || {
        ZcashError::InvalidPczt(alloc::format!(
            "unsupported {pool_label} spend ZIP 32 derivation path"
        ))
    };
    let [purpose, coin_type, path_account_index] = &derivation.derivation_path()[..] else {
        return Err(unsupported_path());
    };
    if purpose != &zip32::ChildIndex::hardened(ZIP32_PURPOSE) {
        return Err(unsupported_path());
    }

    let coin_type = coin_type
        .index()
        .checked_sub(HARDENED_FLAG)
        .ok_or_else(unsupported_path)?;
    if coin_type != ZCASH_MAINNET_COIN_TYPE && coin_type != ZCASH_TESTNET_COIN_TYPE {
        return Err(unsupported_path());
    }

    let path_account_index = path_account_index
        .index()
        .checked_sub(HARDENED_FLAG)
        .ok_or_else(unsupported_path)?;
    let path_account_id =
        zip32::AccountId::try_from(path_account_index).map_err(|_| unsupported_path())?;
    if path_account_id != account_index {
        return Err(ZcashError::InvalidPczt(alloc::format!(
            "unsupported {pool_label} spend ZIP 32 account index"
        )));
    }

    let osk = orchard::keys::SpendingKey::from_zip32_seed(seed, coin_type, account_index).map_err(
        |e| ZcashError::SigningError(format!("failed to derive {pool_label} spending key: {e:?}")),
    )?;
    Ok(Some(orchard::keys::SpendAuthorizingKey::from(&osk)))
}

#[cfg(all(test, feature = "cypherpunk"))]
mod tests {
    use super::*;

    fn assert_invalid_pczt_message<T: core::fmt::Debug>(result: crate::Result<T>, expected: &str) {
        match result {
            Err(ZcashError::InvalidPczt(message)) if message == expected => {}
            other => panic!("unexpected InvalidPczt result: {other:?}"),
        }
    }

    fn signable_sample_pczt() -> crate::pczt::test_support::SamplePczt {
        #[cfg(zcash_unstable = "nu7")]
        {
            crate::pczt::test_support::sample_ironwood_pczt()
        }
        #[cfg(not(zcash_unstable = "nu7"))]
        {
            crate::pczt::test_support::sample_pczt_to_transparent()
        }
    }

    #[cfg(zcash_unstable = "nu7")]
    fn unsupported_orchard_spend_paths_for_signing() -> Vec<Vec<u32>> {
        crate::pczt::test_support::unsupported_orchard_spend_paths()
            .into_iter()
            .filter(|path| path.get(1) != Some(&zip32::ChildIndex::hardened(1).index()))
            .collect()
    }

    #[test]
    fn test_sign_pczt_invalid_seed_fingerprint() {
        let sample = signable_sample_pczt();
        let pczt = Pczt::parse(&sample.bytes).unwrap();
        let mismatched_seed = [9u8; 32];

        let result = sign_pczt(pczt, &mismatched_seed, zip32::AccountId::ZERO);
        assert!(matches!(result, Err(ZcashError::PcztNoMyInputs)));
    }

    #[cfg(zcash_unstable = "nu7")]
    #[test]
    fn test_sign_pczt_ironwood_spend() {
        let sample = crate::pczt::test_support::sample_ironwood_pczt();
        let pczt = Pczt::parse(&sample.bytes).unwrap();

        let base_sighash = RoleSigner::new(pczt.clone())
            .expect("Ironwood PCZT signer should initialize")
            .shielded_sighash();
        let updated_anchor = orchard::Anchor::from_bytes([6u8; 32]).unwrap();
        let updated_anchor_pczt = Updater::new(pczt.clone())
            .set_v6_ironwood_anchor(updated_anchor)
            .expect("v6 Ironwood anchor should be replaceable before proving")
            .finish();
        assert_ne!(
            pczt.ironwood().anchor(),
            updated_anchor_pczt.ironwood().anchor()
        );
        assert_eq!(
            base_sighash,
            RoleSigner::new(updated_anchor_pczt)
                .expect("anchor-updated Ironwood PCZT signer should initialize")
                .shielded_sighash(),
            "v6 Ironwood spend signatures must not commit to the anchor"
        );

        let signed_pczt_bytes = sign_pczt(pczt, &sample.seed, zip32::AccountId::ZERO)
            .expect("Ironwood PCZT should sign");
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
        for action in parsed.ironwood().actions().iter() {
            if let Some(sig) = action.spend().spend_auth_sig() {
                let rk = orchard::primitives::redpallas::VerificationKey::<
                    orchard::primitives::redpallas::SpendAuth,
                >::try_from(*action.spend().rk())
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

    #[test]
    #[cfg(feature = "legacy_pczt_fixtures")]
    fn test_sign_pczt_transparent_input_requires_selected_account() {
        use zcash_vendor::transparent::keys::IncomingViewingKey;

        let sample = crate::pczt::test_support::sample_pczt_to_transparent();
        let account =
            AccountPrivKey::from_seed(&MainNetwork, &sample.seed, zip32::AccountId::ZERO).unwrap();
        let (_, address_index) = account
            .to_account_pubkey()
            .derive_external_ivk()
            .unwrap()
            .default_address();
        let input_sk = account.derive_external_secret_key(address_index).unwrap();
        let secp = secp256k1::Secp256k1::signing_only();
        let pubkey = input_sk.public_key(&secp).serialize();

        let account_one_pczt = Updater::new(Pczt::parse(&sample.bytes).unwrap())
            .update_transparent_with(|mut bundle| {
                let account_one_derivation = transparent::pczt::Bip32Derivation::parse(
                    sample.seed_fingerprint,
                    alloc::vec![
                        44 | zcash_vendor::bip32::ChildNumber::HARDENED_FLAG,
                        133 | zcash_vendor::bip32::ChildNumber::HARDENED_FLAG,
                        1 | zcash_vendor::bip32::ChildNumber::HARDENED_FLAG,
                        0,
                        0,
                    ],
                )
                .unwrap();
                bundle.update_input_with(0, |mut input| {
                    input.set_bip32_derivation(pubkey, account_one_derivation);
                    Ok(())
                })
            })
            .unwrap()
            .finish();

        assert_invalid_pczt_message(
            sign_pczt(account_one_pczt, &sample.seed, zip32::AccountId::ZERO),
            "transparent input bip32 derivation path invalid",
        );
    }

    #[cfg(zcash_unstable = "nu7")]
    #[test]
    #[cfg(feature = "legacy_pczt_fixtures")]
    fn test_sign_pczt_orchard_spend_rejects_unsupported_zip32_path() {
        let sample = crate::pczt::test_support::sample_orchard_spend_pczt();
        for path in unsupported_orchard_spend_paths_for_signing() {
            let pczt = crate::pczt::test_support::orchard_pczt_with_spend_derivation(
                &sample.bytes,
                sample.seed_fingerprint,
                path,
            );

            assert_invalid_pczt_message(
                sign_pczt(
                    Pczt::parse(&pczt).unwrap(),
                    &sample.seed,
                    zip32::AccountId::ZERO,
                ),
                "unsupported Orchard spend ZIP 32 derivation path",
            );
        }
    }

    #[cfg(zcash_unstable = "nu7")]
    #[test]
    fn test_sign_pczt_ironwood_spend_rejects_unsupported_zip32_path() {
        let sample = crate::pczt::test_support::sample_ironwood_pczt();
        for path in unsupported_orchard_spend_paths_for_signing() {
            let pczt = crate::pczt::test_support::ironwood_pczt_with_spend_derivation(
                &sample.bytes,
                sample.seed_fingerprint,
                path,
            );

            assert_invalid_pczt_message(
                sign_pczt(
                    Pczt::parse(&pczt).unwrap(),
                    &sample.seed,
                    zip32::AccountId::ZERO,
                ),
                "unsupported Ironwood spend ZIP 32 derivation path",
            );
        }
    }

    #[cfg(zcash_unstable = "nu7")]
    #[test]
    fn test_sign_pczt_ironwood_spend_ignores_dummy_zip32_metadata() {
        let sample = crate::pczt::test_support::sample_ironwood_pczt();
        let pczt = crate::pczt::test_support::ironwood_pczt_with_dummy_spend_derivation(
            &sample.bytes,
            sample.seed_fingerprint,
            crate::pczt::test_support::orchard_spend_path_for_account(1),
        );

        let signed = sign_pczt(
            Pczt::parse(&pczt).unwrap(),
            &sample.seed,
            zip32::AccountId::ZERO,
        )
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

    #[cfg(zcash_unstable = "nu7")]
    #[test]
    fn test_sign_pczt_orchard_change_output_spend() {
        let sample = crate::pczt::test_support::sample_orchard_change_pczt();
        let pczt = Pczt::parse(&sample.bytes).unwrap();

        let signed = sign_pczt(pczt, &sample.seed, zip32::AccountId::ZERO)
            .expect("Orchard change output spend should sign");
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

    #[cfg(zcash_unstable = "nu7")]
    #[test]
    #[cfg(feature = "legacy_pczt_fixtures")]
    fn test_sign_pczt_orchard_spend_rejects_unselected_account() {
        let sample = crate::pczt::test_support::sample_orchard_spend_pczt();
        let account_one_pczt = crate::pczt::test_support::orchard_pczt_with_spend_derivation(
            &sample.bytes,
            sample.seed_fingerprint,
            crate::pczt::test_support::orchard_spend_path_for_account(1),
        );

        assert_invalid_pczt_message(
            sign_pczt(
                Pczt::parse(&account_one_pczt).unwrap(),
                &sample.seed,
                zip32::AccountId::ZERO,
            ),
            "unsupported Orchard spend ZIP 32 account index",
        );
    }

    #[cfg(zcash_unstable = "nu7")]
    #[test]
    fn test_sign_pczt_ironwood_spend_rejects_unselected_account() {
        let sample = crate::pczt::test_support::sample_ironwood_pczt();
        let account_one_pczt = crate::pczt::test_support::ironwood_pczt_with_spend_derivation(
            &sample.bytes,
            sample.seed_fingerprint,
            crate::pczt::test_support::orchard_spend_path_for_account(1),
        );

        assert_invalid_pczt_message(
            sign_pczt(
                Pczt::parse(&account_one_pczt).unwrap(),
                &sample.seed,
                zip32::AccountId::ZERO,
            ),
            "unsupported Ironwood spend ZIP 32 account index",
        );
    }

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

    fn test_seed() -> Vec<u8> {
        [7u8; 32].to_vec()
    }

    #[test]
    fn firmware_equal_version_stamps_response() {
        let pczt = pczt_with_min_version(&KEYSTONE_FW_VERSION.encode());
        let signed = sign_pczt(pczt, &test_seed(), zip32::AccountId::ZERO)
            .expect("equal-version PCZT should sign");
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

    #[test]
    fn firmware_older_min_version_still_stamps_response() {
        let pczt = pczt_with_min_version(&[1, 0, 0]);
        let signed = sign_pczt(pczt, &test_seed(), zip32::AccountId::ZERO)
            .expect("older-min PCZT should sign");
        let parsed = Pczt::parse(&signed).expect("signed PCZT must parse");

        let stamp = parsed
            .global()
            .proprietary()
            .get(PROP_KEY_FW_VERSION)
            .expect("firmware version stamp must be present");
        assert_eq!(stamp, &KEYSTONE_FW_VERSION.encode().to_vec());
    }

    #[test]
    fn malformed_min_version_round_trips_and_stamps() {
        let pczt = pczt_with_min_version(&[1, 2]);
        let signed = sign_pczt(pczt, &test_seed(), zip32::AccountId::ZERO)
            .expect("malformed min bytes must not block signing");
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

    #[test]
    fn legacy_signing_rejects_unselected_transparent_account() {
        let sample = crate::pczt::legacy_test_support::legacy_transparent_sample();

        sign_pczt(
            Pczt::parse(&sample.bytes).unwrap(),
            &sample.seed,
            zip32::AccountId::ZERO,
        )
        .expect("selected account PCZT should sign");

        let account_one_pczt =
            crate::pczt::legacy_test_support::legacy_transparent_pczt_with_input_derivation(
                &sample.bytes,
                sample.seed_fingerprint,
                sample.input_pubkey,
                crate::pczt::legacy_test_support::legacy_transparent_path_for_account(1),
            );

        let result = sign_pczt(
            Pczt::parse(&account_one_pczt).unwrap(),
            &sample.seed,
            zip32::AccountId::ZERO,
        );

        assert!(matches!(
            result,
            Err(ZcashError::SigningError(msg))
                if msg.contains("transparent input bip32 derivation path invalid")
        ));
    }

    #[cfg(zcash_unstable = "nu7")]
    #[test]
    fn legacy_signing_rejects_v6_pczt() {
        let pczt = Creator::new(
            BranchId::Nu7.into(),
            10,
            MainNetwork.coin_type(),
            [0; 32],
            [0; 32],
        )
        .with_ironwood_anchor([1; 32])
        .build();

        let result = sign_pczt(pczt, &[7u8; 32], zip32::AccountId::ZERO);

        assert!(matches!(
            result,
            Err(ZcashError::SigningError(msg))
                if msg == "V6 or Ironwood PCZTs require cypherpunk signing support"
        ));
    }
}
