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
use zcash_vendor::{orchard, pczt::roles::signer::Signer as RoleSigner, zip32};

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
enum SigningKeyCollectionError {
    Zcash(ZcashError),
    TransparentParse(transparent::pczt::ParseError),
    #[cfg(feature = "cypherpunk")]
    OrchardParse(orchard::pczt::ParseError),
}

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
        }
    }
}

impl From<ZcashError> for SigningKeyCollectionError {
    fn from(e: ZcashError) -> Self {
        SigningKeyCollectionError::Zcash(e)
    }
}

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

#[cfg(all(feature = "multi_coins", not(feature = "cypherpunk")))]
struct SeedSigner<'a> {
    seed: &'a [u8],
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
    reject_legacy_unsupported_pczt(&pczt)?;

    let signer = low_level_signer::Signer::new(pczt);

    #[cfg(feature = "multi_coins")]
    let signer = pczt_ext::sign_transparent(signer, &SeedSigner { seed })
        .map_err(|e| ZcashError::SigningError(e.to_string()))?;

    Ok(stamp_and_redact(signer.finish()).serialize())
}

#[cfg(not(feature = "cypherpunk"))]
fn reject_legacy_unsupported_pczt(pczt: &Pczt) -> Result<(), ZcashError> {
    #[cfg(zcash_unstable = "nu7")]
    {
        // The legacy helper below carries the pre-NU7 transparent sighash implementation.
        // It must not be used for V6/Ironwood PCZTs.
        if *pczt.global().tx_version() >= 6 || !pczt.ironwood().actions().is_empty() {
            return Err(ZcashError::SigningError(
                "V6 or Ironwood PCZTs require cypherpunk signing support".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "cypherpunk")]
pub fn sign_pczt(pczt: Pczt, seed: &[u8]) -> crate::Result<Vec<u8>> {
    let transparent_keys = collect_transparent_signing_keys(&pczt, seed)?;
    let orchard_keys = collect_orchard_signing_keys(&pczt, seed, ShieldedPool::Orchard)?;
    #[cfg(zcash_unstable = "nu7")]
    let ironwood_keys = collect_orchard_signing_keys(&pczt, seed, ShieldedPool::Ironwood)?;

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

fn transparent_key_path_for_input(
    seed: &[u8],
    input: &transparent::pczt::Input,
) -> Result<Option<String>, ZcashError> {
    let fingerprint =
        calculate_seed_fingerprint(seed).map_err(|e| ZcashError::SigningError(e.to_string()))?;

    input
        .bip32_derivation()
        .iter()
        .find_map(|(pubkey, path)| {
            let path_fingerprint = *path.seed_fingerprint();
            if fingerprint != path_fingerprint {
                return None;
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
                Ok(my_pubkey) if my_pubkey.serialize().to_vec().eq(pubkey) => Some(Ok(path)),
                Err(e) => Some(Err(e)),
                _ => None,
            }
        })
        .transpose()
        .map_err(|e| ZcashError::SigningError(e.to_string()))
}

#[cfg(feature = "cypherpunk")]
fn collect_transparent_signing_keys(
    pczt: &Pczt,
    seed: &[u8],
) -> Result<Vec<(usize, secp256k1::SecretKey)>, ZcashError> {
    let mut keys = Vec::new();
    low_level_signer::Signer::new(pczt.clone())
        .sign_transparent_with(|_pczt, bundle, _tx_modifiable| {
            for (index, input) in bundle.inputs_mut().iter().enumerate() {
                if let Some(path) = transparent_key_path_for_input(seed, input)? {
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
    pool: ShieldedPool,
) -> Result<Vec<(usize, orchard::keys::SpendAuthorizingKey)>, ZcashError> {
    let mut keys = Vec::new();

    match pool {
        ShieldedPool::Orchard => {
            low_level_signer::Signer::new(pczt.clone())
                .sign_orchard_with(|_pczt, bundle, _tx_modifiable| {
                    collect_orchard_bundle_signing_keys(&mut keys, seed, pool, bundle)
                })
                .map_err(SigningKeyCollectionError::into_zcash)?;
        }
        #[cfg(zcash_unstable = "nu7")]
        ShieldedPool::Ironwood => {
            low_level_signer::Signer::new(pczt.clone())
                .sign_ironwood_with(|_pczt, bundle, _tx_modifiable| {
                    collect_orchard_bundle_signing_keys(&mut keys, seed, pool, bundle)
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
    pool: ShieldedPool,
    bundle: &mut orchard::pczt::Bundle,
) -> Result<(), SigningKeyCollectionError> {
    for (index, action) in bundle.actions().iter().enumerate() {
        if action.spend().dummy_sk().is_some() {
            continue;
        }
        match action.spend().value().map(|v| v.inner()) {
            Some(0) | None => continue,
            Some(_) => {}
        }
        if let Some(ask) = spend_authorizing_key_for_action(seed, action, pool.label())? {
            keys.push((index, ask));
        }
    }
    Ok(())
}

#[cfg(feature = "cypherpunk")]
fn spend_authorizing_key_for_action(
    seed: &[u8],
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

    match &derivation.derivation_path()[..] {
        [purpose, coin_type, account_index]
            if purpose == &zip32::ChildIndex::hardened(ZIP32_PURPOSE) =>
        {
            let coin_type = coin_type.index().checked_sub(HARDENED_FLAG).ok_or_else(|| {
                ZcashError::SigningError(format!(
                    "{pool_label} ZIP 32 coin type is not hardened"
                ))
            })?;
            if coin_type != ZCASH_MAINNET_COIN_TYPE && coin_type != ZCASH_TESTNET_COIN_TYPE {
                return Err(ZcashError::SigningError(format!(
                    "{pool_label} ZIP 32 coin type is unsupported"
                )));
            }
            let account_index = account_index.index().checked_sub(HARDENED_FLAG).ok_or_else(|| {
                ZcashError::SigningError(format!(
                    "{pool_label} ZIP 32 account index is not hardened"
                ))
            })?;
            let account_id = zip32::AccountId::try_from(account_index).map_err(|_| {
                ZcashError::SigningError(format!("{pool_label} ZIP 32 account index is invalid"))
            })?;
            let osk =
                orchard::keys::SpendingKey::from_zip32_seed(seed, coin_type, account_id).map_err(
                    |e| {
                        ZcashError::SigningError(format!(
                            "failed to derive {pool_label} spending key: {e:?}"
                        ))
                    },
                )?;
            Ok(Some(orchard::keys::SpendAuthorizingKey::from(&osk)))
        }
        _ => Err(ZcashError::SigningError(format!(
            "{pool_label} spend ZIP 32 derivation path invalid"
        ))),
    }
}

#[cfg(all(test, feature = "cypherpunk"))]
mod tests {
    use super::*;

    #[test]
    fn test_sign_pczt_invalid_seed_fingerprint() {
        let sample = crate::pczt::test_support::sample_pczt_to_transparent();
        let pczt = Pczt::parse(&sample.bytes).unwrap();
        let mismatched_seed = [9u8; 32];

        let result = sign_pczt(pczt, &mismatched_seed);
        assert!(result.is_ok());

        let signed_pczt_bytes = result.unwrap();
        let parsed = Pczt::parse(&signed_pczt_bytes).expect("signed PCZT must parse");

        assert!(signed_pczt_bytes.len() < sample.bytes.len());

        let stamp = parsed
            .global()
            .proprietary()
            .get(PROP_KEY_FW_VERSION)
            .expect("firmware version stamp must be present");
        assert_eq!(stamp, &KEYSTONE_FW_VERSION.encode().to_vec());
    }

    #[cfg(zcash_unstable = "nu7")]
    #[test]
    fn test_sign_pczt_ironwood_spend() {
        let sample = crate::pczt::test_support::sample_ironwood_pczt();
        let pczt = Pczt::parse(&sample.bytes).unwrap();

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
        assert!(
            signed_pczt_bytes.len() < sample.bytes.len(),
            "signed response should be redacted",
        );
    }

    fn pczt_with_min_version(min_version: &[u8]) -> Pczt {
        let sample = crate::pczt::test_support::sample_pczt_to_transparent();
        let base = Pczt::parse(&sample.bytes).unwrap();
        let min_version = min_version.to_vec();
        Updater::new(base)
            .update_global_with(|mut g| {
                g.set_proprietary("test:min_fw_version".to_string(), min_version);
            })
            .finish()
    }

    fn test_seed() -> Vec<u8> {
        hex::decode("d561f5aba9db8b100a9a84197322e522f952171a388ad74eaab1ab9db815be3335c3099a0a2bb0fee57e630db5ed7251412b6bd4b905cf518627411fee3f32dd").unwrap()
    }

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

        let result = sign_pczt(pczt, &[7u8; 32]);

        assert!(matches!(
            result,
            Err(ZcashError::SigningError(msg))
                if msg == "V6 or Ironwood PCZTs require cypherpunk signing support"
        ));
    }
}
