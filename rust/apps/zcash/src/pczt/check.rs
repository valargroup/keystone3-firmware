// checking logic for PCZT

use alloc::{string::ToString, vec};

use super::*;

#[cfg(feature = "cypherpunk")]
use orchard::{keys::FullViewingKey, value::ValueSum, Address};

use zcash_vendor::{
    pczt::{self, roles::verifier::Verifier, Pczt},
    ripemd::Ripemd160,
    sha2::{Digest, Sha256},
    transparent::{self, address::TransparentAddress, keys::AccountPubKey},
    zcash_address::{ToAddress, ZcashAddress},
    zcash_protocol::{
        consensus::{self, NetworkConstants},
        value::ZatBalance,
    },
    zip32,
};

fn validate_sapling_bundle_consistency(pczt: &Pczt) -> Result<(), ZcashError> {
    let value_balance = (*pczt.sapling().value_sum())
        .try_into()
        .ok()
        .and_then(|v| ZatBalance::from_i64(v).ok())
        .ok_or(ZcashError::InvalidPczt(
            "sapling value_sum is invalid".to_string(),
        ))?;
    let sapling_value_sum: i64 = value_balance.into();
    let has_sapling_bundle =
        !pczt.sapling().spends().is_empty() || !pczt.sapling().outputs().is_empty();

    if !has_sapling_bundle && sapling_value_sum != 0 {
        return Err(ZcashError::InvalidPczt(
            "sapling value_sum must be zero when Sapling bundle is empty".to_string(),
        ));
    }

    Ok(())
}

#[cfg(feature = "cypherpunk")]
pub fn check_pczt_orchard<P: consensus::Parameters>(
    params: &P,
    seed_fingerprint: &[u8; 32],
    account_index: zip32::AccountId,
    ufvk: &UnifiedFullViewingKey,
    pczt: &Pczt,
) -> Result<(), ZcashError> {
    validate_sapling_bundle_consistency(pczt)?;
    Verifier::new(pczt.clone())
        .with_orchard(|bundle| {
            check_orchard(params, seed_fingerprint, account_index, ufvk, bundle)
                .map_err(pczt::roles::verifier::OrchardError::Custom)
        })
        .map_err(|e| ZcashError::InvalidDataError(alloc::format!("{e:?}")))?;
    Ok(())
}

pub fn check_pczt_transparent<P: consensus::Parameters>(
    params: &P,
    seed_fingerprint: &[u8; 32],
    account_index: zip32::AccountId,
    xpub: &AccountPubKey,
    pczt: &Pczt,
    check_sfp: bool,
) -> Result<(), ZcashError> {
    validate_sapling_bundle_consistency(pczt)?;
    Verifier::new(pczt.clone())
        .with_transparent(|bundle| {
            check_transparent(
                params,
                seed_fingerprint,
                account_index,
                xpub,
                bundle,
                check_sfp,
            )
            .map_err(pczt::roles::verifier::TransparentError::Custom)
        })
        .map_err(|e| match e {
            pczt::roles::verifier::TransparentError::Custom(e) => e,
            _e => ZcashError::InvalidDataError(alloc::format!("{:?}", _e)),
        })?;
    Ok(())
}

fn check_transparent<P: consensus::Parameters>(
    params: &P,
    seed_fingerprint: &[u8; 32],
    account_index: zip32::AccountId,
    xpub: &AccountPubKey,
    bundle: &transparent::pczt::Bundle,
    check_sfp: bool,
) -> Result<(), ZcashError> {
    let mut has_my_input = false;
    bundle.inputs().iter().try_for_each(|input| {
        let _has = check_transparent_input(params, seed_fingerprint, account_index, xpub, input)?;
        if _has {
            has_my_input = true;
        }
        Ok::<_, ZcashError>(())
    })?;
    bundle.outputs().iter().try_for_each(|output| {
        check_transparent_output(params, seed_fingerprint, account_index, xpub, output)?;
        Ok::<_, ZcashError>(())
    })?;
    if check_sfp && !has_my_input {
        return Err(ZcashError::PcztNoMyInputs);
    }
    Ok(())
}

fn check_transparent_input<P: consensus::Parameters>(
    params: &P,
    seed_fingerprint: &[u8; 32],
    account_index: zip32::AccountId,
    xpub: &AccountPubKey,
    input: &transparent::pczt::Input,
) -> Result<bool, ZcashError> {
    let script = input.script_pubkey().clone();
    //p2sh transparent input is not supported yet
    match TransparentAddress::from_script_from_chain(&script) {
        Some(TransparentAddress::PublicKeyHash(hash)) => {
            // 1: find my derivation
            let my_derivation = input
                .bip32_derivation()
                .iter()
                .find(|(_pubkey, derivation)| seed_fingerprint == derivation.seed_fingerprint());
            match my_derivation {
                None => {
                    //not my input, pass
                    Ok(false)
                }
                Some((pubkey, derivation)) => {
                    // 2: derive my pubkey
                    let target = xpub
                        .derive_pubkey_at_bip32_path(
                            params,
                            account_index,
                            derivation.derivation_path(),
                        )
                        .map_err(|_| {
                            ZcashError::InvalidPczt(
                                "transparent input bip32 derivation path invalid".to_string(),
                            )
                        })?;
                    // 3: check my pubkey
                    if &target.serialize() != pubkey {
                        return Err(ZcashError::InvalidPczt(
                            "transparent input script pubkey mismatch".to_string(),
                        ));
                    }
                    // 4: check script pubkey
                    if hash[..] != Ripemd160::digest(Sha256::digest(pubkey))[..] {
                        return Err(ZcashError::InvalidPczt(
                            "transparent input script pubkey mismatch".to_string(),
                        ));
                    }
                    Ok(true)
                }
            }
        }
        _ => Err(ZcashError::InvalidPczt(
            "transparent input script pubkey is not a public key hash".to_string(),
        )),
    }
}

fn check_transparent_output<P: consensus::Parameters>(
    params: &P,
    seed_fingerprint: &[u8; 32],
    account_index: zip32::AccountId,
    xpub: &AccountPubKey,
    output: &transparent::pczt::Output,
) -> Result<(), ZcashError> {
    let script = output.script_pubkey().clone();
    match TransparentAddress::from_script_pubkey(&script) {
        Some(TransparentAddress::PublicKeyHash(hash)) => {
            //check user_address and script_pubkey
            match output.user_address() {
                Some(user_address) => {
                    let ta =
                        ZcashAddress::from_transparent_p2pkh(params.network_type(), hash).encode();
                    if user_address != &ta {
                        return Err(ZcashError::InvalidPczt(
                            "transparent output user_address mismatch".to_string(),
                        ));
                    }
                }
                None => {
                    return Err(ZcashError::InvalidPczt(
                        "transparent output user_address is None".to_string(),
                    ))
                }
            }

            let pubkey = output
                .bip32_derivation()
                .keys()
                .find(|pubkey| hash[..] == Ripemd160::digest(Sha256::digest(pubkey))[..]);
            match pubkey {
                Some(pubkey) => {
                    match output.bip32_derivation().get(pubkey) {
                        Some(bip32_derivation) => {
                            if seed_fingerprint == bip32_derivation.seed_fingerprint() {
                                //verify public key
                                let target = xpub
                                    .derive_pubkey_at_bip32_path(
                                        params,
                                        account_index,
                                        bip32_derivation.derivation_path(),
                                    )
                                    .map_err(|_| {
                                        ZcashError::InvalidPczt(
                                            "transparent input bip32 derivation path invalid"
                                                .to_string(),
                                        )
                                    })?;
                                if &target.serialize() != pubkey {
                                    return Err(ZcashError::InvalidPczt(
                                        "transparent output script pubkey mismatch".to_string(),
                                    ));
                                }
                                Ok(())
                            } else {
                                //not my output, pass
                                Ok(())
                            }
                        }
                        //not my output, pass
                        None => Ok(()),
                    }
                }
                //not my output, pass
                None => Ok(()),
            }
        }
        Some(TransparentAddress::ScriptHash(hash)) => {
            //check user_address
            match output.user_address() {
                Some(user_address) => {
                    let ta =
                        ZcashAddress::from_transparent_p2sh(params.network_type(), hash).encode();
                    if user_address != &ta {
                        return Err(ZcashError::InvalidPczt(
                            "transparent output user_address mismatch".to_string(),
                        ));
                    }
                }
                None => {
                    return Err(ZcashError::InvalidPczt(
                        "transparent output user_address is None".to_string(),
                    ))
                }
            }
            // 1: find my derivation
            let my_derivation = output
                .bip32_derivation()
                .iter()
                .find(|(_pubkey, derivation)| seed_fingerprint == derivation.seed_fingerprint());
            match my_derivation {
                None => {
                    //not my output, pass
                    Ok(())
                }
                Some((pubkey, derivation)) => {
                    // 2: derive my pubkey
                    let target = xpub
                        .derive_pubkey_at_bip32_path(
                            params,
                            account_index,
                            derivation.derivation_path(),
                        )
                        .map_err(|_| {
                            ZcashError::InvalidPczt(
                                "transparent input bip32 derivation path invalid".to_string(),
                            )
                        })?;
                    // 3: check my pubkey
                    if &target.serialize() != pubkey {
                        return Err(ZcashError::InvalidPczt(
                            "transparent input script pubkey mismatch".to_string(),
                        ));
                    }
                    // TODO: find a proper way to check script pubkey
                    Ok(())
                }
            }
        }
        _ => Err(ZcashError::InvalidPczt(
            "transparent output script pubkey is not a public key hash".to_string(),
        )),
    }
}

#[cfg(feature = "cypherpunk")]
// check orchard bundle
fn check_orchard<P: consensus::Parameters>(
    params: &P,
    seed_fingerprint: &[u8; 32],
    account_index: zip32::AccountId,
    ufvk: &UnifiedFullViewingKey,
    bundle: &orchard::pczt::Bundle,
) -> Result<(), ZcashError> {
    bundle.actions().iter().try_for_each(|action| {
        check_action(params, seed_fingerprint, account_index, ufvk, action)?;
        Ok::<_, ZcashError>(())
    })?;

    // At this point, we know that every `value` field in the Orchard bundle is present.
    // Check that `value_sum` is correct so we can use it for fee calculations later.
    let calculated_value_balance = bundle
        .actions()
        .iter()
        .map(|action| {
            action.spend().value().expect("present") - action.output().value().expect("present")
        })
        .sum::<Result<ValueSum, _>>();

    match calculated_value_balance {
        Ok(value_balance) if &value_balance == bundle.value_sum() => Ok(()),
        _ => Err(ZcashError::InvalidPczt(
            "invalid Orchard bundle value balance".into(),
        )),
    }
}

#[cfg(feature = "cypherpunk")]
// check orchard action
fn check_action<P: consensus::Parameters>(
    params: &P,
    seed_fingerprint: &[u8; 32],
    account_index: zip32::AccountId,
    ufvk: &UnifiedFullViewingKey,
    action: &orchard::pczt::Action,
) -> Result<(), ZcashError> {
    // Check `cv_net` first so we know that the `value` fields for both the spend and the
    // output are present and correct.
    action.verify_cv_net().map_err(|e| {
        ZcashError::InvalidPczt(alloc::format!("invalid cv_net in Orchard action: {e:?}"))
    })?;

    let fvk = ufvk.orchard().ok_or(ZcashError::InvalidDataError(
        "orchard fvk is not present".to_string(),
    ))?;
    check_action_spend(params, seed_fingerprint, account_index, fvk, action.spend())?;
    check_action_output(ufvk, action)
}

#[cfg(feature = "cypherpunk")]
// check spend nullifier
fn check_action_spend<P: consensus::Parameters>(
    params: &P,
    seed_fingerprint: &[u8; 32],
    account_index: zip32::AccountId,
    fvk: &FullViewingKey,
    spend: &orchard::pczt::Spend,
) -> Result<(), ZcashError> {
    // We can only verify the `nullifier` and `rk` fields of a spend if we know its FVK.
    let can_verify_nf_rk = match (spend.value(), spend.fvk(), spend.zip32_derivation()) {
        // If the spend is marked as matching the accounts's FVK, verify with it.
        (_, _, Some(zip32_derivation))
            if zip32_derivation.seed_fingerprint() == seed_fingerprint
                && zip32_derivation.derivation_path()
                    == &[
                        zip32::ChildIndex::hardened(32),
                        zip32::ChildIndex::hardened(params.network_type().coin_type()),
                        account_index.into(),
                    ] =>
        {
            Some(Some(fvk))
        }
        // Dummy notes use randomly-generated FVKs, so if one is already present then
        // don't validate using the account's FVK.
        (Some(value), Some(_), _) if value.inner() == 0 => Some(None),
        // Don't verify `nullifier` or `rk` for any other spends.
        _ => None,
    };

    if let Some(expected_fvk) = can_verify_nf_rk {
        spend.verify_nullifier(expected_fvk).map_err(|e| {
            ZcashError::InvalidPczt(alloc::format!("invalid Orchard action nullifier: {e:?}"))
        })?;
        spend.verify_rk(expected_fvk).map_err(|e| {
            ZcashError::InvalidPczt(alloc::format!("invalid Orchard action rk: {e:?}"))
        })?;
    }

    Ok(())
}

#[cfg(feature = "cypherpunk")]
fn is_wallet_orchard_address(fvk: &FullViewingKey, address: &Address) -> bool {
    let external_ivk = fvk.to_ivk(zcash_vendor::zip32::Scope::External);
    let internal_ivk = fvk.to_ivk(zcash_vendor::zip32::Scope::Internal);

    external_ivk.diversifier_index(address).is_some()
        || internal_ivk.diversifier_index(address).is_some()
}

#[cfg(feature = "cypherpunk")]
// check output cmx and internal-ovk output ownership constraints
fn check_action_output(
    ufvk: &UnifiedFullViewingKey,
    action: &orchard::pczt::Action,
) -> Result<(), ZcashError> {
    action
        .output()
        .verify_note_commitment(action.spend())
        .map_err(|e| {
            ZcashError::InvalidPczt(alloc::format!("invalid Orchard action cmx: {e:?}"))
        })?;

    let fvk = ufvk.orchard().ok_or(ZcashError::InvalidDataError(
        "orchard fvk is not present".to_string(),
    ))?;
    let external_ovk = fvk.to_ovk(zcash_vendor::zip32::Scope::External).clone();
    let internal_ovk = fvk.to_ovk(zcash_vendor::zip32::Scope::Internal).clone();
    let transparent_internal_ovk = ufvk
        .transparent()
        .map(|k| orchard::keys::OutgoingViewingKey::from(k.internal_ovk().as_bytes()));

    let mut keys = vec![(Some(external_ovk), false), (Some(internal_ovk), true)];
    if let Some(ovk) = transparent_internal_ovk {
        keys.push((Some(ovk), true));
    }

    for (vk, is_internal_ovk) in keys {
        if let Some((_, address, _)) =
            super::parse::decode_output_enc_ciphertext(action, vk.as_ref())?
        {
            if is_internal_ovk && !is_wallet_orchard_address(fvk, &address) {
                return Err(ZcashError::InvalidPczt(
                    "Orchard output was recoverable with an internal OVK but does not belong to this wallet".into(),
                ));
            }
            break;
        }
    }

    Ok(())
}

#[cfg(feature = "cypherpunk")]
#[cfg(test)]
mod tests {
    use super::*;
    use zcash_vendor::{pczt::Pczt, zcash_protocol::consensus::MAIN_NETWORK};

    #[test]
    fn test_check_pczt_to_transparent_output() {
        let sample = crate::pczt::test_support::sample_pczt_to_transparent();
        let pczt = Pczt::parse(&sample.bytes).unwrap();
        let unified_fvk = UnifiedFullViewingKey::decode(&MAIN_NETWORK, &sample.ufvk_text).unwrap();

        let result = check_pczt_orchard(
            &MAIN_NETWORK,
            &sample.seed_fingerprint,
            zip32::AccountId::ZERO,
            &unified_fvk,
            &pczt,
        );

        assert!(result.is_ok());
    }
    //TODO: add test for happy path
}
