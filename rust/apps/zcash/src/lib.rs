#![no_std]
extern crate alloc;

pub mod errors;
pub mod pczt;
pub mod version;

use errors::{Result, ZcashError};

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use pczt::structs::ParsedPczt;
use zcash_vendor::{
    zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey},
    zcash_protocol::consensus::{self},
    zip32,
};

#[cfg(any(test, feature = "multi_coins", feature = "cypherpunk"))]
use zcash_vendor::pczt::Pczt;

#[cfg(feature = "cypherpunk")]
use zcash_vendor::zcash_protocol::consensus::NetworkConstants;

/// Generates a Zcash address from a Unified Full Viewing Key (UFVK).
///
/// # Parameters
/// * `params` - The consensus parameters for the Zcash network (mainnet or testnet)
/// * `ufvk_text` - The string representation of the Unified Full Viewing Key
///
/// # Returns
/// * `Result<String>` - The encoded Zcash address if successful, or an error if the UFVK is invalid
///                      or if there was an issue generating the address
///
/// # Errors
/// * `ZcashError::GenerateAddressError` - If the UFVK cannot be decoded or if the address cannot be generated
pub fn get_address<P: consensus::Parameters>(params: &P, ufvk_text: &str) -> Result<String> {
    let ufvk = UnifiedFullViewingKey::decode(params, ufvk_text)
        .map_err(|e| ZcashError::GenerateAddressError(e.to_string()))?;
    let (address, _) = ufvk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|e| ZcashError::GenerateAddressError(e.to_string()))?;
    Ok(address.encode(params))
}

/// Validates a Partially Created Zcash Transaction (PCZT) against a Unified Full Viewing Key.
///
/// # Parameters
/// * `params` - The consensus parameters for the Zcash network (mainnet or testnet)
/// * `pczt` - The binary representation of the PCZT to validate
/// * `ufvk_text` - The string representation of the Unified Full Viewing Key
/// * `seed_fingerprint` - A 32-byte fingerprint of the seed used to derive keys
/// * `account_index` - The account index for the keys to check against
///
/// # Returns
/// * `Result<()>` - Ok if the PCZT is valid for the given UFVK, or an error otherwise
///
/// # Errors
/// * `ZcashError::InvalidDataError` - If the UFVK cannot be decoded or the account index is invalid
/// * `ZcashError::InvalidPczt` - If the PCZT data is malformed or cannot be parsed
/// * Other errors from the underlying validation process
#[cfg(feature = "cypherpunk")]
pub fn check_pczt_cypherpunk<P: consensus::Parameters>(
    params: &P,
    pczt: &[u8],
    ufvk_text: &str,
    seed_fingerprint: &[u8; 32],
    account_index: u32,
) -> Result<()> {
    let pczt = pczt::parse_pczt(pczt)?;
    let account_index = zip32::AccountId::try_from(account_index)
        .map_err(|_e| ZcashError::InvalidDataError("invalid account index".to_string()))?;
    let ufvk = UnifiedFullViewingKey::decode(params, ufvk_text)
        .map_err(|e| ZcashError::InvalidDataError(e.to_string()))?;
    let xpub = ufvk.transparent().ok_or(ZcashError::InvalidDataError(
        "transparent xpub is not present".to_string(),
    ))?;
    pczt::check::check_pczt_orchard(params, seed_fingerprint, account_index, &ufvk, &pczt)?;
    pczt::check::check_pczt_transparent(
        params,
        seed_fingerprint,
        account_index,
        xpub,
        &pczt,
        false,
    )?;
    Ok(())
}

#[cfg(feature = "multi_coins")]
pub fn check_pczt_multi_coins<P: consensus::Parameters>(
    params: &P,
    pczt: &[u8],
    xpub: &str,
    seed_fingerprint: &[u8; 32],
    account_index: u32,
) -> Result<()> {
    let pczt = pczt::parse_pczt(pczt)?;
    reject_legacy_check_unsupported_pczt(&pczt)?;
    let account_pubkey = transparent_account_pubkey_from_xpub(xpub)?;
    let account_index = zip32::AccountId::try_from(account_index)
        .map_err(|_e| ZcashError::InvalidDataError("invalid account index".to_string()))?;

    pczt::check::check_pczt_transparent(
        params,
        seed_fingerprint,
        account_index,
        &account_pubkey,
        &pczt,
        true,
    )?;
    Ok(())
}

#[cfg(feature = "multi_coins")]
fn transparent_account_pubkey_from_xpub(
    xpub: &str,
) -> Result<zcash_vendor::transparent::keys::AccountPubKey> {
    use core::str::FromStr;
    use zcash_vendor::{bip32, transparent};

    let xpub: bip32::ExtendedPublicKey<bitcoin::secp256k1::PublicKey> =
        bip32::ExtendedPublicKey::from_str(xpub)
            .map_err(|e| ZcashError::InvalidDataError(e.to_string()))?;

    let key = {
        let chain_code = xpub.attrs().chain_code;
        let pubkey = xpub.public_key().serialize();
        let mut bytes = [0u8; 65];
        bytes[..32].copy_from_slice(&chain_code);
        bytes[32..].copy_from_slice(&pubkey);
        bytes
    };

    transparent::keys::AccountPubKey::deserialize(&key)
        .map_err(|e| ZcashError::InvalidDataError(e.to_string()))
}

#[cfg(feature = "multi_coins")]
fn reject_legacy_check_unsupported_pczt(pczt: &Pczt) -> Result<()> {
    #[cfg(zcash_unstable = "nu6.3")]
    {
        // The legacy multi-coins check path only verifies transparent data.
        // Reject V6/Ironwood PCZTs so check, parse, and sign enforce the same boundary.
        if pczt::pczt_requires_cypherpunk_support(pczt) {
            return Err(ZcashError::InvalidPczt(
                "V6 or Ironwood PCZTs require cypherpunk checking support".to_string(),
            ));
        }
    }
    Ok(())
}

/// Parses a Partially Created Zcash Transaction (PCZT) and extracts its details.
///
/// This function takes a binary PCZT and a Unified Full Viewing Key (UFVK), parses the transaction,
/// and returns a structured representation of the transaction's contents.
///
/// # Parameters
/// * `params` - The consensus parameters for the Zcash network (mainnet or testnet)
/// * `pczt` - The binary representation of the PCZT to parse
/// * `ufvk_text` - The string representation of the Unified Full Viewing Key
/// * `seed_fingerprint` - A 32-byte fingerprint of the seed used to derive keys
/// # Returns
/// * `Result<ParsedPczt>` - A structured representation of the PCZT if successful
///
/// # Errors
/// * `ZcashError::InvalidDataError` - If the UFVK cannot be decoded
/// * `ZcashError::InvalidPczt` - If the PCZT data is malformed or cannot be parsed
/// * Other errors from the underlying parsing process
#[cfg(feature = "cypherpunk")]
pub fn parse_pczt_cypherpunk<P: consensus::Parameters>(
    params: &P,
    pczt: &[u8],
    ufvk_text: &str,
    seed_fingerprint: &[u8; 32],
) -> Result<ParsedPczt> {
    let ufvk = UnifiedFullViewingKey::decode(params, ufvk_text)
        .map_err(|e| ZcashError::InvalidDataError(e.to_string()))?;
    let pczt = pczt::parse_pczt(pczt)?;
    pczt::parse::parse_pczt_cypherpunk(params, seed_fingerprint, &ufvk, &pczt)
}

#[cfg(test)]
mod additional_tests {
    use super::*;
    use zcash_vendor::zcash_protocol::consensus::MAIN_NETWORK;

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_get_address() {
        let ufvk_text = "uview10zf3gnxd08cne6g7ryh6lln79duzsayg0qxktvyc3l6uutfk0agmyclm5g82h5z0lqv4c2gzp0eu0qc0nxzurxhj4ympwn3gj5c3dc9g7ca4eh3q09fw9kka7qplzq0wnauekf45w9vs4g22khtq57sc8k6j6s70kz0rtqlyat6zsjkcqfrlm9quje8vzszs8y9mjvduf7j2vx329hk2v956g6svnhqswxfp3n760mw233w7ffgsja2szdhy5954hsfldalf28wvav0tctxwkmkgrk43tq2p7sqchzc6";
        let addr = get_address(&MAIN_NETWORK, ufvk_text).expect("should generate address");
        // We can print this address to see what it is, and then pin it in the test.
        // For now, let's just assert it is valid and not empty.
        assert!(!addr.is_empty());
        assert!(addr.starts_with("u1")); // Mainnet unified address starts with u1
    }

    #[test]
    fn test_get_address_invalid_ufvk() {
        let ufvk_text = "invalid_ufvk";
        let result = get_address(&MAIN_NETWORK, ufvk_text);
        assert!(result.is_err());
    }
}

#[cfg(feature = "multi_coins")]
pub fn parse_pczt_multi_coins<P: consensus::Parameters>(
    params: &P,
    pczt: &[u8],
    seed_fingerprint: &[u8; 32],
) -> Result<ParsedPczt> {
    let pczt = pczt::parse_pczt(pczt)?;

    pczt::parse::parse_pczt_multi_coins(params, seed_fingerprint, &pczt)
}

/// Signs a Partially Created Zcash Transaction (PCZT) using a seed.
///
/// This function takes a binary PCZT and a seed, parses the transaction,
/// and returns a signed PCZT.
///
/// # Parameters
/// * `pczt` - The binary representation of the PCZT to sign
/// * `seed` - The seed to sign the PCZT with
///
/// # Returns
/// * `Result<Vec<u8>>` - The signed PCZT if successful, or an error otherwise
///
/// # Errors
/// * `ZcashError::InvalidPczt` - If the PCZT data is malformed or cannot be parsed
/// * Other errors from the underlying signing process
pub fn sign_pczt(pczt: &[u8], seed: &[u8]) -> Result<Vec<u8>> {
    let pczt = pczt::parse_pczt(pczt)?;
    pczt::sign::sign_pczt(pczt, seed)
}

#[cfg(all(test, feature = "multi_coins", not(feature = "cypherpunk")))]
mod legacy_tests {
    use super::*;
    use zcash_vendor::{
        pczt::roles::creator::Creator,
        zcash_protocol::consensus::{BranchId, MainNetwork, NetworkConstants},
    };

    fn assert_invalid_pczt_message<T: core::fmt::Debug>(result: Result<T>, expected: &str) {
        match result {
            Err(ZcashError::InvalidPczt(message)) if message == expected => {}
            other => panic!("unexpected InvalidPczt result: {other:?}"),
        }
    }

    #[test]
    fn legacy_parse_uses_seed_fingerprint_and_check_validates_transparent_account() {
        let sample = pczt::legacy_test_support::legacy_transparent_sample();

        let parsed = parse_pczt_multi_coins(&MainNetwork, &sample.bytes, &sample.seed_fingerprint)
            .expect("selected account PCZT should parse");
        assert!(parsed
            .get_transparent()
            .unwrap()
            .get_from()
            .first()
            .unwrap()
            .get_is_mine());
        check_pczt_multi_coins(
            &MainNetwork,
            &sample.bytes,
            &sample.xpub,
            &sample.seed_fingerprint,
            0,
        )
        .expect("selected account PCZT should check");

        let account_one_pczt =
            pczt::legacy_test_support::legacy_transparent_pczt_with_input_derivation(
                &sample.bytes,
                sample.seed_fingerprint,
                sample.input_pubkey,
                pczt::legacy_test_support::legacy_transparent_path_for_account(1),
            );

        parse_pczt_multi_coins(&MainNetwork, &account_one_pczt, &sample.seed_fingerprint)
            .expect("parse uses seed fingerprint ownership only");
        assert_invalid_pczt_message(
            check_pczt_multi_coins(
                &MainNetwork,
                &account_one_pczt,
                &sample.xpub,
                &sample.seed_fingerprint,
                0,
            ),
            "transparent input bip32 derivation path invalid",
        );
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn legacy_check_rejects_v6_pczt() {
        let pczt = Creator::new_v6(
            BranchId::Nu6_3.into(),
            10,
            MainNetwork.coin_type(),
            [0; 32],
            [0; 32],
            [1; 32],
        )
        .build();

        let result = check_pczt_multi_coins(
            &MainNetwork,
            &pczt.serialize(),
            "not-an-xpub",
            &[7u8; 32],
            0,
        );

        assert!(matches!(
            result,
            Err(ZcashError::InvalidPczt(msg))
                if msg == "V6 or Ironwood PCZTs require cypherpunk checking support"
        ));
    }
}

#[cfg(feature = "cypherpunk")]
fn map_shielded_verifier_error(
    e: zcash_vendor::pczt::roles::verifier::OrchardError<ZcashError>,
) -> ZcashError {
    use zcash_vendor::pczt::roles::verifier::OrchardError;

    match e {
        OrchardError::Custom(e) => e,
        _ => ZcashError::InvalidPczt(alloc::format!("{e:?}")),
    }
}

#[cfg(feature = "cypherpunk")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignableShieldedPool {
    Orchard,
    #[cfg(zcash_unstable = "nu6.3")]
    Ironwood,
}

#[cfg(feature = "cypherpunk")]
impl SignableShieldedPool {
    fn label(self) -> &'static str {
        match self {
            SignableShieldedPool::Orchard => "Orchard",
            #[cfg(zcash_unstable = "nu6.3")]
            SignableShieldedPool::Ironwood => "Ironwood",
        }
    }
}

#[cfg(feature = "cypherpunk")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SignableShieldedAction {
    pool: SignableShieldedPool,
    index: usize,
}

#[cfg(feature = "cypherpunk")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShieldedActionPolicy {
    Batch,
    Single,
}

#[cfg(feature = "cypherpunk")]
fn collect_signable_shielded_actions<P: consensus::Parameters>(
    params: &P,
    bundle: &zcash_vendor::orchard::pczt::Bundle,
    pool: SignableShieldedPool,
    seed_fingerprint: &[u8; 32],
    account_index: zip32::AccountId,
    policy: ShieldedActionPolicy,
    actions: &mut Vec<SignableShieldedAction>,
) -> core::result::Result<(), zcash_vendor::pczt::roles::verifier::OrchardError<ZcashError>> {
    use zcash_vendor::pczt::roles::verifier::OrchardError;

    for (index, action) in bundle.actions().iter().enumerate() {
        if action.spend().dummy_sk().is_some() {
            continue;
        }

        let value = action.spend().value().ok_or_else(|| {
            OrchardError::Custom(ZcashError::InvalidPczt(alloc::format!(
                "missing {} spend value for batch signing",
                pool.label(),
            )))
        })?;
        if value.inner() == 0 {
            continue;
        }

        let matches_account = pczt::matching_seed_selected_orchard_account(
            seed_fingerprint,
            action.spend().zip32_derivation().as_ref(),
            params.network_type().coin_type(),
            account_index,
            pool.label(),
        )
        .map_err(OrchardError::Custom)?;
        if !matches_account {
            if policy == ShieldedActionPolicy::Batch {
                return Err(OrchardError::Custom(ZcashError::PcztNoMyInputs));
            }
            continue;
        }

        actions.push(SignableShieldedAction { pool, index });
    }

    Ok(())
}

#[cfg(feature = "cypherpunk")]
fn ensure_actions_are_signed(
    bundle: &zcash_vendor::orchard::pczt::Bundle,
    pool: SignableShieldedPool,
    signable_actions: &[SignableShieldedAction],
) -> core::result::Result<(), zcash_vendor::pczt::roles::verifier::OrchardError<ZcashError>> {
    use zcash_vendor::pczt::roles::verifier::OrchardError;

    for action_ref in signable_actions.iter().filter(|action| action.pool == pool) {
        let action = bundle.actions().get(action_ref.index).ok_or_else(|| {
            OrchardError::Custom(ZcashError::SigningError(alloc::format!(
                "signed PCZT is missing an {} action",
                pool.label(),
            )))
        })?;
        if action.spend().spend_auth_sig().is_none() {
            return Err(OrchardError::Custom(ZcashError::SigningError(
                alloc::format!(
                    "signed PCZT is missing an {} spend authorization signature",
                    pool.label(),
                ),
            )));
        }
    }

    Ok(())
}

#[cfg(feature = "cypherpunk")]
fn signable_shielded_actions<P: consensus::Parameters>(
    params: &P,
    pczt: Pczt,
    seed_fingerprint: &[u8; 32],
    account_index: zip32::AccountId,
    policy: ShieldedActionPolicy,
) -> Result<Vec<SignableShieldedAction>> {
    use zcash_vendor::pczt::roles::verifier::Verifier;

    if policy == ShieldedActionPolicy::Batch && !pczt.sapling().spends().is_empty() {
        return Err(ZcashError::InvalidPczt(
            "Zcash batch PCZT must not contain Sapling spends".to_string(),
        ));
    }

    if policy == ShieldedActionPolicy::Batch && !pczt.transparent().inputs().is_empty() {
        return Err(ZcashError::InvalidPczt(
            "Zcash batch PCZT must not contain transparent inputs".to_string(),
        ));
    }

    let mut actions = Vec::new();
    let verifier = Verifier::new(pczt)
        .with_orchard::<ZcashError, _>(|bundle| {
            collect_signable_shielded_actions(
                params,
                bundle,
                SignableShieldedPool::Orchard,
                seed_fingerprint,
                account_index,
                policy,
                &mut actions,
            )
        })
        .map_err(map_shielded_verifier_error)?;

    #[cfg(zcash_unstable = "nu6.3")]
    let verifier = verifier
        .with_ironwood::<ZcashError, _>(|bundle| {
            collect_signable_shielded_actions(
                params,
                bundle,
                SignableShieldedPool::Ironwood,
                seed_fingerprint,
                account_index,
                policy,
                &mut actions,
            )
        })
        .map_err(map_shielded_verifier_error)?;
    drop(verifier);

    Ok(actions)
}

#[cfg(feature = "cypherpunk")]
fn ensure_shielded_actions_are_signed(
    signed_pczt: Pczt,
    signable_actions: &[SignableShieldedAction],
) -> Result<()> {
    use zcash_vendor::pczt::roles::verifier::Verifier;

    let verifier = Verifier::new(signed_pczt)
        .with_orchard::<ZcashError, _>(|bundle| {
            ensure_actions_are_signed(bundle, SignableShieldedPool::Orchard, signable_actions)
        })
        .map_err(map_shielded_verifier_error)?;

    #[cfg(zcash_unstable = "nu6.3")]
    let verifier = verifier
        .with_ironwood::<ZcashError, _>(|bundle| {
            ensure_actions_are_signed(bundle, SignableShieldedPool::Ironwood, signable_actions)
        })
        .map_err(map_shielded_verifier_error)?;
    drop(verifier);

    Ok(())
}

/// Checks whether the PCZT contains at least one non-dummy supported shielded
/// action that can be signed by the account identified by `seed_fingerprint` and
/// `account_index`.
///
/// `sign_pczt` intentionally returns a redacted PCZT even when no key matched.
/// Batch signing needs this explicit preflight so one approval cannot silently
/// produce a result with zero shielded signatures for an entry.
#[cfg(feature = "cypherpunk")]
pub fn ensure_pczt_has_signable_shielded_action<P: consensus::Parameters>(
    params: &P,
    pczt: &[u8],
    seed_fingerprint: &[u8; 32],
    account_index: u32,
) -> Result<()> {
    let pczt = pczt::parse_pczt(pczt)?;
    let account_index = zip32::AccountId::try_from(account_index)
        .map_err(|_e| ZcashError::InvalidDataError("invalid account index".to_string()))?;

    if signable_shielded_actions(
        params,
        pczt,
        seed_fingerprint,
        account_index,
        ShieldedActionPolicy::Batch,
    )?
    .is_empty()
    {
        Err(ZcashError::PcztNoMyInputs)
    } else {
        Ok(())
    }
}

/// Confirms that every signable supported shielded action in `unsigned_pczt`
/// has a spend authorization signature in the same position in `signed_pczt`.
#[cfg(feature = "cypherpunk")]
pub fn ensure_signable_shielded_actions_are_signed<P: consensus::Parameters>(
    params: &P,
    unsigned_pczt: &[u8],
    signed_pczt: &[u8],
    seed_fingerprint: &[u8; 32],
    account_index: u32,
) -> Result<()> {
    let unsigned_pczt = pczt::parse_pczt(unsigned_pczt)?;
    let account_index = zip32::AccountId::try_from(account_index)
        .map_err(|_e| ZcashError::InvalidDataError("invalid account index".to_string()))?;
    let signable_actions = signable_shielded_actions(
        params,
        unsigned_pczt,
        seed_fingerprint,
        account_index,
        ShieldedActionPolicy::Batch,
    )?;
    if signable_actions.is_empty() {
        Err(ZcashError::PcztNoMyInputs)
    } else {
        let signed_pczt = pczt::parse_pczt(signed_pczt)
            .map_err(|_| ZcashError::InvalidPczt("invalid signed pczt data".to_string()))?;
        ensure_shielded_actions_are_signed(signed_pczt, &signable_actions)
    }
}

/// Confirms that supported shielded actions owned by this account were signed
/// without applying the batch-only shielded input policy to ordinary PCZTs.
#[cfg(feature = "cypherpunk")]
pub fn ensure_owned_supported_shielded_actions_are_signed<P: consensus::Parameters>(
    params: &P,
    unsigned_pczt: &[u8],
    signed_pczt: &[u8],
    seed_fingerprint: &[u8; 32],
    account_index: u32,
) -> Result<()> {
    let unsigned_pczt = pczt::parse_pczt(unsigned_pczt)?;
    let account_index = zip32::AccountId::try_from(account_index)
        .map_err(|_e| ZcashError::InvalidDataError("invalid account index".to_string()))?;
    let signable_actions = signable_shielded_actions(
        params,
        unsigned_pczt,
        seed_fingerprint,
        account_index,
        ShieldedActionPolicy::Single,
    )?;
    if signable_actions.is_empty() {
        Ok(())
    } else {
        let signed_pczt = pczt::parse_pczt(signed_pczt)
            .map_err(|_| ZcashError::InvalidPczt("invalid signed pczt data".to_string()))?;
        ensure_shielded_actions_are_signed(signed_pczt, &signable_actions)
    }
}

#[cfg(feature = "cypherpunk")]
#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeMap, string::String, vec::Vec};

    use consensus::MainNetwork;
    use keystore::algorithms::zcash::{calculate_seed_fingerprint, derive_ufvk};
    use serde::{Deserialize, Serialize};
    use zcash_vendor::zcash_protocol::constants;

    use super::*;
    extern crate std;

    #[derive(Serialize, Deserialize)]
    struct PcztMirror {
        global: GlobalMirror,
        transparent: ::pczt::transparent::Bundle,
        sapling: SaplingBundleMirror,
        orchard: ::pczt::orchard::Bundle,
        #[cfg(zcash_unstable = "nu6.3")]
        ironwood: ::pczt::orchard::Bundle,
    }

    #[derive(Serialize, Deserialize)]
    struct GlobalMirror {
        tx_version: u32,
        version_group_id: u32,
        consensus_branch_id: u32,
        fallback_lock_time: Option<u32>,
        expiry_height: u32,
        coin_type: u32,
        tx_modifiable: u8,
        proprietary: BTreeMap<String, Vec<u8>>,
    }

    #[derive(Serialize, Deserialize)]
    struct SaplingBundleMirror {
        spends: Vec<SaplingSpendMirror>,
        outputs: Vec<SaplingOutputMirror>,
        value_sum: i128,
        anchor: [u8; 32],
        bsk: Option<[u8; 32]>,
    }

    #[derive(Serialize, Deserialize)]
    struct SaplingSpendMirror;

    #[serde_with::serde_as]
    #[derive(Serialize, Deserialize)]
    struct SaplingOutputMirror {
        cv: [u8; 32],
        cmu: [u8; 32],
        ephemeral_key: [u8; 32],
        enc_ciphertext: Vec<u8>,
        out_ciphertext: Vec<u8>,
        #[serde_as(as = "Option<[_; 144]>")]
        zkproof: Option<[u8; 144]>,
        #[serde_as(as = "Option<[_; 43]>")]
        recipient: Option<[u8; 43]>,
        value: Option<u64>,
        rseed: Option<[u8; 32]>,
        rcv: Option<[u8; 32]>,
        ock: Option<[u8; 32]>,
        zip32_derivation: Option<Zip32DerivationMirror>,
        user_address: Option<String>,
        proprietary: BTreeMap<String, Vec<u8>>,
    }

    #[derive(Serialize, Deserialize)]
    struct Zip32DerivationMirror {
        seed_fingerprint: [u8; 32],
        derivation_path: Vec<u32>,
    }

    #[cfg(zcash_unstable = "nu6.3")]
    fn v5_pczt_with_ironwood_actions() -> Vec<u8> {
        let sample = pczt::test_support::sample_ironwood_pczt();
        let mut bytes = sample.bytes;
        let mut pczt: PcztMirror = postcard::from_bytes(&bytes[8..]).unwrap();
        assert!(!pczt.ironwood.actions().is_empty());

        pczt.global.tx_version = constants::V5_TX_VERSION;
        pczt.global.version_group_id = constants::V5_VERSION_GROUP_ID;

        bytes.truncate(8);
        postcard::to_extend(&pczt, bytes).unwrap()
    }

    fn assert_invalid_pczt_message<T: core::fmt::Debug>(result: Result<T>, expected: &str) {
        assert_eq!(
            result.unwrap_err(),
            ZcashError::InvalidPczt(expected.to_string())
        );
    }

    #[test]
    fn test_get_address() {
        let address = get_address(&MainNetwork, "uview1s2e0495jzhdarezq4h4xsunfk4jrq7gzg22tjjmkzpd28wgse4ejm6k7yfg8weanaghmwsvc69clwxz9f9z2hwaz4gegmna0plqrf05zkeue0nevnxzm557rwdkjzl4pl4hp4q9ywyszyjca8jl54730aymaprt8t0kxj8ays4fs682kf7prj9p24dnlcgqtnd2vnskkm7u8cwz8n0ce7yrwx967cyp6dhkc2wqprt84q0jmwzwnufyxe3j0758a9zgk9ssrrnywzkwfhu6ap6cgx3jkxs3un53n75s3");
        assert_eq!(address.unwrap(), "u1tqdskj32l9udfp0rysmca6gpz73fdqc2rmeenyhh0nfrq4vgak284ehkxefw5cf9495rdur0tparuntevp6nnetzjkyzv08m524e4swwk94asas7hm2ad5w5c64zz00hmr7nux0yhaz");
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_batch_preflight_accepts_orchard_spend() {
        let sample = pczt::test_support::sample_orchard_change_pczt();

        ensure_pczt_has_signable_shielded_action(
            &pczt::test_support::Nu6_3Network,
            &sample.bytes,
            &sample.seed_fingerprint,
            0,
        )
        .unwrap();
        assert_eq!(
            ensure_pczt_has_signable_shielded_action(
                &pczt::test_support::Nu6_3Network,
                &sample.bytes,
                &sample.seed_fingerprint,
                1,
            )
            .unwrap_err(),
            ZcashError::PcztNoMyInputs
        );
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_batch_postflight_confirms_orchard_signature() {
        let sample = pczt::test_support::sample_orchard_change_pczt();
        let signed = sign_pczt(&sample.bytes, &sample.seed, 0).expect("Orchard PCZT should sign");

        ensure_signable_shielded_actions_are_signed(
            &pczt::test_support::Nu6_3Network,
            &sample.bytes,
            &signed,
            &sample.seed_fingerprint,
            0,
        )
        .unwrap();
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_single_postflight_confirms_orchard_signature_when_present() {
        let sample = pczt::test_support::sample_orchard_change_pczt();

        assert!(matches!(
            ensure_owned_supported_shielded_actions_are_signed(
                &pczt::test_support::Nu6_3Network,
                &sample.bytes,
                &sample.bytes,
                &sample.seed_fingerprint,
                0,
            ),
            Err(ZcashError::SigningError(message))
                if message == "signed PCZT is missing an Orchard spend authorization signature"
        ));

        let signed = sign_pczt(&sample.bytes, &sample.seed, 0).expect("Orchard PCZT should sign");
        ensure_owned_supported_shielded_actions_are_signed(
            &pczt::test_support::Nu6_3Network,
            &sample.bytes,
            &signed,
            &sample.seed_fingerprint,
            0,
        )
        .unwrap();
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_pczt_ironwood_to_ironwood() {
        let sample = pczt::test_support::sample_ironwood_pczt();
        let seed_fingerprint = sample.seed_fingerprint;
        let parsed_pczt = parse_pczt_cypherpunk(
            &pczt::test_support::Nu6_3Network,
            &sample.bytes,
            &sample.ufvk_text,
            &seed_fingerprint,
        )
        .unwrap();

        assert!(parsed_pczt.get_ironwood().is_some());
        assert!(parsed_pczt.get_orchard().is_none());
        assert_eq!(parsed_pczt.get_fee_value(), "0.0001 ZEC");

        check_pczt_cypherpunk(
            &pczt::test_support::Nu6_3Network,
            &sample.bytes,
            &sample.ufvk_text,
            &seed_fingerprint,
            0,
        )
        .unwrap();

        let signed = sign_pczt(&sample.bytes, &sample.seed).expect("Ironwood PCZT should sign");
        let signed_pczt = Pczt::parse(&signed).expect("signed PCZT must parse");
        assert!(
            signed_pczt
                .ironwood()
                .actions()
                .iter()
                .any(|action| action.spend().spend_auth_sig().is_some()),
            "Ironwood spend authorization signature must be present",
        );
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_parse_and_check_ignore_unsupported_ironwood_spend_zip32_path() {
        let sample = pczt::test_support::sample_ironwood_pczt();
        let parsed_pczt = parse_pczt_cypherpunk(
            &pczt::test_support::Nu6_3Network,
            &sample.bytes,
            &sample.ufvk_text,
            &sample.seed_fingerprint,
        )
        .unwrap();
        assert!(parsed_pczt
            .get_ironwood()
            .unwrap()
            .get_from()
            .first()
            .unwrap()
            .get_is_mine());

        for path in pczt::test_support::unsupported_orchard_spend_paths() {
            let pczt = pczt::test_support::ironwood_pczt_with_spend_derivation(
                &sample.bytes,
                sample.seed_fingerprint,
                path,
            );

            parse_pczt_cypherpunk(
                &pczt::test_support::Nu6_3Network,
                &pczt,
                &sample.ufvk_text,
                &sample.seed_fingerprint,
            )
            .expect("parse uses seed fingerprint ownership only");
            check_pczt_cypherpunk(
                &pczt::test_support::Nu6_3Network,
                &pczt,
                &sample.ufvk_text,
                &sample.seed_fingerprint,
                0,
            )
            .expect("check ignores non-selected shielded spend paths");
        }
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_parse_and_check_ignore_dummy_ironwood_spend_zip32_metadata() {
        let sample = pczt::test_support::sample_ironwood_pczt();
        let mut paths = pczt::test_support::unsupported_orchard_spend_paths();
        paths.push(pczt::test_support::orchard_spend_path_for_account(1));

        for path in paths {
            let pczt = pczt::test_support::ironwood_pczt_with_dummy_spend_derivation(
                &sample.bytes,
                sample.seed_fingerprint,
                path,
            );

            let parsed_pczt = parse_pczt_cypherpunk(
                &pczt::test_support::Nu6_3Network,
                &pczt,
                &sample.ufvk_text,
                &sample.seed_fingerprint,
            )
            .unwrap();
            assert!(parsed_pczt
                .get_ironwood()
                .unwrap()
                .get_from()
                .first()
                .unwrap()
                .get_is_mine());
            check_pczt_cypherpunk(
                &pczt::test_support::Nu6_3Network,
                &pczt,
                &sample.ufvk_text,
                &sample.seed_fingerprint,
                0,
            )
            .unwrap();
        }
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_batch_preflight_accepts_ironwood_spend() {
        let sample = pczt::test_support::sample_ironwood_pczt();

        ensure_pczt_has_signable_shielded_action(
            &pczt::test_support::Nu6_3Network,
            &sample.bytes,
            &sample.seed_fingerprint,
            0,
        )
        .unwrap();
        assert_eq!(
            ensure_pczt_has_signable_shielded_action(
                &pczt::test_support::Nu6_3Network,
                &sample.bytes,
                &sample.seed_fingerprint,
                1,
            )
            .unwrap_err(),
            ZcashError::PcztNoMyInputs
        );
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_batch_postflight_confirms_ironwood_signature() {
        let sample = pczt::test_support::sample_ironwood_pczt();
        let signed = sign_pczt(&sample.bytes, &sample.seed, 0).expect("Ironwood PCZT should sign");

        ensure_signable_shielded_actions_are_signed(
            &pczt::test_support::Nu6_3Network,
            &sample.bytes,
            &signed,
            &sample.seed_fingerprint,
            0,
        )
        .unwrap();
    }

    #[cfg(zcash_unstable = "nu6.3")]
    #[test]
    fn test_parse_check_and_sign_reject_v5_pczt_with_ironwood_actions() {
        let sample = pczt::test_support::sample_ironwood_pczt();
        let malformed_pczt = v5_pczt_with_ironwood_actions();

        assert_invalid_pczt_message(
            parse_pczt_cypherpunk(
                &pczt::test_support::Nu6_3Network,
                &malformed_pczt,
                &sample.ufvk_text,
                &sample.seed_fingerprint,
            ),
            "Ironwood actions require a v6 PCZT",
        );
        assert_invalid_pczt_message(
            check_pczt_cypherpunk(
                &pczt::test_support::Nu6_3Network,
                &malformed_pczt,
                &sample.ufvk_text,
                &sample.seed_fingerprint,
                0,
            ),
            "Ironwood actions require a v6 PCZT",
        );
        assert_invalid_pczt_message(
            sign_pczt(&malformed_pczt, &sample.seed),
            "Ironwood actions require a v6 PCZT",
        );
    }

    #[test]
    fn test_get_address_invalid_ufvk() {
        let invalid_ufvk = "invalid_ufvk_string";
        let result = get_address(&MainNetwork, invalid_ufvk);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ZcashError::GenerateAddressError(_)
        ));
    }

    #[test]
    fn test_check_pczt_invalid_data() {
        let invalid_pczt = b"invalid_pczt_data";
        let seed = hex::decode("d561f5aba9db8b100a9a84197322e522f952171a388ad74eaab1ab9db815be3335c3099a0a2bb0fee57e630db5ed7251412b6bd4b905cf518627411fee3f32dd").unwrap();
        let ufvk = derive_ufvk(&MainNetwork, &seed, "m/32'/133'/0'").unwrap();
        let seed_fingerprint = calculate_seed_fingerprint(&seed).unwrap();

        let result = check_pczt_cypherpunk(
            &MainNetwork,
            invalid_pczt,
            &ufvk.to_string(),
            &seed_fingerprint,
            0,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ZcashError::InvalidPczt(_)));
    }

    #[test]
    fn test_parse_pczt_invalid_data() {
        let invalid_pczt = b"invalid_pczt_data";
        let seed = hex::decode("d561f5aba9db8b100a9a84197322e522f952171a388ad74eaab1ab9db815be3335c3099a0a2bb0fee57e630db5ed7251412b6bd4b905cf518627411fee3f32dd").unwrap();
        let ufvk = derive_ufvk(&MainNetwork, &seed, "m/32'/133'/0'").unwrap();
        let seed_fingerprint = calculate_seed_fingerprint(&seed).unwrap();

        let result = parse_pczt_cypherpunk(
            &MainNetwork,
            invalid_pczt,
            &ufvk.to_string(),
            &seed_fingerprint,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ZcashError::InvalidPczt(_)));
    }

    #[test]
    fn test_sign_pczt_invalid_data() {
        let invalid_pczt = b"invalid_pczt_data";
        let seed = hex::decode("d561f5aba9db8b100a9a84197322e522f952171a388ad74eaab1ab9db815be3335c3099a0a2bb0fee57e630db5ed7251412b6bd4b905cf518627411fee3f32dd").unwrap();

        let result = sign_pczt(invalid_pczt, &seed);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ZcashError::InvalidPczt(_)));
    }
}
