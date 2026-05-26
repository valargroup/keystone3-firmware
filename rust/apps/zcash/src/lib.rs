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
    pczt::Pczt,
    zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey},
    zcash_protocol::consensus::{self},
    zip32,
};

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
    let pczt =
        Pczt::parse(pczt).map_err(|_e| ZcashError::InvalidPczt("invalid pczt data".to_string()))?;
    let account_index = zip32::AccountId::try_from(account_index)
        .map_err(|_e| ZcashError::InvalidDataError("invalid account index".to_string()))?;
    let ufvk = UnifiedFullViewingKey::decode(params, ufvk_text)
        .map_err(|e| ZcashError::InvalidDataError(e.to_string()))?;
    let xpub = ufvk.transparent().ok_or(ZcashError::InvalidDataError(
        "transparent xpub is not present".to_string(),
    ))?;
    pczt::check::check_pczt_orchard(params, seed_fingerprint, account_index, &ufvk, &pczt)?;
    pczt::check::check_pczt_transparent(params, seed_fingerprint, account_index, xpub, &pczt, false)
}

#[cfg(feature = "multi_coins")]
pub fn check_pczt_multi_coins<P: consensus::Parameters>(
    params: &P,
    pczt: &[u8],
    xpub: &str,
    seed_fingerprint: &[u8; 32],
    account_index: u32,
) -> Result<()> {
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

    let account_pubkey = transparent::keys::AccountPubKey::deserialize(&key)
        .map_err(|e| ZcashError::InvalidDataError(e.to_string()))?;

    let pczt =
        Pczt::parse(pczt).map_err(|_e| ZcashError::InvalidPczt("invalid pczt data".to_string()))?;
    let account_index = zip32::AccountId::try_from(account_index)
        .map_err(|_e| ZcashError::InvalidDataError("invalid account index".to_string()))?;

    pczt::check::check_pczt_transparent(
        params,
        seed_fingerprint,
        account_index,
        &account_pubkey,
        &pczt,
        true,
    )
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
///
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
    let pczt =
        Pczt::parse(pczt).map_err(|_e| ZcashError::InvalidPczt("invalid pczt data".to_string()))?;
    pczt::parse::parse_pczt_cypherpunk(params, seed_fingerprint, &ufvk, &pczt)
}

#[cfg(test)]
mod additional_tests {
    use super::*;
    use zcash_vendor::zcash_protocol::consensus::MAIN_NETWORK;

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
    let pczt =
        Pczt::parse(pczt).map_err(|_e| ZcashError::InvalidPczt("invalid pczt data".to_string()))?;

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
    let pczt =
        Pczt::parse(pczt).map_err(|_e| ZcashError::InvalidPczt("invalid pczt data".to_string()))?;
    pczt::sign::sign_pczt(pczt, seed)
}

#[cfg(feature = "cypherpunk")]
#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ::pczt::roles::creator::Creator;
    use consensus::MainNetwork;
    use keystore::algorithms::zcash::{calculate_seed_fingerprint, derive_ufvk};
    use rand_core::OsRng;
    use serde::{Deserialize, Serialize};
    use zcash_primitives::transaction::{
        builder::{BuildConfig, Builder, PcztResult},
        fees::zip317,
    };
    use zcash_vendor::{
        orchard,
        transparent::{bundle as transparent, keys::IncomingViewingKey},
        zcash_protocol::{
            consensus::{BranchId, NetworkConstants},
            memo::MemoBytes,
            value::Zatoshis,
        },
        zip32,
    };

    use super::*;
    extern crate std;

    const EMPTY_SAPLING_BUNDLE_ERROR: &str =
        "sapling value_sum must be zero when Sapling bundle is empty";

    #[derive(Serialize, Deserialize)]
    struct PcztMirror {
        global: ::pczt::common::Global,
        transparent: ::pczt::transparent::Bundle,
        sapling: SaplingBundleMirror,
        orchard: ::pczt::orchard::Bundle,
    }

    #[derive(Serialize, Deserialize)]
    struct SaplingBundleMirror {
        spends: Vec<::pczt::sapling::Spend>,
        outputs: Vec<::pczt::sapling::Output>,
        value_sum: i128,
        anchor: [u8; 32],
        bsk: Option<[u8; 32]>,
    }

    fn malformed_pczt_with_empty_sapling_bundle_and_nonzero_value_sum() -> Vec<u8> {
        let mut bytes = Creator::new(
            BranchId::Nu6.into(),
            10,
            MainNetwork.coin_type(),
            [0; 32],
            [0; 32],
        )
        .build()
        .serialize();
        let mut pczt: PcztMirror = postcard::from_bytes(&bytes[8..]).unwrap();
        assert!(pczt.sapling.spends.is_empty());
        assert!(pczt.sapling.outputs.is_empty());

        pczt.sapling.value_sum = 1;

        bytes.truncate(8);
        postcard::to_extend(&pczt, bytes).unwrap()
    }

    fn assert_empty_sapling_bundle_error<T: core::fmt::Debug>(result: Result<T>) {
        assert_eq!(
            result.unwrap_err(),
            ZcashError::InvalidPczt(EMPTY_SAPLING_BUNDLE_ERROR.to_string())
        );
    }

    #[test]
    fn test_get_address() {
        let address = get_address(&MainNetwork, "uview1s2e0495jzhdarezq4h4xsunfk4jrq7gzg22tjjmkzpd28wgse4ejm6k7yfg8weanaghmwsvc69clwxz9f9z2hwaz4gegmna0plqrf05zkeue0nevnxzm557rwdkjzl4pl4hp4q9ywyszyjca8jl54730aymaprt8t0kxj8ays4fs682kf7prj9p24dnlcgqtnd2vnskkm7u8cwz8n0ce7yrwx967cyp6dhkc2wqprt84q0jmwzwnufyxe3j0758a9zgk9ssrrnywzkwfhu6ap6cgx3jkxs3un53n75s3");
        assert_eq!(address.unwrap(), "u1tqdskj32l9udfp0rysmca6gpz73fdqc2rmeenyhh0nfrq4vgak284ehkxefw5cf9495rdur0tparuntevp6nnetzjkyzv08m524e4swwk94asas7hm2ad5w5c64zz00hmr7nux0yhaz");
    }

    #[test]
    fn test_pczt_orchard_to_transparent() {
        let sample = pczt::test_support::sample_pczt_to_transparent();
        let seed_fingerprint = sample.seed_fingerprint;
        let parsed_pczt = parse_pczt_cypherpunk(
            &MainNetwork,
            &sample.bytes,
            &sample.ufvk_text,
            &seed_fingerprint,
        )
        .unwrap();

        assert!(parsed_pczt.get_transparent().is_some());
        assert!(parsed_pczt.get_orchard().is_some());
        let transparent = parsed_pczt.get_transparent().unwrap();
        let orchard = parsed_pczt.get_orchard().unwrap();
        assert_eq!(transparent.get_to().len(), 1);
        assert_eq!(
            transparent.get_to().first().unwrap().get_address(),
            sample.transparent_recipient
        );
        assert_eq!(
            transparent.get_to().first().unwrap().get_value(),
            "0.001 ZEC"
        );
        assert!(!transparent.get_to().first().unwrap().get_is_change());
        assert_eq!(
            orchard.get_to().first().unwrap().get_address(),
            "<internal-address>"
        );
        assert_eq!(orchard.get_to().first().unwrap().get_value(), "0.00885 ZEC");
        assert!(orchard.get_to().first().unwrap().get_is_change());
        assert_eq!(parsed_pczt.get_fee_value(), "0.00015 ZEC");
    }

    #[test]
    fn test_parse_pczt_rejects_orchard_internal_ovk_change_spoofing() {
        let params = MainNetwork;
        let rng = OsRng;

        let victim_seed = [7u8; 32];
        let ufvk_text = derive_ufvk(&params, &victim_seed, "m/32'/133'/0'").unwrap();
        let ufvk = UnifiedFullViewingKey::decode(&params, &ufvk_text).unwrap();
        let victim_fvk = ufvk.orchard().unwrap().clone();
        let victim_account = zcash_vendor::transparent::keys::AccountPrivKey::from_seed(
            &params,
            &victim_seed,
            zip32::AccountId::ZERO,
        )
        .unwrap();
        let (victim_addr, address_index) = victim_account
            .to_account_pubkey()
            .derive_external_ivk()
            .unwrap()
            .default_address();
        let victim_sk = victim_account
            .derive_external_secret_key(address_index)
            .unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::signing_only();
        let victim_pubkey = victim_sk.public_key(&secp);

        let attacker_orchard_sk = orchard::keys::SpendingKey::from_bytes([2; 32]).unwrap();
        let attacker_fvk = orchard::keys::FullViewingKey::from(&attacker_orchard_sk);
        let attacker_recipient = attacker_fvk.address_at(0u32, orchard::keys::Scope::External);
        let victim_change = victim_fvk.address_at(0u32, orchard::keys::Scope::Internal);

        let utxo = transparent::OutPoint::new([1u8; 32], 1);
        let coin = transparent::TxOut::new(
            Zatoshis::const_from_u64(1_000_000),
            victim_addr.script().into(),
        );

        let mut builder = Builder::new(
            &params,
            10_000_000.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
            },
        );
        builder
            .add_transparent_p2pkh_input(victim_pubkey, utxo, coin)
            .unwrap();
        builder
            .add_orchard_output::<zip317::FeeRule>(
                Some(victim_fvk.to_ovk(orchard::keys::Scope::Internal)),
                attacker_recipient,
                Zatoshis::const_from_u64(100_000),
                MemoBytes::empty(),
            )
            .unwrap();
        builder
            .add_orchard_output::<zip317::FeeRule>(
                Some(victim_fvk.to_ovk(orchard::keys::Scope::Internal)),
                victim_change,
                Zatoshis::const_from_u64(885_000),
                MemoBytes::empty(),
            )
            .unwrap();

        let PcztResult { pczt_parts, .. } = builder
            .build_for_pczt(rng, &zip317::FeeRule::standard())
            .unwrap();
        let pczt = Creator::build_from_parts(pczt_parts).unwrap();
        let pczt_bytes = pczt.serialize();
        let seed_fingerprint = calculate_seed_fingerprint(&victim_seed).unwrap();

        let result = parse_pczt_cypherpunk(&params, &pczt_bytes, &ufvk_text, &seed_fingerprint);
        match result {
            Err(ZcashError::InvalidPczt(_)) => {}
            Err(ZcashError::InvalidDataError(msg))
                if msg.contains("Orchard output was recoverable with an internal OVK but does not belong to this wallet") => {}
            Err(e) => panic!("unexpected error: {e:?}"),
            Ok(parsed) => {
                let orchard = parsed.get_orchard();
                panic!("unexpected success: orchard={orchard:?}");
            }
        }

        let check_result =
            check_pczt_cypherpunk(&params, &pczt_bytes, &ufvk_text, &seed_fingerprint, 0);
        match check_result {
            Err(ZcashError::InvalidPczt(_)) => {}
            Err(ZcashError::InvalidDataError(msg))
                if msg.contains("Orchard output was recoverable with an internal OVK but does not belong to this wallet") => {}
            Err(e) => panic!("unexpected check error: {e:?}"),
            Ok(()) => panic!("unexpected check success"),
        }
    }

    #[test]
    fn test_check_pczt_rejects_empty_sapling_bundle_with_nonzero_value_sum() {
        let seed = [9u8; 32];
        let malformed_pczt = malformed_pczt_with_empty_sapling_bundle_and_nonzero_value_sum();
        let ufvk = derive_ufvk(&MainNetwork, &seed, "m/32'/133'/0'").unwrap();
        let seed_fingerprint = calculate_seed_fingerprint(&seed).unwrap();

        let result = check_pczt_cypherpunk(
            &MainNetwork,
            &malformed_pczt,
            &ufvk.to_string(),
            &seed_fingerprint,
            0,
        );

        assert_empty_sapling_bundle_error(result);
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
    fn test_check_pczt_invalid_ufvk() {
        let sample = pczt::test_support::sample_pczt_to_transparent();
        let seed_fingerprint = [0u8; 32];

        let result = check_pczt_cypherpunk(
            &MainNetwork,
            &sample.bytes,
            "invalid_ufvk",
            &seed_fingerprint,
            0,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ZcashError::InvalidDataError(_)
        ));
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
