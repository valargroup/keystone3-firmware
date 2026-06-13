pub mod check;
pub mod parse;
pub mod sign;
pub mod structs;

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use serde::Deserialize;
use serde_with::serde_as;
use zcash_vendor::{
    pczt::Pczt,
    transparent,
    zcash_protocol::{constants, value::ZatBalance},
    zip32,
};

use crate::errors::ZcashError;

const PCZT_MAGIC_BYTES: &[u8] = b"PCZT";
const PCZT_VERSION_1: u32 = 1;
const PCZT_VERSION_2: u32 = 2;

#[allow(dead_code)]
#[derive(Deserialize)]
struct PcztV1 {
    global: zcash_vendor::pczt::common::Global,
    transparent: zcash_vendor::pczt::transparent::Bundle,
    sapling: zcash_vendor::pczt::sapling::Bundle,
    orchard: PcztV1OrchardBundle,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct PcztV1OrchardBundle {
    actions: Vec<PcztV1OrchardAction>,
    flags: u8,
    value_sum: (u64, bool),
    anchor: [u8; 32],
    zkproof: Option<Vec<u8>>,
    bsk: Option<[u8; 32]>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct PcztV1OrchardAction {
    cv_net: [u8; 32],
    spend: PcztV1OrchardSpend,
    output: PcztV1OrchardOutput,
    rcv: Option<[u8; 32]>,
}

#[serde_as]
#[allow(dead_code)]
#[derive(Deserialize)]
struct PcztV1OrchardSpend {
    nullifier: [u8; 32],
    rk: [u8; 32],
    #[serde_as(as = "Option<[_; 64]>")]
    spend_auth_sig: Option<[u8; 64]>,
    #[serde_as(as = "Option<[_; 43]>")]
    recipient: Option<[u8; 43]>,
    value: Option<u64>,
    rho: Option<[u8; 32]>,
    rseed: Option<[u8; 32]>,
    #[serde_as(as = "Option<[_; 96]>")]
    fvk: Option<[u8; 96]>,
    witness: Option<(u32, [[u8; 32]; 32])>,
    alpha: Option<[u8; 32]>,
    zip32_derivation: Option<PcztV1Zip32Derivation>,
    dummy_sk: Option<[u8; 32]>,
    proprietary: BTreeMap<String, Vec<u8>>,
}

#[serde_as]
#[allow(dead_code)]
#[derive(Deserialize)]
struct PcztV1OrchardOutput {
    cmx: [u8; 32],
    ephemeral_key: [u8; 32],
    enc_ciphertext: Vec<u8>,
    out_ciphertext: Vec<u8>,
    #[serde_as(as = "Option<[_; 43]>")]
    recipient: Option<[u8; 43]>,
    value: Option<u64>,
    rseed: Option<[u8; 32]>,
    ock: Option<[u8; 32]>,
    zip32_derivation: Option<PcztV1Zip32Derivation>,
    user_address: Option<String>,
    proprietary: BTreeMap<String, Vec<u8>>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct PcztV1Zip32Derivation {
    seed_fingerprint: [u8; 32],
    derivation_path: Vec<u32>,
}

#[cfg(zcash_unstable = "nu7")]
#[allow(dead_code)]
#[derive(Deserialize)]
struct PcztV2WithoutIronwood {
    global: zcash_vendor::pczt::common::Global,
    transparent: zcash_vendor::pczt::transparent::Bundle,
    sapling: zcash_vendor::pczt::sapling::Bundle,
    orchard: zcash_vendor::pczt::orchard::Bundle,
}

pub(crate) fn parse_pczt(bytes: &[u8]) -> Result<Pczt, ZcashError> {
    ensure_strict_pczt_encoding(bytes)?;
    Pczt::parse(bytes).map_err(|_| ZcashError::InvalidPczt("invalid pczt data".to_string()))
}

fn ensure_strict_pczt_encoding(bytes: &[u8]) -> Result<(), ZcashError> {
    if bytes.len() < 8 {
        return Err(ZcashError::InvalidPczt("invalid pczt data".to_string()));
    }
    if &bytes[..4] != PCZT_MAGIC_BYTES {
        return Err(ZcashError::InvalidPczt("invalid pczt data".to_string()));
    }

    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let payload = &bytes[8..];
    let remaining = match version {
        PCZT_VERSION_1 => postcard::take_from_bytes::<PcztV1>(payload)
            .map(|(_, remaining)| remaining)
            .map_err(|_| ZcashError::InvalidPczt("invalid pczt data".to_string()))?,
        PCZT_VERSION_2 => match postcard::take_from_bytes::<Pczt>(payload) {
            Ok((_, remaining)) => remaining,
            Err(err) => {
                #[cfg(zcash_unstable = "nu7")]
                {
                    postcard::take_from_bytes::<PcztV2WithoutIronwood>(payload)
                        .map(|(_, remaining)| remaining)
                        .map_err(|_| {
                            let _ = err;
                            ZcashError::InvalidPczt("invalid pczt data".to_string())
                        })?
                }
                #[cfg(not(zcash_unstable = "nu7"))]
                {
                    let _ = err;
                    return Err(ZcashError::InvalidPczt("invalid pczt data".to_string()));
                }
            }
        },
        _ => return Err(ZcashError::InvalidPczt("invalid pczt data".to_string())),
    };

    if remaining.is_empty() {
        Ok(())
    } else {
        Err(ZcashError::InvalidPczt("invalid pczt data".to_string()))
    }
}

pub(crate) fn validate_supported_pczt(pczt: &Pczt) -> Result<(), ZcashError> {
    validate_supported_sapling(pczt)?;

    #[cfg(zcash_unstable = "nu7")]
    {
        let has_ironwood = !pczt.ironwood().actions().is_empty();
        let is_v6 = *pczt.global().tx_version() == constants::V6_TX_VERSION
            && *pczt.global().version_group_id() == constants::V6_VERSION_GROUP_ID;
        if has_ironwood && !is_v6 {
            return Err(ZcashError::InvalidPczt(
                "Ironwood actions require a v6 PCZT".to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_supported_sapling(pczt: &Pczt) -> Result<(), ZcashError> {
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

    if has_sapling_bundle {
        return Err(ZcashError::InvalidPczt(
            "Sapling spends and outputs are not supported".to_string(),
        ));
    }

    if sapling_value_sum != 0 {
        return Err(ZcashError::InvalidPczt(
            "sapling value_sum must be zero when Sapling bundle is empty".to_string(),
        ));
    }

    Ok(())
}

pub(crate) fn transparent_derivation_matches_selected_account<
    P: zcash_vendor::zcash_protocol::consensus::Parameters,
>(
    params: &P,
    seed_fingerprint: &[u8; 32],
    account_index: zip32::AccountId,
    xpub: &transparent::keys::AccountPubKey,
    pubkey: &[u8; 33],
    derivation: &transparent::pczt::Bip32Derivation,
    field_label: &str,
) -> Result<bool, ZcashError> {
    if seed_fingerprint != derivation.seed_fingerprint() {
        return Ok(false);
    }

    let target = xpub
        .derive_pubkey_at_bip32_path(params, account_index, derivation.derivation_path())
        .map_err(|_| {
            ZcashError::InvalidPczt(format!(
                "transparent {field_label} bip32 derivation path invalid"
            ))
        })?;
    if &target.serialize() != pubkey {
        return Err(ZcashError::InvalidPczt(format!(
            "transparent {field_label} script pubkey mismatch"
        )));
    }

    Ok(true)
}

/// Returns the supported account declared by a shielded spend derivation that
/// belongs to this seed. Missing or different seed fingerprints are not ours
/// and return `None`; matching fingerprints with paths outside
/// `m/32'/coin_type'/account'` are invalid.
#[cfg(feature = "cypherpunk")]
pub(crate) fn matching_seed_supported_orchard_account(
    seed_fingerprint: &[u8; 32],
    derivation: Option<&zcash_vendor::orchard::pczt::Zip32Derivation>,
    coin_type: u32,
    pool_label: &str,
) -> Result<Option<zcash_vendor::zip32::AccountId>, crate::errors::ZcashError> {
    let Some(derivation) = derivation else {
        return Ok(None);
    };
    if derivation.seed_fingerprint() != seed_fingerprint {
        return Ok(None);
    }

    let unsupported_path = || {
        crate::errors::ZcashError::InvalidPczt(alloc::format!(
            "unsupported {pool_label} spend ZIP 32 derivation path"
        ))
    };

    let [purpose, path_coin_type, account_index] = &derivation.derivation_path()[..] else {
        return Err(unsupported_path());
    };

    if purpose != &zcash_vendor::zip32::ChildIndex::hardened(32)
        || path_coin_type != &zcash_vendor::zip32::ChildIndex::hardened(coin_type)
    {
        return Err(unsupported_path());
    }

    let account_index = account_index
        .index()
        .checked_sub(1 << 31)
        .ok_or_else(unsupported_path)?;
    zcash_vendor::zip32::AccountId::try_from(account_index)
        .map(Some)
        .map_err(|_| unsupported_path())
}

/// Returns whether a shielded spend belongs to the selected account. Matching
/// seed fingerprints for any other supported account are invalid because the UI
/// only reviews and signs the selected account.
#[cfg(feature = "cypherpunk")]
pub(crate) fn matching_seed_selected_orchard_account(
    seed_fingerprint: &[u8; 32],
    derivation: Option<&zcash_vendor::orchard::pczt::Zip32Derivation>,
    coin_type: u32,
    account_index: zcash_vendor::zip32::AccountId,
    pool_label: &str,
) -> Result<bool, crate::errors::ZcashError> {
    match matching_seed_supported_orchard_account(
        seed_fingerprint,
        derivation,
        coin_type,
        pool_label,
    )? {
        Some(matching_account) if matching_account == account_index => Ok(true),
        Some(_) => Err(crate::errors::ZcashError::InvalidPczt(alloc::format!(
            "unsupported {pool_label} spend ZIP 32 account index"
        ))),
        None => Ok(false),
    }
}

#[cfg(all(
    zcash_unstable = "nu7",
    any(feature = "multi_coins", not(feature = "cypherpunk"))
))]
pub(crate) fn pczt_requires_cypherpunk_support(pczt: &zcash_vendor::pczt::Pczt) -> bool {
    *pczt.global().tx_version() >= 6 || !pczt.ironwood().actions().is_empty()
}

#[cfg(all(test, feature = "cypherpunk"))]
pub(crate) mod test_support {
    use alloc::{string::String, vec, vec::Vec};

    use ::pczt::roles::{creator::Creator, updater::Updater};
    use bitcoin::secp256k1::Secp256k1;
    #[cfg(zcash_unstable = "nu7")]
    use incrementalmerkletree::Retention;
    use keystore::algorithms::zcash::{calculate_seed_fingerprint, derive_ufvk};
    use rand_core::OsRng;
    #[cfg(zcash_unstable = "nu7")]
    use shardtree::{store::memory::MemoryShardStore, ShardTree};
    #[cfg(zcash_unstable = "nu7")]
    use zcash_note_encryption::try_note_decryption;
    use zcash_primitives::transaction::{
        builder::{BuildConfig, Builder, PcztResult},
        fees::zip317,
    };
    #[cfg(zcash_unstable = "nu7")]
    use zcash_vendor::zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade};
    use zcash_vendor::{
        orchard,
        pczt::Pczt,
        transparent::{bundle as transparent, keys::IncomingViewingKey},
        zcash_keys::keys::UnifiedFullViewingKey,
        zcash_protocol::{
            consensus::{MainNetwork, Parameters},
            memo::{Memo, MemoBytes},
            value::Zatoshis,
        },
        zip32,
    };

    pub(crate) struct SamplePczt {
        pub(crate) bytes: Vec<u8>,
        pub(crate) seed: Vec<u8>,
        pub(crate) ufvk_text: String,
        pub(crate) seed_fingerprint: [u8; 32],
        pub(crate) transparent_recipient: String,
    }

    #[cfg(zcash_unstable = "nu7")]
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct Nu7Network;

    #[cfg(zcash_unstable = "nu7")]
    impl Parameters for Nu7Network {
        fn network_type(&self) -> NetworkType {
            NetworkType::Main
        }

        fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
            match nu {
                NetworkUpgrade::Nu7 => Some(BlockHeight::from_u32(10)),
                _ => MainNetwork.activation_height(nu),
            }
        }
    }

    #[cfg(zcash_unstable = "nu7")]
    pub(crate) fn unsupported_orchard_spend_paths() -> Vec<Vec<u32>> {
        vec![
            vec![
                zip32::ChildIndex::hardened(32).index(),
                zip32::ChildIndex::hardened(1).index(),
                zip32::ChildIndex::hardened(0).index(),
            ],
            vec![
                zip32::ChildIndex::hardened(32).index(),
                zip32::ChildIndex::hardened(133).index(),
                zip32::ChildIndex::hardened(0).index(),
                zip32::ChildIndex::hardened(0).index(),
            ],
        ]
    }

    #[cfg(zcash_unstable = "nu7")]
    pub(crate) fn orchard_spend_path_for_account(account_index: u32) -> Vec<u32> {
        vec![
            zip32::ChildIndex::hardened(32).index(),
            zip32::ChildIndex::hardened(133).index(),
            zip32::ChildIndex::hardened(account_index).index(),
        ]
    }

    #[cfg(zcash_unstable = "nu7")]
    pub(crate) fn orchard_pczt_with_spend_derivation(
        bytes: &[u8],
        seed_fingerprint: [u8; 32],
        path: Vec<u32>,
    ) -> Vec<u8> {
        Updater::new(Pczt::parse(bytes).unwrap())
            .update_orchard_with(|mut bundle| {
                for action_index in 0..bundle.bundle().actions().len() {
                    let derivation =
                        orchard::pczt::Zip32Derivation::parse(seed_fingerprint, path.clone())
                            .unwrap();
                    bundle.update_action_with(action_index, |mut action| {
                        action.set_spend_zip32_derivation(derivation);
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .unwrap()
            .finish()
            .serialize()
    }

    #[cfg(zcash_unstable = "nu7")]
    pub(crate) fn orchard_pczt_with_dummy_spend_derivation(
        bytes: &[u8],
        seed_fingerprint: [u8; 32],
        path: Vec<u32>,
    ) -> Vec<u8> {
        Updater::new(Pczt::parse(bytes).unwrap())
            .update_orchard_with(|mut bundle| {
                let dummy_action_indices = bundle
                    .bundle()
                    .actions()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, action)| {
                        matches!(action.spend().value().map(|value| value.inner()), Some(0))
                            .then_some(index)
                    })
                    .collect::<Vec<_>>();
                assert!(!dummy_action_indices.is_empty());

                for action_index in dummy_action_indices {
                    let derivation =
                        orchard::pczt::Zip32Derivation::parse(seed_fingerprint, path.clone())
                            .unwrap();
                    bundle.update_action_with(action_index, |mut action| {
                        action.set_spend_zip32_derivation(derivation);
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .unwrap()
            .finish()
            .serialize()
    }

    #[cfg(zcash_unstable = "nu7")]
    pub(crate) fn ironwood_pczt_with_spend_derivation(
        bytes: &[u8],
        seed_fingerprint: [u8; 32],
        path: Vec<u32>,
    ) -> Vec<u8> {
        Updater::new(Pczt::parse(bytes).unwrap())
            .update_ironwood_with(|mut bundle| {
                for action_index in 0..bundle.bundle().actions().len() {
                    let derivation =
                        orchard::pczt::Zip32Derivation::parse(seed_fingerprint, path.clone())
                            .unwrap();
                    bundle.update_action_with(action_index, |mut action| {
                        action.set_spend_zip32_derivation(derivation);
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .unwrap()
            .finish()
            .serialize()
    }

    #[cfg(zcash_unstable = "nu7")]
    pub(crate) fn ironwood_pczt_with_dummy_spend_derivation(
        bytes: &[u8],
        seed_fingerprint: [u8; 32],
        path: Vec<u32>,
    ) -> Vec<u8> {
        Updater::new(Pczt::parse(bytes).unwrap())
            .update_ironwood_with(|mut bundle| {
                let dummy_action_indices = bundle
                    .bundle()
                    .actions()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, action)| {
                        matches!(action.spend().value().map(|value| value.inner()), Some(0))
                            .then_some(index)
                    })
                    .collect::<Vec<_>>();
                assert!(!dummy_action_indices.is_empty());

                for action_index in dummy_action_indices {
                    let derivation =
                        orchard::pczt::Zip32Derivation::parse(seed_fingerprint, path.clone())
                            .unwrap();
                    bundle.update_action_with(action_index, |mut action| {
                        action.set_spend_zip32_derivation(derivation);
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .unwrap()
            .finish()
            .serialize()
    }

    pub(crate) fn sample_pczt_to_transparent() -> SamplePczt {
        let params = MainNetwork;
        let seed = [7u8; 32];
        let ufvk_text = derive_ufvk(&params, &seed, "m/32'/133'/0'").unwrap();
        let ufvk = UnifiedFullViewingKey::decode(&params, &ufvk_text).unwrap();
        let orchard_fvk = ufvk.orchard().unwrap().clone();

        let account = zcash_vendor::transparent::keys::AccountPrivKey::from_seed(
            &params,
            &seed,
            zip32::AccountId::ZERO,
        )
        .unwrap();
        let (input_addr, address_index) = account
            .to_account_pubkey()
            .derive_external_ivk()
            .unwrap()
            .default_address();
        let input_sk = account.derive_external_secret_key(address_index).unwrap();
        let secp = Secp256k1::signing_only();
        let input_pubkey = input_sk.public_key(&secp);

        let recipient_sk = zcash_vendor::transparent::keys::AccountPrivKey::from_seed(
            &params,
            &[8u8; 32],
            zip32::AccountId::ZERO,
        )
        .unwrap();
        let (recipient, _) = recipient_sk
            .to_account_pubkey()
            .derive_external_ivk()
            .unwrap()
            .default_address();
        let transparent_recipient = recipient
            .to_zcash_address(MainNetwork.network_type())
            .encode();
        let change = orchard_fvk.address_at(0u32, orchard::keys::Scope::Internal);

        let coin = transparent::TxOut::new(
            Zatoshis::const_from_u64(1_000_000),
            input_addr.script().into(),
        );
        let mut builder = Builder::new(
            &params,
            10_000_000.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(orchard::Anchor::empty_tree()),
                #[cfg(zcash_unstable = "nu7")]
                ironwood_anchor: None,
            },
        );
        builder
            .add_transparent_p2pkh_input(
                input_pubkey,
                transparent::OutPoint::new([1u8; 32], 1),
                coin,
            )
            .unwrap();
        builder
            .add_transparent_output(&recipient, Zatoshis::const_from_u64(100_000))
            .unwrap();
        builder
            .add_orchard_output::<zip317::FeeRule>(
                Some(orchard_fvk.to_ovk(orchard::keys::Scope::Internal)),
                change,
                Zatoshis::const_from_u64(885_000),
                MemoBytes::empty(),
            )
            .unwrap();

        let PcztResult { pczt_parts, .. } = builder
            .build_for_pczt(OsRng, &zip317::FeeRule::standard())
            .unwrap();
        let pczt = Updater::new(Creator::build_from_parts(pczt_parts).unwrap())
            .update_transparent_with(|mut bundle| {
                bundle.update_output_with(0, |mut output| {
                    output.set_user_address(transparent_recipient.clone());
                    Ok(())
                })
            })
            .unwrap()
            .finish();

        SamplePczt {
            bytes: pczt.serialize(),
            seed: seed.to_vec(),
            ufvk_text,
            seed_fingerprint: calculate_seed_fingerprint(&seed).unwrap(),
            transparent_recipient,
        }
    }

    #[cfg(zcash_unstable = "nu7")]
    pub(crate) fn sample_orchard_spend_pczt() -> SamplePczt {
        let params = MainNetwork;
        let seed = [7u8; 32];
        let ufvk_text = derive_ufvk(&params, &seed, "m/32'/133'/0'").unwrap();
        let ufvk = UnifiedFullViewingKey::decode(&params, &ufvk_text).unwrap();
        let orchard_fvk = ufvk.orchard().unwrap().clone();
        let orchard_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
        let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
        let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

        let value = orchard::value::NoteValue::from_raw(1_000_000);
        let note = {
            let mut orchard_builder = orchard::builder::Builder::new(
                orchard::builder::BundleProtocol::Orchard,
                orchard::builder::BundleType::DEFAULT,
                orchard::Anchor::empty_tree(),
            );
            orchard_builder
                .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
                .unwrap();
            let (bundle, meta) = orchard_builder.build::<i64>(&mut OsRng).unwrap().unwrap();
            let action = bundle
                .actions()
                .get(meta.output_action_index(0).unwrap())
                .unwrap();
            let domain = orchard::note_encryption::OrchardDomain::for_action(action);
            let (note, _, _) =
                try_note_decryption(&domain, &orchard_ivk.prepare(), action).unwrap();
            note
        };

        let (anchor, merkle_path) = {
            let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
            let leaf = orchard::tree::MerkleHashOrchard::from_cmx(&cmx);
            let mut tree = ShardTree::<_, 32, 16>::new(
                MemoryShardStore::<orchard::tree::MerkleHashOrchard, u32>::empty(),
                100,
            );
            tree.append(leaf, Retention::Marked).unwrap();
            tree.checkpoint(9_999_999).unwrap();
            let merkle_path = tree
                .witness_at_checkpoint_depth(0.into(), 0)
                .unwrap()
                .unwrap();
            let anchor = merkle_path.root(leaf);
            (anchor.into(), merkle_path.into())
        };

        let mut builder = Builder::new(
            &params,
            10_000_000.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: Some(anchor),
                ironwood_anchor: None,
            },
        );
        builder
            .add_orchard_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, merkle_path)
            .unwrap();
        builder
            .add_orchard_output::<zip317::FeeRule>(
                Some(orchard_ovk),
                recipient,
                Zatoshis::const_from_u64(990_000),
                MemoBytes::empty(),
            )
            .unwrap();
        let PcztResult {
            pczt_parts,
            orchard_meta,
            ..
        } = builder
            .build_for_pczt(OsRng, &zip317::FeeRule::standard())
            .unwrap();
        let spend_action_index = orchard_meta.spend_action_index(0).unwrap();
        let seed_fingerprint = calculate_seed_fingerprint(&seed).unwrap();
        let derivation = orchard::pczt::Zip32Derivation::parse(
            seed_fingerprint,
            vec![
                zip32::ChildIndex::hardened(32).index(),
                zip32::ChildIndex::hardened(133).index(),
                zip32::ChildIndex::hardened(0).index(),
            ],
        )
        .unwrap();
        let pczt = Updater::new(Creator::build_from_parts(pczt_parts).unwrap())
            .update_orchard_with(|mut bundle| {
                bundle.update_action_with(spend_action_index, |mut action| {
                    action.set_spend_zip32_derivation(derivation);
                    Ok(())
                })
            })
            .unwrap()
            .finish();

        SamplePczt {
            bytes: pczt.serialize(),
            seed: seed.to_vec(),
            ufvk_text,
            seed_fingerprint,
            transparent_recipient: String::new(),
        }
    }

    #[cfg(zcash_unstable = "nu7")]
    pub(crate) fn sample_ironwood_pczt() -> SamplePczt {
        let params = Nu7Network;
        let seed = [7u8; 32];
        let ufvk_text = derive_ufvk(&params, &seed, "m/32'/133'/0'").unwrap();
        let ufvk = UnifiedFullViewingKey::decode(&params, &ufvk_text).unwrap();
        let orchard_fvk = ufvk.orchard().unwrap().clone();
        let orchard_ivk = orchard_fvk.to_ivk(orchard::keys::Scope::External);
        let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
        let recipient = orchard_fvk.address_at(0u32, orchard::keys::Scope::External);

        let value = orchard::value::NoteValue::from_raw(1_000_000);
        let note = {
            let mut orchard_builder = orchard::builder::Builder::new(
                orchard::builder::BundleProtocol::Ironwood,
                orchard::builder::BundleType::DEFAULT,
                orchard::Anchor::empty_tree(),
            );
            orchard_builder
                .add_output_with_version(
                    None,
                    recipient,
                    value,
                    Memo::Empty.encode().into_bytes(),
                    orchard::note::NoteVersion::V3,
                )
                .unwrap();
            let (bundle, meta) = orchard_builder.build::<i64>(&mut OsRng).unwrap().unwrap();
            let action = bundle
                .actions()
                .get(meta.output_action_index(0).unwrap())
                .unwrap();
            let domain = orchard::note_encryption::OrchardDomain::for_action(action);
            let (note, _, _) =
                try_note_decryption(&domain, &orchard_ivk.prepare(), action).unwrap();
            note
        };

        let (anchor, merkle_path) = {
            let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
            let leaf = orchard::tree::MerkleHashOrchard::from_cmx(&cmx);
            let mut tree = ShardTree::<_, 32, 16>::new(
                MemoryShardStore::<orchard::tree::MerkleHashOrchard, u32>::empty(),
                100,
            );
            tree.append(leaf, Retention::Marked).unwrap();
            tree.checkpoint(9_999_999).unwrap();
            let merkle_path = tree
                .witness_at_checkpoint_depth(0.into(), 0)
                .unwrap()
                .unwrap();
            let anchor = merkle_path.root(leaf);
            (anchor.into(), merkle_path.into())
        };

        let mut builder = Builder::new(
            &params,
            10_000_000.into(),
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: Some(anchor),
            },
        );
        builder
            .add_ironwood_spend::<zip317::FeeRule>(orchard_fvk.clone(), note, merkle_path)
            .unwrap();
        builder
            .add_ironwood_output::<zip317::FeeRule>(
                Some(orchard_ovk),
                recipient,
                Zatoshis::const_from_u64(990_000),
                MemoBytes::empty(),
            )
            .unwrap();
        let PcztResult {
            pczt_parts,
            ironwood_meta,
            ..
        } = builder
            .build_for_pczt(OsRng, &zip317::FeeRule::standard())
            .unwrap();
        let spend_action_index = ironwood_meta.spend_action_index(0).unwrap();
        let seed_fingerprint = calculate_seed_fingerprint(&seed).unwrap();
        let derivation = orchard::pczt::Zip32Derivation::parse(
            seed_fingerprint,
            vec![
                zip32::ChildIndex::hardened(32).index(),
                zip32::ChildIndex::hardened(133).index(),
                zip32::ChildIndex::hardened(0).index(),
            ],
        )
        .unwrap();
        let pczt = Updater::new(Creator::build_from_parts(pczt_parts).unwrap())
            .update_ironwood_with(|mut bundle| {
                bundle.update_action_with(spend_action_index, |mut action| {
                    action.set_spend_zip32_derivation(derivation);
                    Ok(())
                })
            })
            .unwrap()
            .finish();

        SamplePczt {
            bytes: pczt.serialize(),
            seed: seed.to_vec(),
            ufvk_text,
            seed_fingerprint,
            transparent_recipient: String::new(),
        }
    }
}
