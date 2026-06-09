pub mod check;
pub mod parse;
pub mod sign;
pub mod structs;

#[cfg(all(test, feature = "cypherpunk"))]
pub(crate) mod test_support {
    use alloc::{string::String, vec, vec::Vec};

    use ::pczt::roles::{creator::Creator, updater::Updater};
    use bitcoin::secp256k1::Secp256k1;
    use incrementalmerkletree::Retention;
    use keystore::algorithms::zcash::{calculate_seed_fingerprint, derive_ufvk};
    use rand_core::OsRng;
    use shardtree::{store::memory::MemoryShardStore, ShardTree};
    use zcash_note_encryption::try_note_decryption;
    use zcash_primitives::transaction::{
        builder::{BuildConfig, Builder, PcztResult},
        fees::zip317,
    };
    #[cfg(zcash_unstable = "nu7")]
    use zcash_vendor::zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade};
    use zcash_vendor::{
        orchard,
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
                #[cfg(zcash_unstable = "nu7")]
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
