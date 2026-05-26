use alloc::{string::ToString, vec::Vec};

use keystore::algorithms::secp256k1::get_public_key_by_seed;
use keystore::algorithms::zcash::calculate_seed_fingerprint;
use zcash_vendor::zcash_keys::keys::UnifiedFullViewingKey;

#[cfg(feature = "cypherpunk")]
use zcash_vendor::orchard;

#[cfg(feature = "cypherpunk")]
use keystore::algorithms::zcash::sign_message_orchard;

use crate::errors::ZcashError;

pub mod check;
pub mod parse;
pub mod sign;
pub mod structs;

#[cfg(all(test, feature = "cypherpunk"))]
pub(crate) mod test_support {
    use alloc::{string::String, vec::Vec};

    use ::pczt::roles::{creator::Creator, updater::Updater};
    use bitcoin::secp256k1::Secp256k1;
    use keystore::algorithms::zcash::{calculate_seed_fingerprint, derive_ufvk};
    use rand_core::OsRng;
    use zcash_primitives::transaction::{
        builder::{BuildConfig, Builder, PcztResult},
        fees::zip317,
    };
    use zcash_vendor::{
        orchard,
        transparent::{bundle as transparent, keys::IncomingViewingKey},
        zcash_keys::keys::UnifiedFullViewingKey,
        zcash_protocol::{
            consensus::{MainNetwork, Parameters},
            memo::MemoBytes,
            value::Zatoshis,
        },
        zip32,
    };

    pub(crate) struct SamplePczt {
        pub(crate) bytes: Vec<u8>,
        pub(crate) ufvk_text: String,
        pub(crate) seed_fingerprint: [u8; 32],
        pub(crate) transparent_recipient: String,
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
            ufvk_text,
            seed_fingerprint: calculate_seed_fingerprint(&seed).unwrap(),
            transparent_recipient,
        }
    }
}
