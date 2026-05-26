use super::*;
use crate::version::KEYSTONE_FW_VERSION;

/// `global.proprietary` key stamped into every signed PCZT response.
/// Value is 3 bytes `[major, minor, build]`. Wallets read this to check
/// whether the device meets their minimum version requirements.
const PROP_KEY_FW_VERSION: &str = "keystone:fw_version";
use bitcoin::secp256k1;
use blake2b_simd::Hash;
use keystore::algorithms::secp256k1::get_private_key_by_seed;
use rand_core::OsRng;
use zcash_vendor::{
    pczt::{
        roles::{low_level_signer, redactor::Redactor, updater::Updater},
        Pczt,
    },
    pczt_ext::{self, PcztSigner},
    transparent::{self, sighash::SignableInput},
};

struct SeedSigner<'a> {
    seed: &'a [u8],
}

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
        let fingerprint = calculate_seed_fingerprint(self.seed)
            .map_err(|e| ZcashError::SigningError(e.to_string()))?;

        let key_path = input.bip32_derivation();

        let path = key_path
            .iter()
            .find_map(|(pubkey, path)| {
                let path_fingerprint = *path.seed_fingerprint();
                if fingerprint == path_fingerprint {
                    let path = {
                        let mut ret = "m".to_string();
                        for i in path.derivation_path().iter() {
                            if i.is_hardened() {
                                ret.push_str(&alloc::format!("/{}'", i.index()));
                            } else {
                                ret.push_str(&alloc::format!("/{}", i.index()));
                            }
                        }
                        ret
                    };
                    match get_public_key_by_seed(self.seed, &path) {
                        Ok(my_pubkey) if my_pubkey.serialize().to_vec().eq(pubkey) => {
                            Some(Ok(path))
                        }
                        Err(e) => Some(Err(e)),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .transpose()
            .map_err(|e| ZcashError::SigningError(e.to_string()))?;

        if let Some(path) = path {
            let sk = get_private_key_by_seed(self.seed, &path).map_err(|e| {
                ZcashError::SigningError(alloc::format!("failed to get private key: {e:?}"))
            })?;
            let secp = secp256k1::Secp256k1::new();
            input.sign(index, hash, &sk, &secp).map_err(|e| {
                ZcashError::SigningError(alloc::format!("failed to sign input: {e:?}"))
            })?;
        }

        Ok(())
    }

    #[cfg(feature = "cypherpunk")]
    fn sign_orchard(
        &self,
        action: &mut orchard::pczt::Action,
        hash: Hash,
    ) -> Result<(), Self::Error> {
        let fingerprint = calculate_seed_fingerprint(self.seed)
            .map_err(|e| ZcashError::SigningError(e.to_string()))?;

        let derivation = action.spend().zip32_derivation().as_ref().ok_or_else(|| {
            ZcashError::SigningError("missing ZIP 32 derivation for Orchard action".into())
        })?;

        if &fingerprint == derivation.seed_fingerprint() {
            sign_message_orchard(
                action,
                self.seed,
                hash.as_bytes().try_into().expect("correct length"),
                &derivation.derivation_path().clone(),
                OsRng,
            )
            .map_err(|e| ZcashError::SigningError(e.to_string()))
        } else {
            Ok(())
        }
    }
}
pub fn sign_pczt(pczt: Pczt, seed: &[u8]) -> crate::Result<Vec<u8>> {
    let signer = low_level_signer::Signer::new(pczt);

    #[cfg(any(feature = "multi_coins", feature = "cypherpunk"))]
    let signer = pczt_ext::sign_transparent(signer, &SeedSigner { seed })
        .map_err(|e| ZcashError::SigningError(e.to_string()))?;
    #[cfg(feature = "cypherpunk")]
    let signer = pczt_ext::sign_orchard(signer, &SeedSigner { seed })
        .map_err(|e| ZcashError::SigningError(e.to_string()))?;

    // Stamp the firmware version into `global.proprietary` so the wallet can
    // tell exactly which version of Keystone firmware produced this signature.
    // The Redactor below intentionally does not touch `global`, so this value
    // survives the redaction pass into the returned bytes.
    let stamped_pczt = Updater::new(signer.finish())
        .update_global_with(|mut g| {
            g.set_proprietary(
                PROP_KEY_FW_VERSION.into(),
                KEYSTONE_FW_VERSION.encode().to_vec(),
            );
        })
        .finish();

    // Now that we've created the signature, remove the other optional fields from the
    // PCZT, to reduce its size for the return trip and make the QR code scanning more
    // reliable. The wallet that provided the unsigned PCZT can retain it for combining if
    // these fields are needed.
    let signed_pczt = Redactor::new(stamped_pczt)
        .redact_orchard_with(|mut r| {
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
        })
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
        .finish();

    Ok(signed_pczt.serialize())
}

#[cfg(test)]
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
