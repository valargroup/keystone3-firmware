#![no_std]
#![feature(vec_into_raw_parts)]

extern crate alloc;

pub mod address;
pub mod structs;

use crate::common::{
    errors::RustCError,
    ffi::CSliceFFI,
    structs::{ExtendedPublicKey, TransactionCheckResult, TransactionParseResult},
    types::{PtrBytes, PtrT, PtrUR},
    ur::{UREncodeResult, FRAGMENT_MAX_LENGTH_DEFAULT, FRAGMENT_UNLIMITED_LENGTH},
    utils::{recover_c_array, recover_c_char},
};
use crate::{extract_array, extract_ptr_with_type};
use alloc::{format, string::String, string::ToString, vec::Vec};
use app_avalanche::{
    constants::{
        C_BLOCKCHAIN_ID, C_CHAIN_PREFIX, C_TEST_BLOCKCHAIN_ID, P_BLOCKCHAIN_ID, X_BLOCKCHAIN_ID,
        X_P_CHAIN_PREFIX, X_TEST_BLOCKCHAIN_ID,
    },
    errors::AvaxError,
    get_avax_tx_header, get_avax_tx_type_id, parse_avax_tx,
    transactions::{
        base_tx::{avax_base_sign, BaseTx},
        c_chain::{evm_export::ExportTx as CchainExportTx, evm_import::ImportTx as CchainImportTx},
        export::ExportTx,
        import::ImportTx,
        p_chain::{
            add_permissionless_delegator::AddPermissionlessDelegatorTx,
            add_permissionless_validator::AddPermissionlessValidatorTx,
        },
        type_id::{self, TypeId},
    },
};
use structs::DisplayAvaxTx;
use {
    hex,
    ur_registry::{
        avalanche::{avax_sign_request::AvaxSignRequest, avax_signature::AvaxSignature},
        traits::RegistryItem,
    },
};

fn validate_transaction_by_type(tx_data: Vec<u8>) -> Result<(), AvaxError> {
    let type_id = get_avax_tx_type_id(tx_data.clone())?;

    macro_rules! validate_tx {
        ($tx_type:ty) => {
            parse_avax_tx::<$tx_type>(tx_data).map(|_| ())
        };
    }

    match type_id {
        TypeId::BaseTx => {
            let header = get_avax_tx_header(tx_data.clone())?;
            if header.get_blockchain_id() == C_BLOCKCHAIN_ID
                || header.get_blockchain_id() == C_TEST_BLOCKCHAIN_ID
            {
                validate_tx!(CchainImportTx)
            } else {
                validate_tx!(BaseTx)
            }
        }
        TypeId::PchainExportTx | TypeId::XchainExportTx => validate_tx!(ExportTx),
        TypeId::XchainImportTx | TypeId::PchainImportTx => validate_tx!(ImportTx),
        TypeId::CchainExportTx => validate_tx!(CchainExportTx),
        TypeId::AddPermissionlessValidator => validate_tx!(AddPermissionlessValidatorTx),
        TypeId::AddPermissionlessDelegator => validate_tx!(AddPermissionlessDelegatorTx),
        _ => Err(AvaxError::UnsupportedTransaction(format!(
            "{type_id:?} not support"
        ))),
    }
}

#[no_mangle]
pub unsafe extern "C" fn avax_parse_transaction(
    ptr: PtrUR,
    mfp: PtrBytes,
    mfp_len: u32,
    public_keys: PtrT<CSliceFFI<ExtendedPublicKey>>,
) -> PtrT<TransactionParseResult<DisplayAvaxTx>> {
    parse_transaction_by_type(extract_ptr_with_type!(ptr, AvaxSignRequest), public_keys)
}

unsafe fn parse_transaction_by_type(
    sign_request: &mut AvaxSignRequest,
    public_keys: PtrT<CSliceFFI<ExtendedPublicKey>>,
) -> PtrT<TransactionParseResult<DisplayAvaxTx>> {
    let tx_data = sign_request.get_tx_data();
    let type_id = match get_avax_tx_type_id(sign_request.get_tx_data()) {
        Ok(type_id) => type_id,
        Err(_) => {
            return TransactionParseResult::from(RustCError::InvalidData(
                "invalid avax tx type id".to_string(),
            ))
            .c_ptr()
        }
    };

    // Build full derivation paths from sign_request.
    let derivation_keypaths = sign_request.get_derivation_path();
    if derivation_keypaths.is_empty() {
        return TransactionParseResult::from(RustCError::InvalidData(
            "invalid derivation path".to_string(),
        ))
        .c_ptr();
    }

    let mut paths: Vec<String> = Vec::new();
    for kp in derivation_keypaths.iter() {
        match kp.get_path() {
            Some(p) => paths.push(format!("m/{}", p)),
            None => {
                return TransactionParseResult::from(RustCError::InvalidData(
                    "invalid derivation path".to_string(),
                ))
                .c_ptr()
            }
        }
    }

    // Derive addresses by matching every full path with available keys.
    let mut from_infos: Vec<(String, String)> = Vec::new();
    let mut address = String::new();
    for full_path in paths.iter() {
        let mut derived_address = "no address".to_string();
        for key in recover_c_array(public_keys).iter() {
            let key_path = recover_c_char(key.path).to_lowercase();
            if full_path.starts_with(&key_path) {
                derived_address = match key_path.as_str() {
                    "m/44'/60'/0'" => app_ethereum::address::derive_address(
                        full_path.as_str(),
                        &recover_c_char(key.xpub),
                        &key_path,
                    )
                    .unwrap_or("no address".to_string()),
                    _ => app_avalanche::get_address(
                        app_avalanche::network::Network::AvaxMainNet,
                        full_path.as_str(),
                        &recover_c_char(key.xpub),
                        &key_path,
                    )
                    .unwrap_or("no address".to_string()),
                };

                if derived_address != "no address" && address.is_empty() {
                    address = derived_address.clone();
                }
                break;
            }
        }
        from_infos.push((full_path.clone(), derived_address));
    }

    if address.is_empty() {
        address = "no address".to_string();
    }

    if from_infos.is_empty() {
        return TransactionParseResult::from(RustCError::InvalidData(
            "invalid derivation path".to_string(),
        ))
        .c_ptr();
    }

    // Helper macro: given a concrete tx type `$tx_type`, parse raw tx bytes (`tx_data`)
    // into that type with `parse_avax_tx::<$tx_type>`, then convert it to the
    // UI-friendly `DisplayAvaxTx` and wrap it into `TransactionParseResult` (C pointer).
    // On parse error, returns a unified `InvalidData` result.
    macro_rules! parse_tx {
        ($tx_type:ty) => {
            parse_avax_tx::<$tx_type>(tx_data)
                .map(|parse_data| {
                    TransactionParseResult::success(
                        DisplayAvaxTx::from_tx_info(
                            parse_data,
                            from_infos.clone(),
                            address.clone(),
                            type_id,
                        )
                        .c_ptr(),
                    )
                    .c_ptr()
                })
                .unwrap_or_else(|_| {
                    TransactionParseResult::from(RustCError::InvalidData(
                        "invalid data".to_string(),
                    ))
                    .c_ptr()
                })
        };
    }
    match type_id {
        TypeId::BaseTx => {
            let header = get_avax_tx_header(tx_data.clone()).unwrap();
            if header.get_blockchain_id() == C_BLOCKCHAIN_ID
                || header.get_blockchain_id() == C_TEST_BLOCKCHAIN_ID
            {
                // For C-chain import, use empty path
                parse_avax_tx::<CchainImportTx>(tx_data)
                    .map(|parse_data| {
                        TransactionParseResult::success(
                            DisplayAvaxTx::from_tx_info(
                                parse_data,
                                from_infos.clone(),
                                address.clone(),
                                type_id,
                            )
                            .c_ptr(),
                        )
                        .c_ptr()
                    })
                    .unwrap_or_else(|_| {
                        TransactionParseResult::from(RustCError::InvalidData(
                            "invalid data".to_string(),
                        ))
                        .c_ptr()
                    })
            } else {
                parse_tx!(BaseTx)
            }
        }
        TypeId::PchainExportTx | TypeId::XchainExportTx => parse_tx!(ExportTx),
        TypeId::XchainImportTx | TypeId::PchainImportTx => parse_tx!(ImportTx),
        TypeId::CchainExportTx => parse_tx!(CchainExportTx),
        TypeId::AddPermissionlessValidator => parse_tx!(AddPermissionlessValidatorTx),
        TypeId::AddPermissionlessDelegator => parse_tx!(AddPermissionlessDelegatorTx),
        _ => TransactionParseResult::from(RustCError::InvalidData(format!(
            "{type_id:?} not support"
        )))
        .c_ptr(),
    }
}

#[no_mangle]
unsafe fn avax_sign_dynamic(
    ptr: PtrUR,
    seed: PtrBytes,
    seed_len: u32,
    fragment_length: usize,
) -> PtrT<UREncodeResult> {
    let seed = extract_array!(seed, u8, seed_len as usize);
    build_sign_result(ptr, seed)
        .map(|v: AvaxSignature| v.try_into())
        .map_or_else(
            |e| UREncodeResult::from(e).c_ptr(),
            |v| {
                v.map_or_else(
                    |e| UREncodeResult::from(e).c_ptr(),
                    |data| {
                        UREncodeResult::encode(
                            data,
                            AvaxSignature::get_registry_type().get_type(),
                            fragment_length,
                        )
                        .c_ptr()
                    },
                )
            },
        )
}

unsafe fn build_sign_result(ptr: PtrUR, seed: &[u8]) -> Result<AvaxSignature, AvaxError> {
    let sign_request = extract_ptr_with_type!(ptr, AvaxSignRequest);

    let derivation_keypaths = sign_request.get_derivation_path();
    if derivation_keypaths.is_empty() {
        return Err(AvaxError::InvalidInput);
    }
    let mut paths: Vec<String> = Vec::new();
    for kp in derivation_keypaths.iter() {
        match kp.get_path() {
            Some(p) => paths.push(format!("m/{}", p)),
            None => return Err(AvaxError::InvalidInput),
        }
    }

    avax_base_sign(seed, paths, sign_request.get_tx_data()).map(|signature| {
        let signatures: Vec<Vec<u8>> = signature.into_iter().map(|arr| arr.to_vec()).collect();
        AvaxSignature::new(sign_request.get_request_id(), signatures)
    })
}

#[no_mangle]
pub unsafe extern "C" fn avax_sign(
    ptr: PtrUR,
    seed: PtrBytes,
    seed_len: u32,
) -> PtrT<UREncodeResult> {
    avax_sign_dynamic(ptr, seed, seed_len, FRAGMENT_MAX_LENGTH_DEFAULT)
}

#[no_mangle]
pub unsafe extern "C" fn avax_sign_unlimited(
    ptr: PtrUR,
    seed: PtrBytes,
    seed_len: u32,
) -> PtrT<UREncodeResult> {
    avax_sign_dynamic(ptr, seed, seed_len, FRAGMENT_UNLIMITED_LENGTH)
}

#[no_mangle]
pub unsafe extern "C" fn avax_check_transaction(
    ptr: PtrUR,
    mfp: PtrBytes,
    mfp_len: u32,
) -> PtrT<TransactionCheckResult> {
    let avax_tx = extract_ptr_with_type!(ptr, AvaxSignRequest);
    let mfp: [u8; 4] = match extract_array!(mfp, u8, mfp_len as usize).try_into() {
        Ok(mfp) => mfp,
        Err(_) => {
            return TransactionCheckResult::from(RustCError::InvalidMasterFingerprint).c_ptr();
        }
    };

    let derivation_paths = avax_tx.get_derivation_path();
    let first_path = match derivation_paths.first() {
        Some(path) => path,
        None => {
            return TransactionCheckResult::from(RustCError::InvalidData(
                "missing derivation path".to_string(),
            ))
            .c_ptr();
        }
    };

    match first_path.get_source_fingerprint() {
        Some(fingerprint) if fingerprint == mfp => {
            match validate_transaction_by_type(avax_tx.get_tx_data()) {
                Ok(()) => TransactionCheckResult::new().c_ptr(),
                Err(e) => TransactionCheckResult::from(e).c_ptr(),
            }
        }
        _ => TransactionCheckResult::from(RustCError::MasterFingerprintMismatch).c_ptr(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FUJI_BASE_TX: &str = "00000000000000000005ab68eb1ee142a05cfe768c36e11f0b596db5a3c6c77aabe665dad9e638ca94f7000000023d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa000000070000000001312d00000000000000000000000001000000018771921301d5bffff592dae86695a615bdb4a4413d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa000000070000000004b571c0000000000000000000000001000000010969ea62e2bb30e66d82e82fe267edf6871ea5f7000000019eae34633c2103aaee5253bb3ca3046c2ab4718a109ffcdb77b51d0427be6bb7000000003d9bdac0ed1d761330cf680efdeb1a42159eb387d6d2950c96f7d28f61bbe2aa000000050000000005f5e100000000010000000000000000";

    #[test]
    fn check_rejects_replaced_first_output_asset_id() {
        let valid_tx = hex::decode(FUJI_BASE_TX).unwrap();
        assert!(validate_transaction_by_type(valid_tx.clone()).is_ok());

        let mut replaced_asset_tx = valid_tx;
        // codec + type + network + blockchain id + outputs count
        const FIRST_OUTPUT_ASSET_OFFSET: usize = 2 + 4 + 4 + 32 + 4;
        replaced_asset_tx[FIRST_OUTPUT_ASSET_OFFSET..FIRST_OUTPUT_ASSET_OFFSET + 32].fill(0xaa);

        assert!(validate_transaction_by_type(replaced_asset_tx).is_err());
    }
}
