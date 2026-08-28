use super::structs::DisplayTx;
use crate::common::errors::RustCError;
use crate::common::keystone;
use crate::common::keystone::{build_parse_context, build_payload};
use crate::common::structs::{TransactionCheckResult, TransactionParseResult};
use crate::common::types::{PtrBytes, PtrString, PtrT, PtrUR};
use crate::common::ur::{QRCodeType, UREncodeResult};
use crate::extract_array;
use alloc::boxed::Box;
use alloc::string::ToString;
use ur_registry::pb::protoc;

fn is_supported_legacy_utxo_payload(payload: &protoc::Payload) -> bool {
    matches!(
        payload.content.as_ref(),
        Some(protoc::payload::Content::SignTx(sign_tx))
            if app_bitcoin::network::is_supported_legacy_utxo_transaction(sign_tx)
    )
}

#[no_mangle]
pub unsafe extern "C" fn utxo_parse_keystone(
    ptr: PtrUR,
    ur_type: QRCodeType,
    master_fingerprint: PtrBytes,
    length: u32,
    x_pub: PtrString,
) -> *mut TransactionParseResult<DisplayTx> {
    if matches!(ur_type, QRCodeType::Bytes) {
        return TransactionParseResult::from(RustCError::UnsupportedTransaction(
            "bitcoin-family transactions are not supported via ur:bytes".to_string(),
        ))
        .c_ptr();
    }
    if length != 4 {
        return TransactionParseResult::from(RustCError::InvalidMasterFingerprint).c_ptr();
    }
    build_payload(ptr, ur_type).map_or_else(
        |e| TransactionParseResult::from(e).c_ptr(),
        |payload| {
            if !is_supported_legacy_utxo_payload(&payload) {
                return TransactionParseResult::from(RustCError::UnsupportedTransaction(
                    app_bitcoin::network::UNSUPPORTED_LEGACY_UTXO_MESSAGE.to_string(),
                ))
                .c_ptr();
            }
            build_parse_context(master_fingerprint, x_pub).map_or_else(
                |e| TransactionParseResult::from(e).c_ptr(),
                |context| {
                    app_bitcoin::parse_raw_tx(payload, context).map_or_else(
                        |e| TransactionParseResult::from(e).c_ptr(),
                        |res| {
                            TransactionParseResult::success(Box::into_raw(Box::new(
                                DisplayTx::from(res),
                            )))
                            .c_ptr()
                        },
                    )
                },
            )
        },
    )
}

#[no_mangle]
pub unsafe extern "C" fn utxo_sign_keystone(
    ptr: PtrUR,
    ur_type: QRCodeType,
    master_fingerprint: PtrBytes,
    length: u32,
    x_pub: PtrString,
    cold_version: i32,
    seed: PtrBytes,
    seed_len: u32,
) -> *mut UREncodeResult {
    if matches!(ur_type, QRCodeType::Bytes) {
        return UREncodeResult::from(RustCError::UnsupportedTransaction(
            "bitcoin-family transactions are not supported via ur:bytes".to_string(),
        ))
        .c_ptr();
    }
    let seed = extract_array!(seed, u8, seed_len as usize);
    keystone::sign(
        ptr,
        ur_type,
        master_fingerprint,
        length,
        x_pub,
        cold_version,
        seed,
    )
}

#[no_mangle]
pub unsafe extern "C" fn utxo_check_keystone(
    ptr: PtrUR,
    ur_type: QRCodeType,
    master_fingerprint: PtrBytes,
    length: u32,
    x_pub: PtrString,
) -> PtrT<TransactionCheckResult> {
    if matches!(ur_type, QRCodeType::Bytes) {
        return TransactionCheckResult::from(RustCError::UnsupportedTransaction(
            "bitcoin-family transactions are not supported via ur:bytes".to_string(),
        ))
        .c_ptr();
    }
    keystone::check(ptr, ur_type, master_fingerprint, length, x_pub)
}
