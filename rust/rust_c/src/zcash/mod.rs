pub mod structs;

use crate::common::{
    errors::RustCError,
    free::Free,
    structs::{SimpleResponse, TransactionCheckResult, TransactionParseResult},
    types::{Ptr, PtrBytes, PtrString, PtrT, PtrUR},
    ur::{UREncodeResult, FRAGMENT_MAX_LENGTH_DEFAULT, FRAGMENT_UNLIMITED_LENGTH},
    utils::{convert_c_char, recover_c_char},
};
use crate::{extract_array, extract_array_mut};
use crate::{extract_ptr_with_type, make_free_method};
use alloc::{boxed::Box, format, string::String, string::ToString, vec::Vec};
use app_zcash::get_address;
#[cfg(feature = "cypherpunk")]
use app_zcash::{
    BatchSignRequest, BatchSignRequestMessage, BatchSignResponse, BatchSignResponseMessage,
};
use core::slice;
use cryptoxide::hashing::sha256;
use cty::c_char;
use keystore::algorithms::{
    ed25519::slip10_ed25519::get_private_key_by_seed,
    zcash::{calculate_seed_fingerprint, derive_ufvk},
};
use structs::DisplayPczt;
use structs::DisplayZcashBatch;
use structs::ZcashCheckedPczt;
use ur_registry::traits::RegistryItem;
use ur_registry::zcash::zcash_batch_sig_result::ZcashBatchSigResult;
use ur_registry::zcash::zcash_pczt::ZcashPczt;
use ur_registry::zcash::zcash_sign_batch::ZcashSignBatch;
use zcash_vendor::zcash_protocol::consensus::MainNetwork;
use zeroize::Zeroize;

// Batch memory is bounded by message count AND total payload bytes. A full
// 35-message pczt-v1 batch used about 35% of RAM on target hardware; the
// compact PCZT messages this build consumes are far smaller per message, so the
// message ceiling rises to 80 (a full migration batch) while the byte bound
// keeps 80 full-size payloads from exceeding what the old 35-message cap
// admitted in practice. Revisit under memory pressure or for new message kinds.
#[cfg(feature = "cypherpunk")]
const ZCASH_BATCH_MAX_MESSAGES: usize = 80;
#[cfg(feature = "cypherpunk")]
const ZCASH_BATCH_MAX_TOTAL_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

#[no_mangle]
pub unsafe extern "C" fn derive_zcash_ufvk(
    seed: PtrBytes,
    seed_len: u32,
    account_path: PtrString,
) -> *mut SimpleResponse<c_char> {
    let seed = extract_array!(seed, u8, seed_len as usize);
    let account_path = unsafe { recover_c_char(account_path) };
    let ufvk_text = derive_ufvk(&MainNetwork, seed, &account_path);
    let result = match ufvk_text {
        Ok(text) => SimpleResponse::success(convert_c_char(text)).simple_c_ptr(),
        Err(e) => SimpleResponse::from(e).simple_c_ptr(),
    };
    result
}

#[no_mangle]
pub unsafe extern "C" fn calculate_zcash_seed_fingerprint(
    seed: PtrBytes,
    seed_len: u32,
) -> *mut SimpleResponse<u8> {
    let mut seed = extract_array_mut!(seed, u8, seed_len as usize);
    let sfp = calculate_seed_fingerprint(seed);
    let result = match sfp {
        Ok(bytes) => {
            SimpleResponse::success(Box::into_raw(Box::new(bytes)) as *mut u8).simple_c_ptr()
        }
        Err(e) => SimpleResponse::from(e).simple_c_ptr(),
    };
    seed.zeroize();
    result
}

#[no_mangle]
pub unsafe extern "C" fn generate_zcash_default_address(
    ufvk_text: PtrString,
) -> *mut SimpleResponse<c_char> {
    let ufvk_text = unsafe { recover_c_char(ufvk_text) };
    let address = get_address(&MainNetwork, &ufvk_text);
    match address {
        Ok(text) => SimpleResponse::success(convert_c_char(text)).simple_c_ptr(),
        Err(e) => SimpleResponse::from(e).simple_c_ptr(),
    }
}

#[no_mangle]
#[cfg(feature = "cypherpunk")]
pub unsafe extern "C" fn check_zcash_tx_cypherpunk(
    tx: PtrUR,
    ufvk: PtrString,
    seed_fingerprint: PtrBytes,
    account_index: u32,
    disabled: bool,
    checked_pczt: Ptr<Ptr<ZcashCheckedPczt>>,
) -> *mut TransactionCheckResult {
    *checked_pczt = core::ptr::null_mut();
    if disabled {
        return TransactionCheckResult::from(RustCError::UnsupportedTransaction(
            "Zcash requires at least 256-bit entropy (use 33-word Shamir shares)".to_string(),
        ))
        .c_ptr();
    }
    let pczt = extract_ptr_with_type!(tx, ZcashPczt);
    let ufvk_text = unsafe { recover_c_char(ufvk) };
    let seed_fingerprint = extract_array!(seed_fingerprint, u8, 32);
    let seed_fingerprint = seed_fingerprint.try_into().unwrap();
    match app_zcash::check_pczt_cypherpunk(
        &MainNetwork,
        &pczt.get_data(),
        &ufvk_text,
        seed_fingerprint,
        account_index,
    ) {
        Ok(normalized) => {
            *checked_pczt = ZcashCheckedPczt::new(normalized).c_ptr();
            TransactionCheckResult::new().c_ptr()
        }
        Err(e) => TransactionCheckResult::from(e).c_ptr(),
    }
}

#[cfg(feature = "multi-coins")]
#[no_mangle]
pub unsafe extern "C" fn check_zcash_tx_multi_coins(
    tx: PtrUR,
    xpub: PtrString,
    seed_fingerprint: PtrBytes,
    account_index: u32,
    disabled: bool,
    checked_pczt: Ptr<Ptr<ZcashCheckedPczt>>,
) -> *mut TransactionCheckResult {
    *checked_pczt = core::ptr::null_mut();
    if disabled {
        return TransactionCheckResult::from(RustCError::UnsupportedTransaction(
            "Zcash requires at least 256-bit entropy (use 33-word Shamir shares)".to_string(),
        ))
        .c_ptr();
    }
    let pczt = extract_ptr_with_type!(tx, ZcashPczt);
    let xpub_text = unsafe { recover_c_char(xpub) };
    let seed_fingerprint = extract_array!(seed_fingerprint, u8, 32);
    let seed_fingerprint = seed_fingerprint.try_into().unwrap();
    match app_zcash::check_pczt_multi_coins(
        &MainNetwork,
        &pczt.get_data(),
        &xpub_text,
        seed_fingerprint,
        account_index,
    ) {
        Ok(normalized) => {
            *checked_pczt = ZcashCheckedPczt::new(normalized).c_ptr();
            TransactionCheckResult::new().c_ptr()
        }
        Err(e) => TransactionCheckResult::from(e).c_ptr(),
    }
}

#[cfg(feature = "cypherpunk")]
#[no_mangle]
pub unsafe extern "C" fn parse_zcash_tx_cypherpunk(
    checked_pczt: Ptr<ZcashCheckedPczt>,
    ufvk: PtrString,
    seed_fingerprint: PtrBytes,
) -> Ptr<TransactionParseResult<DisplayPczt>> {
    if checked_pczt.is_null() {
        return TransactionParseResult::from(RustCError::InvalidData(
            "no checked PCZT available".to_string(),
        ))
        .c_ptr();
    }
    let checked = extract_ptr_with_type!(checked_pczt, ZcashCheckedPczt);
    let bytes = match checked.checked_bytes() {
        Ok(bytes) => bytes,
        Err(e) => return TransactionParseResult::from(e).c_ptr(),
    };
    let ufvk_text = unsafe { recover_c_char(ufvk) };
    let seed_fingerprint = extract_array!(seed_fingerprint, u8, 32);
    let seed_fingerprint = seed_fingerprint.try_into().unwrap();
    match app_zcash::parse_pczt_cypherpunk(&MainNetwork, bytes, &ufvk_text, seed_fingerprint) {
        Ok(pczt) => TransactionParseResult::success(DisplayPczt::from(&pczt).c_ptr()).c_ptr(),
        Err(e) => TransactionParseResult::from(e).c_ptr(),
    }
}

#[cfg(feature = "multi-coins")]
#[no_mangle]
pub unsafe extern "C" fn parse_zcash_tx_multi_coins(
    checked_pczt: Ptr<ZcashCheckedPczt>,
    seed_fingerprint: PtrBytes,
) -> Ptr<TransactionParseResult<DisplayPczt>> {
    if checked_pczt.is_null() {
        return TransactionParseResult::from(RustCError::InvalidData(
            "no checked PCZT available".to_string(),
        ))
        .c_ptr();
    }
    let checked = extract_ptr_with_type!(checked_pczt, ZcashCheckedPczt);
    let bytes = match checked.checked_bytes() {
        Ok(bytes) => bytes,
        Err(e) => return TransactionParseResult::from(e).c_ptr(),
    };
    let seed_fingerprint = extract_array!(seed_fingerprint, u8, 32);
    let seed_fingerprint = seed_fingerprint.try_into().unwrap();
    match app_zcash::parse_pczt_multi_coins(&MainNetwork, bytes, seed_fingerprint) {
        Ok(pczt) => TransactionParseResult::success(DisplayPczt::from(&pczt).c_ptr()).c_ptr(),
        Err(e) => TransactionParseResult::from(e).c_ptr(),
    }
}

#[cfg(feature = "cypherpunk")]
fn validate_zcash_batch(batch: &BatchSignRequest) -> Result<(), RustCError> {
    let messages = batch.messages();
    if batch.request_id().is_empty() {
        return Err(RustCError::InvalidData(
            "Zcash batch has no request id".to_string(),
        ));
    }
    if messages.is_empty() {
        return Err(RustCError::InvalidData(
            "Zcash batch has no messages".to_string(),
        ));
    }
    if messages.len() > ZCASH_BATCH_MAX_MESSAGES {
        return Err(RustCError::UnsupportedTransaction(format!(
            "Zcash batch supports at most {ZCASH_BATCH_MAX_MESSAGES} messages"
        )));
    }

    let mut total_payload_bytes = 0usize;
    for (index, message) in messages.iter().enumerate() {
        if message.message_id().is_empty() {
            return Err(RustCError::InvalidData(format!(
                "Zcash batch message {index} has no id"
            )));
        }
        if message.pczt().is_empty() {
            return Err(RustCError::InvalidData(format!(
                "Zcash batch message {index} has no payload"
            )));
        }
        total_payload_bytes = total_payload_bytes.saturating_add(message.pczt().len());
        if total_payload_bytes > ZCASH_BATCH_MAX_TOTAL_PAYLOAD_BYTES {
            return Err(RustCError::UnsupportedTransaction(format!(
                "Zcash batch payloads exceed {ZCASH_BATCH_MAX_TOTAL_PAYLOAD_BYTES} bytes"
            )));
        }

        let digest = sha256(message.pczt());

        for previous in &messages[..index] {
            if sha256(previous.pczt()) == digest {
                return Err(RustCError::InvalidData(
                    "Zcash batch contains duplicate payloads".to_string(),
                ));
            }
            if previous.message_id() == message.message_id() {
                return Err(RustCError::InvalidData(
                    "Zcash batch contains duplicate message ids".to_string(),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(feature = "cypherpunk")]
#[no_mangle]
pub unsafe extern "C" fn check_zcash_batch_tx_cypherpunk(
    tx: PtrUR,
    ufvk: PtrString,
    seed_fingerprint: PtrBytes,
    account_index: u32,
    disabled: bool,
    checked_batch: Ptr<Ptr<ZcashCheckedPczt>>,
) -> *mut TransactionCheckResult {
    *checked_batch = core::ptr::null_mut();
    if disabled {
        return TransactionCheckResult::from(RustCError::UnsupportedTransaction(
            "Zcash requires at least 256-bit entropy (use 33-word Shamir shares)".to_string(),
        ))
        .c_ptr();
    }
    let registry = extract_ptr_with_type!(tx, ZcashSignBatch);
    let batch = match BatchSignRequest::parse(registry.get_data()) {
        Ok(batch) => batch,
        Err(e) => {
            return TransactionCheckResult::from(RustCError::InvalidData(format!(
                "invalid PCZT batch request: {e:?}"
            )))
            .c_ptr();
        }
    };
    let ufvk_text = unsafe { recover_c_char(ufvk) };
    let seed_fingerprint = extract_array!(seed_fingerprint, u8, 32);
    let seed_fingerprint = seed_fingerprint.try_into().unwrap();

    if let Err(e) = validate_zcash_batch(&batch) {
        return TransactionCheckResult::from(e).c_ptr();
    }

    let messages = batch.messages();
    let mut checked_messages = Vec::with_capacity(messages.len());
    for message in messages {
        match app_zcash::check_batch_pczt_cypherpunk(
            &MainNetwork,
            message.pczt(),
            &ufvk_text,
            seed_fingerprint,
            account_index,
        ) {
            Ok(normalized) => {
                checked_messages.push(BatchSignRequestMessage::new(
                    message.message_id().to_vec(),
                    normalized,
                ));
            }
            Err(e) => return TransactionCheckResult::from(e).c_ptr(),
        }
    }

    // Rebuild the Postcard request around the normalized PCZTs so parse/sign
    // consume exactly what was checked.
    let normalized_batch =
        BatchSignRequest::new(batch.request_id().to_vec(), checked_messages).serialize();
    *checked_batch = ZcashCheckedPczt::new(normalized_batch).c_ptr();
    TransactionCheckResult::new().c_ptr()
}

#[cfg(feature = "cypherpunk")]
#[no_mangle]
pub unsafe extern "C" fn parse_zcash_batch_tx_cypherpunk(
    checked_batch: Ptr<ZcashCheckedPczt>,
    ufvk: PtrString,
    seed_fingerprint: PtrBytes,
    disabled: bool,
) -> Ptr<TransactionParseResult<DisplayZcashBatch>> {
    if disabled {
        return TransactionParseResult::from(RustCError::UnsupportedTransaction(
            "Zcash requires at least 256-bit entropy (use 33-word Shamir shares)".to_string(),
        ))
        .c_ptr();
    }
    if checked_batch.is_null() {
        return TransactionParseResult::from(RustCError::InvalidData(
            "no checked Zcash batch available".to_string(),
        ))
        .c_ptr();
    }
    let checked = extract_ptr_with_type!(checked_batch, ZcashCheckedPczt);
    let bytes = match checked.checked_bytes() {
        Ok(bytes) => bytes,
        Err(e) => return TransactionParseResult::from(e).c_ptr(),
    };
    let batch = match BatchSignRequest::parse(bytes) {
        Ok(batch) => batch,
        Err(e) => {
            return TransactionParseResult::from(RustCError::InvalidData(format!("{e:?}"))).c_ptr()
        }
    };
    let ufvk_text = unsafe { recover_c_char(ufvk) };
    let seed_fingerprint = extract_array!(seed_fingerprint, u8, 32);
    let seed_fingerprint = seed_fingerprint.try_into().unwrap();

    #[cfg(zcash_unstable = "nu6.3")]
    if batch.messages().len() > 1 {
        // The normalized bytes were already validated in preflight, so this only
        // re-shapes the display: the split transaction plus one aggregate
        // migration summary. Any error means "not a split-plus-migrations batch";
        // fall through to the per-message review below, which renders each
        // already-checked message individually.
        if let Ok(display_items) =
            parse_zcash_batch_as_split_plus_migrations(&batch, &ufvk_text, seed_fingerprint)
        {
            return TransactionParseResult::success(DisplayZcashBatch::from(display_items).c_ptr())
                .c_ptr();
        }
    }

    let mut parsed_items = Vec::new();
    for message in batch.messages() {
        match app_zcash::parse_pczt_cypherpunk(
            &MainNetwork,
            message.pczt(),
            &ufvk_text,
            seed_fingerprint,
        ) {
            Ok(pczt) => parsed_items.push(pczt),
            Err(e) => return TransactionParseResult::from(e).c_ptr(),
        }
    }
    // FFI display structs leak if dropped (freed via free_TransactionParseResult_*,
    // not Drop), so build them only after every message has parsed.
    let display_items: Vec<DisplayPczt> = parsed_items.iter().map(DisplayPczt::from).collect();

    TransactionParseResult::success(DisplayZcashBatch::from(display_items).c_ptr()).c_ptr()
}

/// Renders a multi-message batch as the split transaction (message 0, full
/// per-output review) plus ONE aggregate migration summary covering the
/// remaining messages, instead of one full page per child. Operates on the
/// normalized bytes already validated in preflight: message 0 is parsed for
/// display, and each remaining child is folded into the summary by
/// [`app_zcash::summarize_batch_migration_pczt_cypherpunk`], which enforces the
/// strict one-spend, one-wallet-owned-output migration shape. Errors mean "not
/// a split-plus-migrations batch" and the caller falls back to the ordinary
/// per-message review.
#[cfg(all(feature = "cypherpunk", zcash_unstable = "nu6.3"))]
fn parse_zcash_batch_as_split_plus_migrations(
    batch: &BatchSignRequest,
    ufvk_text: &str,
    seed_fingerprint: &[u8; 32],
) -> app_zcash::errors::Result<Vec<DisplayPczt>> {
    let messages = batch.messages();
    // The only caller gates this behind `messages.len() > 1`, so message 0
    // (the split transaction) is always present.
    debug_assert!(messages.len() > 1);
    let mut display_items = Vec::new();

    let split_message = &messages[0];
    let split_pczt = app_zcash::parse_pczt_cypherpunk(
        &MainNetwork,
        split_message.pczt(),
        ufvk_text,
        seed_fingerprint,
    )?;

    let mut summary = app_zcash::BatchMigrationSummary::default();
    for message in messages.iter().skip(1) {
        let child = app_zcash::summarize_batch_migration_pczt_cypherpunk(
            &MainNetwork,
            message.pczt(),
            ufvk_text,
            seed_fingerprint,
        )?;
        summary.add_child(&child)?;
    }
    let summary_pczt = summary.to_parsed_pczt();

    // Materialize the FFI display structs only after every fallible step: their
    // nested C-side allocations are freed through free_TransactionParseResult_*,
    // not Drop, so building one before an Err (which sends the caller down the
    // per-message fallback) would leak it on every non-migration batch review.
    display_items.push(DisplayPczt::from(&split_pczt));
    display_items.push(DisplayPczt::from(&summary_pczt));

    Ok(display_items)
}

#[cfg(feature = "cypherpunk")]
unsafe fn sign_zcash_batch_tx_cypherpunk_dynamic(
    checked_batch: Ptr<ZcashCheckedPczt>,
    seed_fingerprint: PtrBytes,
    account_index: u32,
    disabled: bool,
    seed: PtrBytes,
    seed_len: u32,
    max_fragment_length: usize,
    allow_multipart: bool,
) -> *mut UREncodeResult {
    if disabled {
        return UREncodeResult::from(RustCError::UnsupportedTransaction(
            "Zcash requires at least 256-bit entropy (use 33-word Shamir shares)".to_string(),
        ))
        .c_ptr();
    }
    if checked_batch.is_null() {
        return UREncodeResult::from(RustCError::InvalidData(
            "no checked Zcash batch available for signing".to_string(),
        ))
        .c_ptr();
    }
    let checked = extract_ptr_with_type!(checked_batch, ZcashCheckedPczt);
    let expected_seed_fingerprint = extract_array!(seed_fingerprint, u8, 32);
    let expected_seed_fingerprint: &[u8; 32] = expected_seed_fingerprint.try_into().unwrap();
    let mut seed = extract_array_mut!(seed, u8, seed_len as usize);

    let result = match checked.checked_bytes() {
        Ok(bytes) => match BatchSignRequest::parse(bytes) {
            Ok(batch) => match calculate_seed_fingerprint(seed) {
                Ok(seed_fingerprint) => {
                    if &seed_fingerprint != expected_seed_fingerprint {
                        seed.zeroize();
                        return UREncodeResult::from(RustCError::MasterFingerprintMismatch).c_ptr();
                    }

                    let mut results = Vec::new();
                    let mut error = None;
                    for message in batch.messages() {
                        match app_zcash::sign_checked_batch_pczt(
                            &MainNetwork,
                            message.pczt(),
                            seed,
                            &seed_fingerprint,
                            account_index,
                        ) {
                            Ok(payload) => {
                                match app_zcash::extract_compact_sigs_from_signed_pczt(&payload) {
                                    Ok(compact_sigs) => {
                                        results.push(BatchSignResponseMessage::new(
                                            message.message_id().to_vec(),
                                            compact_sigs,
                                        ));
                                    }
                                    Err(e) => {
                                        error = Some(UREncodeResult::from(e).c_ptr());
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                error = Some(UREncodeResult::from(e).c_ptr());
                                break;
                            }
                        }
                    }

                    if let Some(error) = error {
                        error
                    } else {
                        let response = BatchSignResponse::new(batch.request_id().to_vec(), results);
                        match response.serialize() {
                            Ok(bytes) => {
                                let registry_type =
                                    ZcashBatchSigResult::get_registry_type().get_type();
                                if allow_multipart {
                                    UREncodeResult::encode(
                                        bytes,
                                        registry_type,
                                        max_fragment_length,
                                    )
                                    .c_ptr()
                                } else {
                                    UREncodeResult::encode_full_response(bytes, registry_type)
                                        .c_ptr()
                                }
                            }
                            Err(e) => UREncodeResult::from(RustCError::InvalidData(format!(
                                "encode PCZT batch response: {e:?}"
                            )))
                            .c_ptr(),
                        }
                    }
                }
                Err(e) => UREncodeResult::from(e).c_ptr(),
            },
            Err(e) => UREncodeResult::from(RustCError::InvalidData(format!("{e:?}"))).c_ptr(),
        },
        Err(e) => UREncodeResult::from(e).c_ptr(),
    };
    seed.zeroize();
    result
}

#[cfg(feature = "cypherpunk")]
#[no_mangle]
pub unsafe extern "C" fn sign_zcash_batch_tx_cypherpunk(
    checked_batch: Ptr<ZcashCheckedPczt>,
    seed_fingerprint: PtrBytes,
    account_index: u32,
    disabled: bool,
    seed: PtrBytes,
    seed_len: u32,
) -> *mut UREncodeResult {
    sign_zcash_batch_tx_cypherpunk_dynamic(
        checked_batch,
        seed_fingerprint,
        account_index,
        disabled,
        seed,
        seed_len,
        FRAGMENT_MAX_LENGTH_DEFAULT,
        true,
    )
}

#[cfg(feature = "cypherpunk")]
#[no_mangle]
pub unsafe extern "C" fn sign_zcash_batch_tx_cypherpunk_unlimited(
    checked_batch: Ptr<ZcashCheckedPczt>,
    seed_fingerprint: PtrBytes,
    account_index: u32,
    disabled: bool,
    seed: PtrBytes,
    seed_len: u32,
) -> *mut UREncodeResult {
    sign_zcash_batch_tx_cypherpunk_dynamic(
        checked_batch,
        seed_fingerprint,
        account_index,
        disabled,
        seed,
        seed_len,
        FRAGMENT_UNLIMITED_LENGTH,
        false,
    )
}

#[no_mangle]
pub unsafe extern "C" fn sign_zcash_tx(
    checked_pczt: Ptr<ZcashCheckedPczt>,
    seed: PtrBytes,
    seed_len: u32,
) -> *mut UREncodeResult {
    sign_zcash_tx_dynamic(checked_pczt, seed, seed_len, FRAGMENT_MAX_LENGTH_DEFAULT)
}

#[no_mangle]
pub unsafe extern "C" fn sign_zcash_tx_unlimited(
    checked_pczt: Ptr<ZcashCheckedPczt>,
    seed: PtrBytes,
    seed_len: u32,
) -> *mut UREncodeResult {
    sign_zcash_tx_dynamic(checked_pczt, seed, seed_len, FRAGMENT_UNLIMITED_LENGTH)
}

unsafe fn sign_zcash_tx_dynamic(
    checked_pczt: Ptr<ZcashCheckedPczt>,
    seed: PtrBytes,
    seed_len: u32,
    max_fragment_length: usize,
) -> *mut UREncodeResult {
    if checked_pczt.is_null() {
        return UREncodeResult::from(RustCError::InvalidData(
            "no checked PCZT available for signing".to_string(),
        ))
        .c_ptr();
    }
    let checked = extract_ptr_with_type!(checked_pczt, ZcashCheckedPczt);
    let mut seed = extract_array_mut!(seed, u8, seed_len as usize);
    let result = match checked.checked_bytes() {
        Ok(bytes) => match app_zcash::sign_pczt(bytes, seed) {
            Ok(pczt) => match ZcashPczt::new(pczt).try_into() {
                Err(e) => UREncodeResult::from(e).c_ptr(),
                Ok(v) => UREncodeResult::encode(
                    v,
                    ZcashPczt::get_registry_type().get_type(),
                    max_fragment_length,
                )
                .c_ptr(),
            },
            Err(e) => UREncodeResult::from(e).c_ptr(),
        },
        Err(e) => UREncodeResult::from(e).c_ptr(),
    };
    seed.zeroize();
    result
}

#[cfg(feature = "cypherpunk")]
unsafe fn sign_zcash_tx_cypherpunk_dynamic(
    checked_pczt: Ptr<ZcashCheckedPczt>,
    seed_fingerprint: PtrBytes,
    account_index: u32,
    disabled: bool,
    seed: PtrBytes,
    seed_len: u32,
    max_fragment_length: usize,
) -> *mut UREncodeResult {
    if disabled {
        return UREncodeResult::from(RustCError::UnsupportedTransaction(
            "Zcash requires at least 256-bit entropy (use 33-word Shamir shares)".to_string(),
        ))
        .c_ptr();
    }
    if checked_pczt.is_null() {
        return UREncodeResult::from(RustCError::InvalidData(
            "no checked PCZT available for signing".to_string(),
        ))
        .c_ptr();
    }
    let checked = extract_ptr_with_type!(checked_pczt, ZcashCheckedPczt);
    let expected_seed_fingerprint = extract_array!(seed_fingerprint, u8, 32);
    let expected_seed_fingerprint: &[u8; 32] = expected_seed_fingerprint.try_into().unwrap();
    let mut seed = extract_array_mut!(seed, u8, seed_len as usize);

    let result = match checked.checked_bytes() {
        Ok(pczt_bytes) => match calculate_seed_fingerprint(seed) {
            Ok(seed_fingerprint) => {
                if &seed_fingerprint != expected_seed_fingerprint {
                    seed.zeroize();
                    return UREncodeResult::from(RustCError::MasterFingerprintMismatch).c_ptr();
                }
                match app_zcash::sign_checked_pczt(
                    &MainNetwork,
                    pczt_bytes,
                    seed,
                    &seed_fingerprint,
                    account_index,
                ) {
                    Ok(signed_pczt) => match ZcashPczt::new(signed_pczt).try_into() {
                        Err(e) => UREncodeResult::from(e).c_ptr(),
                        Ok(v) => UREncodeResult::encode(
                            v,
                            ZcashPczt::get_registry_type().get_type(),
                            max_fragment_length,
                        )
                        .c_ptr(),
                    },
                    Err(e) => UREncodeResult::from(e).c_ptr(),
                }
            }
            Err(e) => UREncodeResult::from(e).c_ptr(),
        },
        Err(e) => UREncodeResult::from(e).c_ptr(),
    };
    seed.zeroize();
    result
}

#[cfg(feature = "cypherpunk")]
#[no_mangle]
pub unsafe extern "C" fn sign_zcash_tx_cypherpunk(
    checked_pczt: Ptr<ZcashCheckedPczt>,
    seed_fingerprint: PtrBytes,
    account_index: u32,
    disabled: bool,
    seed: PtrBytes,
    seed_len: u32,
) -> *mut UREncodeResult {
    sign_zcash_tx_cypherpunk_dynamic(
        checked_pczt,
        seed_fingerprint,
        account_index,
        disabled,
        seed,
        seed_len,
        FRAGMENT_MAX_LENGTH_DEFAULT,
    )
}

#[cfg(feature = "cypherpunk")]
#[no_mangle]
pub unsafe extern "C" fn sign_zcash_tx_cypherpunk_unlimited(
    checked_pczt: Ptr<ZcashCheckedPczt>,
    seed_fingerprint: PtrBytes,
    account_index: u32,
    disabled: bool,
    seed: PtrBytes,
    seed_len: u32,
) -> *mut UREncodeResult {
    sign_zcash_tx_cypherpunk_dynamic(
        checked_pczt,
        seed_fingerprint,
        account_index,
        disabled,
        seed,
        seed_len,
        FRAGMENT_UNLIMITED_LENGTH,
    )
}

make_free_method!(TransactionParseResult<DisplayPczt>);
make_free_method!(TransactionParseResult<DisplayZcashBatch>);

/// Frees a `ZcashCheckedPczt` previously returned through a check FFI out-param.
#[no_mangle]
pub unsafe extern "C" fn free_zcash_checked_pczt(ptr: PtrT<ZcashCheckedPczt>) {
    if ptr.is_null() {
        return;
    }
    let checked = alloc::boxed::Box::from_raw(ptr);
    checked.free();
}

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[no_mangle]
pub unsafe extern "C" fn rust_aes256_cbc_encrypt(
    data: PtrString,
    password: PtrString,
    iv: PtrBytes,
    iv_len: u32,
) -> *mut SimpleResponse<c_char> {
    let data = unsafe { recover_c_char(data) };
    let data = data.as_bytes();
    let password = unsafe { recover_c_char(password) };
    let iv = extract_array!(iv, u8, iv_len as usize);
    let key = sha256(password.as_bytes());
    let iv = GenericArray::from_slice(iv);
    let key = GenericArray::from_slice(&key);
    let ct = Aes256CbcEnc::new(key, iv).encrypt_padded_vec_mut::<Pkcs7>(data);
    SimpleResponse::success(convert_c_char(hex::encode(ct))).simple_c_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn rust_aes256_cbc_decrypt(
    hex_data: PtrString,
    password: PtrString,
    iv: PtrBytes,
    iv_len: u32,
) -> *mut SimpleResponse<c_char> {
    let hex_data = unsafe { recover_c_char(hex_data) };
    let data = hex::decode(hex_data).unwrap();
    let password = unsafe { recover_c_char(password) };
    let iv = extract_array!(iv, u8, iv_len as usize);
    let key = sha256(password.as_bytes());
    let iv = GenericArray::from_slice(iv);
    let key = GenericArray::from_slice(&key);

    match Aes256CbcDec::new(key, iv).decrypt_padded_vec_mut::<Pkcs7>(&data) {
        Ok(pt) => {
            SimpleResponse::success(convert_c_char(String::from_utf8(pt).unwrap())).simple_c_ptr()
        }
        Err(_e) => SimpleResponse::from(RustCError::InvalidHex("decrypt failed".to_string()))
            .simple_c_ptr(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_derive_iv_from_seed(
    seed: PtrBytes,
    seed_len: u32,
) -> *mut SimpleResponse<u8> {
    let seed = extract_array!(seed, u8, seed_len as usize);
    let iv_path = "m/44'/1557192335'/0'/2'/0'".to_string();
    let iv = get_private_key_by_seed(seed, &iv_path).unwrap();
    let mut iv_bytes = [0; 16];
    iv_bytes.copy_from_slice(&iv[..16]);
    SimpleResponse::success(Box::into_raw(Box::new(iv_bytes)) as *mut u8).simple_c_ptr()
}

#[cfg(test)]
mod tests {
    use alloc::{format, string::String, vec, vec::Vec};

    use super::*;

    #[cfg(feature = "cypherpunk")]
    fn test_zcash_batch(messages: Vec<BatchSignRequestMessage>) -> BatchSignRequest {
        BatchSignRequest::new(b"test-request".to_vec(), messages)
    }

    #[cfg(feature = "cypherpunk")]
    fn test_zcash_message(id: &[u8], payload: &[u8]) -> BatchSignRequestMessage {
        BatchSignRequestMessage::new(id.to_vec(), payload.to_vec())
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_accepts_valid_envelope() {
        let batch = test_zcash_batch(vec![
            test_zcash_message(b"one", b"pczt-one"),
            test_zcash_message(b"two", b"pczt-two"),
        ]);

        validate_zcash_batch(&batch).unwrap();
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_accepts_max_messages() {
        let batch = test_zcash_batch(
            (0..ZCASH_BATCH_MAX_MESSAGES)
                .map(|index| {
                    test_zcash_message(
                        format!("id-{index}").as_bytes(),
                        format!("pczt-{index}").as_bytes(),
                    )
                })
                .collect(),
        );

        validate_zcash_batch(&batch).unwrap();
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_rejects_oversized_total_payload() {
        // Three messages whose summed payloads cross the byte bound: the count
        // cap alone no longer bounds RAM, so the byte bound must reject this.
        let big = vec![0xAB; ZCASH_BATCH_MAX_TOTAL_PAYLOAD_BYTES / 2];
        let batch = test_zcash_batch(vec![
            test_zcash_message(b"one", &big),
            test_zcash_message(b"two", &[big.as_slice(), &[0x01]].concat()),
            test_zcash_message(b"three", b"pczt-three"),
        ]);

        let error = validate_zcash_batch(&batch).unwrap_err();
        assert!(matches!(
            error,
            RustCError::UnsupportedTransaction(message)
                if message.contains("payloads exceed")
        ));
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_rejects_empty_request_id_and_messages() {
        let empty_request_id =
            BatchSignRequest::new(vec![], vec![test_zcash_message(b"one", b"pczt-one")]);
        assert_eq!(
            validate_zcash_batch(&empty_request_id).unwrap_err(),
            RustCError::InvalidData("Zcash batch has no request id".to_string())
        );

        let empty_messages = test_zcash_batch(vec![]);
        assert_eq!(
            validate_zcash_batch(&empty_messages).unwrap_err(),
            RustCError::InvalidData("Zcash batch has no messages".to_string())
        );
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_rejects_invalid_message_fields() {
        let empty_message_id = test_zcash_message(b"", b"pczt-one");
        assert_eq!(
            validate_zcash_batch(&test_zcash_batch(vec![empty_message_id])).unwrap_err(),
            RustCError::InvalidData("Zcash batch message 0 has no id".to_string())
        );

        let empty_payload = test_zcash_message(b"one", b"");
        assert_eq!(
            validate_zcash_batch(&test_zcash_batch(vec![empty_payload])).unwrap_err(),
            RustCError::InvalidData("Zcash batch message 0 has no payload".to_string())
        );
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_rejects_too_many_messages() {
        let batch = test_zcash_batch(
            (0..=ZCASH_BATCH_MAX_MESSAGES)
                .map(|index| {
                    test_zcash_message(
                        format!("id-{index}").as_bytes(),
                        format!("pczt-{index}").as_bytes(),
                    )
                })
                .collect(),
        );

        assert!(matches!(
            validate_zcash_batch(&batch),
            Err(RustCError::UnsupportedTransaction(message))
                if message.contains("supports at most")
        ));
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_rejects_duplicate_ids_and_payloads() {
        let duplicate_ids = test_zcash_batch(vec![
            test_zcash_message(b"same", b"pczt-one"),
            test_zcash_message(b"same", b"pczt-two"),
        ]);
        assert_eq!(
            validate_zcash_batch(&duplicate_ids).unwrap_err(),
            RustCError::InvalidData("Zcash batch contains duplicate message ids".to_string())
        );

        let duplicate_payloads = test_zcash_batch(vec![
            test_zcash_message(b"one", b"pczt"),
            test_zcash_message(b"two", b"pczt"),
        ]);
        assert_eq!(
            validate_zcash_batch(&duplicate_payloads).unwrap_err(),
            RustCError::InvalidData("Zcash batch contains duplicate payloads".to_string())
        );
    }

    /// The batch signer fails closed: with no checked batch stored (a null
    /// container) it refuses and produces no signature UR.
    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_sign_zcash_batch_refuses_without_checked_batch() {
        for unlimited in [false, true] {
            let result = unsafe {
                if unlimited {
                    sign_zcash_batch_tx_cypherpunk_unlimited(
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        0,
                        false,
                        core::ptr::null_mut(),
                        0,
                    )
                } else {
                    sign_zcash_batch_tx_cypherpunk(
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        0,
                        false,
                        core::ptr::null_mut(),
                        0,
                    )
                }
            };
            assert!(!result.is_null());
            assert!(
                unsafe { (*result).data.is_null() },
                "signing without a checked batch must not produce a signature UR"
            );
            unsafe { Box::from_raw(result).free() };
        }
    }

    #[test]
    fn test_aes256_cbc_encrypt() {
        let mut data = convert_c_char("hello world".to_string());
        let mut password = convert_c_char("password".to_string());
        let mut seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        let iv = unsafe { rust_derive_iv_from_seed(seed.as_mut_ptr(), 64) };
        let mut iv = unsafe { slice::from_raw_parts_mut((*iv).data, 16) };
        let iv_len = 16;
        let ct = unsafe { rust_aes256_cbc_encrypt(data, password, iv.as_mut_ptr(), iv_len as u32) };
        assert!(!ct.is_null());
        let ct_vec = unsafe { (*ct).data };
        let value = unsafe { recover_c_char(ct_vec) };
        assert_eq!(value, "4989eed8515d7d3fcc16b009d8cdff9e");
    }

    #[test]
    fn test_aes256_cbc_decrypt() {
        //8dd387c3b2656d9f24ace7c3daf6fc26a1c161098460f8dddd37545fc951f9cd7da6c75c71ae52f32ceb8827eca2169ef4a643d2ccb9f01389d281a85850e2ddd100630ab1ca51310c3e6ccdd3029d0c48db18cdc971dba8f0daff9ad281b56221ffefc7d32333ea310a1f74f99dea444f8a089002cf1f0cd6a4ddf608a7b5388dc09f9417612657b9bf335a466f951547f9707dd129b3c24c900a26010f51c543eba10e9aabef7062845dc6969206b25577a352cb4d984db67c54c7615fe60769726bffa59fd8bd0b66fe29ee3c358af13cf0796c2c062bc79b73271eb0366f0536e425f8e42307ead4c695804fd3281aca5577d9a621e3a8047b14128c280c45343b5bbb783a065d94764e90ad6820fe81a200637401c256b1fb8f58a9d412d303b89c647411662907cdc55ed93adb
        //73e6ca87d5cd5622cdc747367905efe7
        //68487dc295052aa79c530e283ce698b8c6bb1b42ff0944252e1910dbecdc5425
        let mut seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        // First encrypt to get ciphertext
        let enc_data = convert_c_char("hello world".to_string());
        let enc_password = convert_c_char("password".to_string());
        let iv_resp = unsafe { rust_derive_iv_from_seed(seed.as_mut_ptr(), 64) };
        let mut iv_enc = unsafe { slice::from_raw_parts_mut((*iv_resp).data, 16) };
        let ct =
            unsafe { rust_aes256_cbc_encrypt(enc_data, enc_password, iv_enc.as_mut_ptr(), 16) };
        let ct_hex = unsafe { recover_c_char((*ct).data) };
        assert_eq!(ct_hex, "4989eed8515d7d3fcc16b009d8cdff9e");

        // Now decrypt
        let data = convert_c_char(ct_hex);
        let password = convert_c_char("password".to_string());
        let iv = unsafe { rust_derive_iv_from_seed(seed.as_mut_ptr(), 64) };
        let iv = unsafe { slice::from_raw_parts_mut((*iv).data, 16) };
        let iv_len = 16;
        let pt = unsafe { rust_aes256_cbc_decrypt(data, password, iv.as_mut_ptr(), iv_len as u32) };
        assert!(!pt.is_null());
        let ct_vec = unsafe { (*pt).data };
        let value = unsafe { recover_c_char(ct_vec) };
        assert_eq!(value, "hello world");
    }

    #[test]
    fn test_dep_aes256() {
        let mut data = b"hello world";
        let seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        let iv_path = "m/44'/1557192335'/0'/2'/0'".to_string();
        let iv = get_private_key_by_seed(&seed, &iv_path).unwrap();
        let mut iv_bytes = [0; 16];
        iv_bytes.copy_from_slice(&iv[..16]);
        let key = sha256(b"password");
        let iv = GenericArray::from_slice(&iv_bytes);
        let key = GenericArray::from_slice(&key);

        let encrypter = Aes256CbcEnc::new(key, iv);
        let decrypter = Aes256CbcDec::new(key, iv);

        let ct = encrypter.encrypt_padded_vec_mut::<Pkcs7>(data);
        let pt = decrypter.decrypt_padded_vec_mut::<Pkcs7>(&ct).unwrap();

        assert_eq!(String::from_utf8(pt).unwrap(), "hello world");
    }
}
