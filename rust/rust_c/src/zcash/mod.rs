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
use app_zcash::pczt::{sign::SpendAuthCache, structs::ParsedPczt};
#[cfg(feature = "cypherpunk")]
use app_zcash::version::KEYSTONE_FW_VERSION;
use core::slice;
use cryptoxide::hashing::sha256;
use cty::c_char;
use keystore::algorithms::{
    ed25519::slip10_ed25519::get_private_key_by_seed,
    zcash::{calculate_seed_fingerprint, derive_ufvk},
};
#[cfg(feature = "cypherpunk")]
use structs::BatchDisplayCache;
use structs::DisplayPczt;
use structs::DisplayZcashBatch;
use structs::ZcashCheckedPczt;
use ur_registry::traits::RegistryItem;
use ur_registry::zcash::zcash_batch_sig_result::ZcashBatchSigResult;
use ur_registry::zcash::zcash_pczt::ZcashPczt;
use ur_registry::zcash::zcash_sign_batch::ZcashSignBatch;
#[cfg(feature = "cypherpunk")]
use zcash_vendor::pczt::roles::signer::batch::{BatchSignRequest, BatchSignResponse};
use zcash_vendor::{pczt::Pczt, zcash_protocol::consensus::MainNetwork};
use zeroize::Zeroize;

// Batch size limits. The three sender-facing caps (wire bytes, PCZT count,
// total shielded actions) form the compatibility contract: any request within
// all three is never size-rejected, because the two internal representation
// caps below are derived to be implied by them
// (`test_normalized_cap_covers_wire_contract`).

/// Cap on the number of PCZTs in one batch request. Sender-facing.
#[cfg(feature = "cypherpunk")]
const ZCASH_BATCH_MAX_PCZTS: usize = 40;

/// Sender-facing cap on the received request: request id plus compact Postcard
/// body as transmitted, so a wallet can verify it locally before displaying
/// the QR. Checked BEFORE parse, which also bounds parse-time action-struct
/// allocation (about 2 KiB in memory per action at 122 wire bytes minimum,
/// including Vec capacity doubling) under the device heap; the previous
/// 512 KiB value was never practically scannable over QR and admitted a
/// pre-approval parse-time OOM hang.
#[cfg(feature = "cypherpunk")]
const ZCASH_BATCH_MAX_WIRE_BYTES: usize = 128 * 1024;

/// Sender-facing cap on total shielded (Orchard + Ironwood) actions across
/// the batch, countable from the compact encoding without resolving fields.
/// Memory-derived: up to three full action arrays coexist during check and
/// sign, and each in-memory action costs about 2 KiB (the inline witness
/// Option reserves 1,032 bytes even when None), so 384 keeps worst-case peaks
/// well under the usable PSRAM heap; the allocator loops forever on OOM.
#[cfg(feature = "cypherpunk")]
const ZCASH_BATCH_MAX_TOTAL_ACTIONS: usize = 384;

/// Worst-case wire growth of one action under `Pczt::resolve_fields` for the
/// pinned pczt crate: filling omitted cv_net (+32) and cmx (+32) and
/// re-encrypting an empty-memo compact ciphertext to the full 580-byte form
/// (+581). Pinned empirically by `test_resolved_action_growth_is_bounded`;
/// re-derive it whenever the pczt crate pin changes (the Cargo.lock pin is
/// the real guard - the fixture test cannot see newly added elidable fields).
#[cfg(feature = "cypherpunk")]
const ZCASH_BATCH_MAX_RESOLVED_ACTION_GROWTH: usize = 645;

/// Cap on the retained normalized envelope (post-`resolve_fields`, re-encoded
/// v2). Any request satisfying the sender-facing caps fits:
/// MAX_WIRE_BYTES + MAX_TOTAL_ACTIONS * MAX_RESOLVED_ACTION_GROWTH
///   = 131,072 + 247,680 = 378,752 <= 524,288.
/// Bounded by device memory: batch buffers live in the PSRAM heap and
/// post-parse worst-case peaks stay near 3.6 MiB at this cap.
#[cfg(feature = "cypherpunk")]
const ZCASH_BATCH_MAX_NORMALIZED_BYTES: usize = 512 * 1024;

/// Cap on the canonical per-PCZT payload sum, the defense-in-depth invariant
/// `validate_zcash_batch_payloads` checks. Standalone `Pczt::serialize()`
/// re-encodes each PCZT as v2 with its own 8-byte header, and re-encoding a
/// v1-wire PCZT additionally grows by up to 7 fixed bytes (transparent Option
/// wrap +1, sapling Option tag + anchor Option +2, orchard Option tag +
/// anchor Option + note_version +3, absent-ironwood None tag +1) plus 5 bytes
/// per action, so for any wire-legal batch:
/// MAX_WIRE_BYTES + 15 * MAX_PCZTS + 5 * MAX_TOTAL_ACTIONS
///   = 131,072 + 600 + 1,920 = 133,592.
#[cfg(feature = "cypherpunk")]
const ZCASH_BATCH_MAX_CANONICAL_PAYLOAD_BYTES: usize =
    ZCASH_BATCH_MAX_WIRE_BYTES + 15 * ZCASH_BATCH_MAX_PCZTS + 5 * ZCASH_BATCH_MAX_TOTAL_ACTIONS;

#[cfg(feature = "cypherpunk")]
const ZCASH_BATCH_REQUEST_HEADER_LEN: usize = 12;

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

/// Enforces the count, canonical byte total, and duplicate payload limits.
#[cfg(feature = "cypherpunk")]
fn validate_zcash_batch_payloads(payloads: &[Vec<u8>]) -> Result<(), RustCError> {
    if payloads.is_empty() {
        return Err(RustCError::InvalidData(
            "Zcash batch has no PCZTs".to_string(),
        ));
    }
    if payloads.len() > ZCASH_BATCH_MAX_PCZTS {
        return Err(RustCError::UnsupportedTransaction(format!(
            "Zcash batch supports at most {ZCASH_BATCH_MAX_PCZTS} PCZTs"
        )));
    }

    let mut total_payload_bytes = 0usize;
    let mut payload_digests = Vec::with_capacity(payloads.len());
    for (index, payload) in payloads.iter().enumerate() {
        if payload.is_empty() {
            return Err(RustCError::InvalidData(format!(
                "Zcash batch PCZT {index} has no payload"
            )));
        }
        total_payload_bytes = total_payload_bytes.saturating_add(payload.len());
        if total_payload_bytes > ZCASH_BATCH_MAX_CANONICAL_PAYLOAD_BYTES {
            return Err(RustCError::UnsupportedTransaction(format!(
                "Zcash batch PCZTs exceed {ZCASH_BATCH_MAX_CANONICAL_PAYLOAD_BYTES} bytes"
            )));
        }

        let digest = sha256(payload);
        if payload_digests.contains(&digest) {
            return Err(RustCError::InvalidData(
                "Zcash batch contains duplicate PCZTs".to_string(),
            ));
        }
        payload_digests.push(digest);
    }

    Ok(())
}

/// Serializes one logical batch PCZT into its canonical standalone encoding.
#[cfg(feature = "cypherpunk")]
fn serialize_batch_pczt(pczt: &Pczt) -> Result<Vec<u8>, RustCError> {
    pczt.clone()
        .serialize()
        .map_err(|e| RustCError::InvalidData(format!("encode PCZT in batch request: {e:?}")))
}

/// Applies firmware batch limits to the request body owned by the PCZT crate.
#[cfg(feature = "cypherpunk")]
fn validate_zcash_batch(batch: &BatchSignRequest) -> Result<Vec<Vec<u8>>, RustCError> {
    let payloads = batch
        .pczts()
        .iter()
        .map(serialize_batch_pczt)
        .collect::<Result<Vec<_>, _>>()?;
    validate_zcash_batch_payloads(&payloads)?;
    Ok(payloads)
}

/// Bounds one batch envelope (request id + data) against `max_bytes`,
/// reporting the applied cap in the error.
#[cfg(feature = "cypherpunk")]
fn validate_zcash_batch_envelope_with(
    request_id: &[u8],
    data: &[u8],
    max_bytes: usize,
) -> Result<(), RustCError> {
    if request_id.is_empty() {
        return Err(RustCError::InvalidData(
            "Zcash batch request id must not be empty".to_string(),
        ));
    }
    if request_id.len().saturating_add(data.len()) > max_bytes {
        return Err(RustCError::UnsupportedTransaction(format!(
            "Zcash batch request exceeds {max_bytes} bytes"
        )));
    }
    Ok(())
}

/// Bounds the retained normalized envelope (the re-encoded post-resolve
/// batch), which may legally exceed the wire cap by the resolved-field
/// growth; see `ZCASH_BATCH_MAX_NORMALIZED_BYTES`.
#[cfg(feature = "cypherpunk")]
fn validate_zcash_batch_normalized_envelope(
    request_id: &[u8],
    data: &[u8],
) -> Result<(), RustCError> {
    validate_zcash_batch_envelope_with(request_id, data, ZCASH_BATCH_MAX_NORMALIZED_BYTES)
}

/// Rejects an oversized top-level count before Postcard allocates the PCZT vector.
#[cfg(feature = "cypherpunk")]
fn validate_zcash_batch_request_count(data: &[u8]) -> Result<(), RustCError> {
    let Some(header) = data.get(..ZCASH_BATCH_REQUEST_HEADER_LEN) else {
        return Ok(());
    };

    // Leave malformed or unknown headers to the canonical parser so it retains
    // its existing error. The pinned parser recognizes PCZT versions 1 and 2.
    let pczt_version = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if &header[..8] != b"PCZB\x01\0\0\0" || !matches!(pczt_version, 1 | 2) {
        return Ok(());
    }

    // Decode only the sequence length; malformed bodies remain the canonical
    // parser's responsibility.
    let Ok((pczt_count, _)) =
        postcard::take_from_bytes::<usize>(&data[ZCASH_BATCH_REQUEST_HEADER_LEN..])
    else {
        return Ok(());
    };
    if pczt_count > ZCASH_BATCH_MAX_PCZTS {
        return Err(RustCError::UnsupportedTransaction(format!(
            "Zcash batch supports at most {ZCASH_BATCH_MAX_PCZTS} PCZTs"
        )));
    }

    Ok(())
}

/// Enforces the sender-facing cap on total shielded (Orchard + Ironwood)
/// actions in a parsed batch. Runs at wire ingress and again on the sign-time
/// reopen of the retained normalized bytes; `resolve_fields` preserves action
/// counts, so the two checks always agree.
#[cfg(feature = "cypherpunk")]
fn validate_zcash_batch_action_count(batch: &BatchSignRequest) -> Result<(), RustCError> {
    let total_actions = batch.pczts().iter().fold(0usize, |total, pczt| {
        total
            .saturating_add(pczt.orchard().actions().len())
            .saturating_add(pczt.ironwood().actions().len())
    });
    if total_actions > ZCASH_BATCH_MAX_TOTAL_ACTIONS {
        return Err(RustCError::UnsupportedTransaction(format!(
            "Zcash batch exceeds {ZCASH_BATCH_MAX_TOTAL_ACTIONS} shielded actions"
        )));
    }
    Ok(())
}

/// Parses the bounded outer registry into the PCZT crate's batch request.
///
/// `max_envelope_bytes` selects the representation-specific envelope cap:
/// `ZCASH_BATCH_MAX_WIRE_BYTES` at wire ingress and
/// `ZCASH_BATCH_MAX_NORMALIZED_BYTES` when reopening the retained normalized
/// bytes at sign time.
#[cfg(feature = "cypherpunk")]
fn parse_zcash_batch_registry(
    registry: &ZcashSignBatch,
    max_envelope_bytes: usize,
) -> Result<BatchSignRequest, RustCError> {
    validate_zcash_batch_envelope_with(
        registry.get_request_id(),
        registry.get_data(),
        max_envelope_bytes,
    )?;
    validate_zcash_batch_request_count(registry.get_data())?;
    let batch = BatchSignRequest::parse(registry.get_data())
        .map_err(|e| RustCError::InvalidData(format!("invalid PCZT batch request: {e:?}")))?;
    validate_zcash_batch_action_count(&batch)?;
    Ok(batch)
}

/// Reopens the exact normalized envelope retained by the check step.
#[cfg(feature = "cypherpunk")]
fn parse_checked_zcash_batch(data: &[u8]) -> Result<(Vec<u8>, BatchSignRequest), RustCError> {
    let registry = ZcashSignBatch::try_from(data.to_vec()).map_err(|e| {
        RustCError::InvalidData(format!("decode checked Zcash batch envelope: {e:?}"))
    })?;
    let batch = parse_zcash_batch_registry(&registry, ZCASH_BATCH_MAX_NORMALIZED_BYTES)?;
    Ok((registry.get_request_id().to_vec(), batch))
}

/// Retains normalized PCZTs and their request id as checked firmware state.
#[cfg(feature = "cypherpunk")]
fn encode_checked_zcash_batch(request_id: &[u8], data: Vec<u8>) -> Result<Vec<u8>, RustCError> {
    validate_zcash_batch_normalized_envelope(request_id, &data)?;
    ZcashSignBatch::new(request_id.to_vec(), data)
        .try_into()
        .map_err(|e| {
            RustCError::InvalidData(format!("encode normalized Zcash batch envelope: {e:?}"))
        })
}

/// Wraps the PCZT crate's signature response with its echoed request id and
/// the firmware version that produced the signatures.
#[cfg(feature = "cypherpunk")]
fn encode_zcash_batch_sig_result(
    request_id: Vec<u8>,
    data: Vec<u8>,
) -> Result<Vec<u8>, RustCError> {
    ZcashBatchSigResult::new(request_id, data, KEYSTONE_FW_VERSION.encode())
        .try_into()
        .map_err(|e| RustCError::InvalidData(format!("encode Zcash batch result envelope: {e:?}")))
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
    let batch = match parse_zcash_batch_registry(registry, ZCASH_BATCH_MAX_WIRE_BYTES) {
        Ok(batch) => batch,
        Err(e) => return TransactionCheckResult::from(e).c_ptr(),
    };
    let request_id = registry.get_request_id().to_vec();
    let ufvk_text = unsafe { recover_c_char(ufvk) };
    let seed_fingerprint = extract_array!(seed_fingerprint, u8, 32);
    let seed_fingerprint = seed_fingerprint.try_into().unwrap();

    let payloads = match validate_zcash_batch(&batch) {
        Ok(payloads) => payloads,
        Err(e) => return TransactionCheckResult::from(e).c_ptr(),
    };

    // Each check returns normalized bytes, display rows, an optional compact
    // migration classification, and the bound signability decision from the
    // same shielded action pass.
    let mut checked_pczts = Vec::with_capacity(payloads.len());
    let mut rows: Vec<ParsedPczt> = Vec::with_capacity(payloads.len());
    let mut migration_summaries = Vec::with_capacity(payloads.len());
    let mut signability = Vec::with_capacity(payloads.len());
    // One check context for the whole batch: the UFVK decode and the wallet
    // Orchard key derivation depend only on the device UFVK, so they run once
    // here instead of once per PCZT (see BatchCheckContext).
    let check_ctx = app_zcash::BatchCheckContext::new(&ufvk_text);
    for payload in payloads {
        match app_zcash::check_batch_pczt_with_display(
            &MainNetwork,
            &payload,
            &check_ctx,
            seed_fingerprint,
            account_index,
        ) {
            Ok((normalized, parsed, migration_summary, checked_signability)) => {
                let pczt = match Pczt::parse(&normalized) {
                    Ok(pczt) => pczt,
                    Err(e) => {
                        return TransactionCheckResult::from(RustCError::InvalidData(format!(
                            "parse normalized PCZT in batch request: {e:?}"
                        )))
                        .c_ptr();
                    }
                };
                checked_pczts.push(pczt);
                rows.push(parsed);
                migration_summaries.push(migration_summary);
                signability.push(checked_signability);
            }
            Err(e) => return TransactionCheckResult::from(e).c_ptr(),
        }
    }

    // Compact eligible Orchard-to-Ironwood transfers by content, independent of
    // their PCZT positions. Ambiguous batches retain every ordinary row.
    let display_rows = app_zcash::compact_checked_batch_migration_review(
        rows.into_iter().zip(migration_summaries),
    );
    let display =
        BatchDisplayCache::new(display_rows, signability, *seed_fingerprint, account_index);

    // Rebuild the Postcard request around the normalized PCZTs so parse/sign
    // consume exactly what was checked, then preserve the outer request id for
    // the eventual batch result.
    let normalized_request = match BatchSignRequest::new(checked_pczts).serialize() {
        Ok(bytes) => bytes,
        Err(e) => {
            return TransactionCheckResult::from(RustCError::InvalidData(format!(
                "encode normalized PCZT batch request: {e:?}"
            )))
            .c_ptr();
        }
    };
    let normalized_batch = match encode_checked_zcash_batch(&request_id, normalized_request) {
        Ok(bytes) => bytes,
        Err(e) => return TransactionCheckResult::from(e).c_ptr(),
    };
    *checked_batch = ZcashCheckedPczt::new_with_display(normalized_batch, display).c_ptr();
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
    // `ufvk` and `seed_fingerprint` are retained for ABI/signature stability but
    // unused now that parse converts the display rows the check pass cached
    // instead of re-decrypting every output.
    let _ = (ufvk, seed_fingerprint);
    let checked = extract_ptr_with_type!(checked_batch, ZcashCheckedPczt);
    if let Err(e) = checked.checked_bytes() {
        return TransactionParseResult::from(e).c_ptr();
    }
    if checked.display.is_null() {
        // Can't happen for a batch checked container (the batch check always
        // stores a cache), but fail closed rather than silently re-deriving.
        return TransactionParseResult::from(RustCError::InvalidData(
            "no checked Zcash batch display available".to_string(),
        ))
        .c_ptr();
    }
    // Convert the cached rows into fresh owned FFI structs. There is no fallible
    // step after the first `DisplayPczt` is built, so the "materialize only after
    // all fallible steps" leak-safety is trivially preserved.
    let display_items = batch_display_items(&*checked.display);

    TransactionParseResult::success(DisplayZcashBatch::from(display_items).c_ptr()).c_ptr()
}

/// Converts the cached review rows into fresh FFI display structs. The cache
/// already contains either the compacted review or all ordinary PCZT rows.
#[cfg(feature = "cypherpunk")]
fn batch_display_items(cache: &BatchDisplayCache) -> Vec<DisplayPczt> {
    cache.rows().iter().map(DisplayPczt::from).collect()
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
    if checked.display.is_null() {
        return UREncodeResult::from(RustCError::InvalidData(
            "no checked Zcash batch signability available".to_string(),
        ))
        .c_ptr();
    }
    let expected_seed_fingerprint = extract_array!(seed_fingerprint, u8, 32);
    let expected_seed_fingerprint: &[u8; 32] = expected_seed_fingerprint.try_into().unwrap();
    let checked_signability =
        match (&*checked.display).signability(expected_seed_fingerprint, account_index) {
            Some(signability) => signability,
            None => {
                return UREncodeResult::from(RustCError::InvalidData(
                    "checked Zcash batch signing context mismatch".to_string(),
                ))
                .c_ptr();
            }
        };
    let mut seed = extract_array_mut!(seed, u8, seed_len as usize);

    let result = match checked.checked_bytes() {
        Ok(bytes) => match parse_checked_zcash_batch(bytes) {
            Ok((request_id, batch)) => match calculate_seed_fingerprint(seed) {
                Ok(seed_fingerprint) => {
                    if &seed_fingerprint != expected_seed_fingerprint {
                        seed.zeroize();
                        return UREncodeResult::from(RustCError::MasterFingerprintMismatch).c_ptr();
                    }
                    if checked_signability.len() != batch.pczts().len() {
                        seed.zeroize();
                        return UREncodeResult::from(RustCError::InvalidData(
                            "checked Zcash batch signability count mismatch".to_string(),
                        ))
                        .c_ptr();
                    }

                    let mut results = Vec::new();
                    let mut error = None;
                    // One scrubbed spend-auth slot for the whole request. The
                    // selected account key stays cached across every batch PCZT.
                    let ask_cache = SpendAuthCache::new();
                    // Preserve request order and emit nothing unless every PCZT signs.
                    for (pczt, checked_signability) in batch.pczts().iter().zip(checked_signability)
                    {
                        let payload = match serialize_batch_pczt(pczt) {
                            Ok(payload) => payload,
                            Err(e) => {
                                error = Some(UREncodeResult::from(e).c_ptr());
                                break;
                            }
                        };
                        match app_zcash::sign_checked_batch_pczt_with_cached_signability(
                            &payload,
                            checked_signability,
                            seed,
                            &ask_cache,
                        ) {
                            Ok(payload) => {
                                match app_zcash::extract_compact_sigs_from_signed_pczt(&payload) {
                                    Ok(compact_sigs) => {
                                        results.push(compact_sigs);
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
                    // End the secret's lifetime before response serialization
                    // and UR encoding, while retaining it across every PCZT.
                    drop(ask_cache);

                    if let Some(error) = error {
                        error
                    } else {
                        let response = BatchSignResponse::new(results);
                        match response.serialize() {
                            Ok(bytes) => {
                                let registry_type =
                                    ZcashBatchSigResult::get_registry_type().get_type();
                                match encode_zcash_batch_sig_result(request_id, bytes) {
                                    Ok(cbor) => {
                                        if allow_multipart {
                                            UREncodeResult::encode(
                                                cbor,
                                                registry_type,
                                                max_fragment_length,
                                            )
                                            .c_ptr()
                                        } else {
                                            UREncodeResult::encode_full_response(
                                                cbor,
                                                registry_type,
                                            )
                                            .c_ptr()
                                        }
                                    }
                                    Err(e) => UREncodeResult::from(e).c_ptr(),
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
            Err(e) => UREncodeResult::from(e).c_ptr(),
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
    fn test_zcash_payloads(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| format!("pczt-{index}").into_bytes())
            .collect()
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_accepts_valid_payloads() {
        let payloads = test_zcash_payloads(2);

        validate_zcash_batch_payloads(&payloads).unwrap();
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_accepts_max_pczts() {
        let payloads = test_zcash_payloads(ZCASH_BATCH_MAX_PCZTS);

        validate_zcash_batch_payloads(&payloads).unwrap();
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_rejects_oversized_total_payload() {
        // Three PCZTs whose summed payloads cross the byte bound: the count cap
        // alone no longer bounds RAM, so the byte bound must reject this.
        let big = vec![0xAB; ZCASH_BATCH_MAX_CANONICAL_PAYLOAD_BYTES / 2];
        let payloads = vec![big.clone(), [big.as_slice(), &[0x01]].concat(), vec![0x02]];

        let error = validate_zcash_batch_payloads(&payloads).unwrap_err();
        assert!(matches!(
            error,
            RustCError::UnsupportedTransaction(message)
                if message.contains("PCZTs exceed")
        ));
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_rejects_empty_batch_and_payload() {
        assert_eq!(
            validate_zcash_batch_payloads(&[]).unwrap_err(),
            RustCError::InvalidData("Zcash batch has no PCZTs".to_string())
        );

        assert_eq!(
            validate_zcash_batch_payloads(&[vec![]]).unwrap_err(),
            RustCError::InvalidData("Zcash batch PCZT 0 has no payload".to_string())
        );
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_rejects_too_many_pczts() {
        let payloads = test_zcash_payloads(ZCASH_BATCH_MAX_PCZTS + 1);

        assert!(matches!(
            validate_zcash_batch_payloads(&payloads),
            Err(RustCError::UnsupportedTransaction(message))
                if message.contains("supports at most")
        ));
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_rejects_duplicate_pczts() {
        let duplicate_payloads = vec![b"pczt".to_vec(), b"pczt".to_vec()];
        assert_eq!(
            validate_zcash_batch_payloads(&duplicate_payloads).unwrap_err(),
            RustCError::InvalidData("Zcash batch contains duplicate PCZTs".to_string())
        );
    }

    #[cfg(feature = "cypherpunk")]
    fn empty_batch_request() -> Vec<u8> {
        BatchSignRequest::new(vec![]).serialize().unwrap()
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_checked_zcash_batch_preserves_request_id() {
        let request_id = vec![0xaa, 0xbb];
        let checked = encode_checked_zcash_batch(&request_id, empty_batch_request()).unwrap();

        let (decoded_request_id, batch) = parse_checked_zcash_batch(&checked).unwrap();

        assert_eq!(decoded_request_id, request_id);
        assert!(batch.pczts().is_empty());
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_zcash_batch_rejects_invalid_envelope_bounds() {
        let registry = ZcashSignBatch::new(vec![], empty_batch_request());

        assert_eq!(
            parse_zcash_batch_registry(&registry, ZCASH_BATCH_MAX_WIRE_BYTES).unwrap_err(),
            RustCError::InvalidData("Zcash batch request id must not be empty".to_string())
        );

        let oversized = ZcashSignBatch::new(vec![0xaa], vec![0; ZCASH_BATCH_MAX_WIRE_BYTES]);
        assert!(matches!(
            parse_zcash_batch_registry(&oversized, ZCASH_BATCH_MAX_WIRE_BYTES),
            Err(RustCError::UnsupportedTransaction(message))
                if message.contains("batch request exceeds")
        ));
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_zcash_batch_rejects_count_before_parse() {
        let mut request = empty_batch_request();
        request[ZCASH_BATCH_REQUEST_HEADER_LEN] = ZCASH_BATCH_MAX_PCZTS as u8;
        validate_zcash_batch_request_count(&request).unwrap();

        let mut overlong_small_count = empty_batch_request();
        overlong_small_count[ZCASH_BATCH_REQUEST_HEADER_LEN] = 0x81;
        overlong_small_count.push(0);
        validate_zcash_batch_request_count(&overlong_small_count).unwrap();

        // The body declares 41 PCZTs but omits them. Reaching the count error
        // proves the limit is enforced before the full request is parsed.
        request[ZCASH_BATCH_REQUEST_HEADER_LEN] += 1;
        let registry = ZcashSignBatch::new(vec![0xaa], request);
        assert_eq!(
            parse_zcash_batch_registry(&registry, ZCASH_BATCH_MAX_WIRE_BYTES).unwrap_err(),
            RustCError::UnsupportedTransaction(format!(
                "Zcash batch supports at most {ZCASH_BATCH_MAX_PCZTS} PCZTs"
            ))
        );
    }

    /// One-action PCZT with cv_net, cmx, and the ciphertext elided to the
    /// compact memo form, generated with the pinned pczt crate (387 bytes).
    /// Resolving it re-derives all three fields at their maximum growth.
    #[cfg(feature = "cypherpunk")]
    const ELIDED_ONE_ACTION_PCZT: [u8; 387] = [
        0x50, 0x43, 0x5a, 0x54, 0x02, 0x00, 0x00, 0x00, 0x05, 0x8a, 0xce, 0x9c, 0xb5, 0x02, 0xd5,
        0xa0, 0x9c, 0xc7, 0x0c, 0x00, 0x80, 0xad, 0xe2, 0x04, 0x85, 0x01, 0x83, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xad, 0x1c, 0x11, 0xf6, 0x15, 0x5e, 0xc8, 0xf3,
        0xca, 0xbd, 0x63, 0xda, 0x1d, 0x28, 0x6f, 0x73, 0x08, 0x03, 0x60, 0x9f, 0xc4, 0x9e, 0x2a,
        0xb4, 0xf2, 0xde, 0xa2, 0xc7, 0x4a, 0xbb, 0x65, 0x09, 0x00, 0x00, 0x01, 0xa0, 0x8d, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79, 0x4b, 0xd5, 0x9f, 0x8c, 0x9f,
        0xf4, 0x67, 0xda, 0x4d, 0xa5, 0x9b, 0x5d, 0xf7, 0x01, 0x5d, 0x82, 0x63, 0xe3, 0xc3, 0x43,
        0xee, 0x83, 0x22, 0xe9, 0xd1, 0x4d, 0x9f, 0x12, 0x19, 0x50, 0x0b, 0x01, 0x00, 0x50, 0x07,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x07, 0x07, 0x07, 0x07, 0x01, 0xcc, 0x36, 0x60, 0x19, 0x59, 0x21, 0x3b, 0x6b, 0x0c, 0xdb,
        0x96, 0xa7, 0x5c, 0x17, 0xc3, 0xa6, 0x68, 0xa9, 0x7f, 0x0d, 0x6a, 0x8c, 0x5c, 0xe1, 0x64,
        0xa5, 0x18, 0xea, 0x9b, 0xa9, 0xa5, 0x0e, 0xa7, 0x51, 0x91, 0xfd, 0x86, 0x1b, 0x0f, 0xf1,
        0x0e, 0x62, 0xb0, 0x01, 0xa0, 0x8d, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// Appends the Postcard LEB128 varint encoding of `value`.
    #[cfg(feature = "cypherpunk")]
    fn put_postcard_varint(bytes: &mut Vec<u8>, mut value: u64) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                bytes.push(byte);
                break;
            }
            bytes.push(byte | 0x80);
        }
    }

    /// A 32-byte test nullifier varied by `index` so fixture actions stay
    /// distinct and batch duplicate detection never trips.
    #[cfg(feature = "cypherpunk")]
    fn test_nullifier(index: u32) -> [u8; 32] {
        let mut nullifier = [0x11; 32];
        nullifier[..4].copy_from_slice(&index.to_le_bytes());
        nullifier
    }

    /// Postcard encoding of a minimal `Global`: v5 tx version, Nu6 branch id,
    /// mainnet coin type, no fallback lock time, zero expiry, empty
    /// proprietary map.
    #[cfg(feature = "cypherpunk")]
    fn test_global_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        put_postcard_varint(&mut bytes, 5); // tx_version
        put_postcard_varint(&mut bytes, 0x26A7_270A); // version_group_id (v5)
        put_postcard_varint(&mut bytes, 0xC8E7_1055); // consensus_branch_id (Nu6)
        bytes.push(0x00); // fallback_lock_time: None
        put_postcard_varint(&mut bytes, 0); // expiry_height
        put_postcard_varint(&mut bytes, 133); // coin_type
        bytes.push(0x00); // tx_modifiable
        bytes.push(0x00); // proprietary: empty map
        bytes
    }

    /// Minimal parseable v2 Orchard action (122 bytes): mandatory nullifier,
    /// rk, and ephemeral key present; every optional field elided; empty-memo
    /// compact ciphertext. Parseable without being resolvable, which is all
    /// the count- and size-shaped fixtures need.
    #[cfg(feature = "cypherpunk")]
    fn v2_min_action_bytes(index: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(0x00); // cv_net: None
        bytes.push(0x01); // spend.nullifier: Some
        bytes.extend_from_slice(&test_nullifier(index));
        bytes.push(0x01); // spend.rk: Some
        bytes.extend_from_slice(&[0x22; 32]);
        bytes.extend_from_slice(&[0x00; 10]); // remaining spend Options: None
        bytes.push(0x00); // spend.proprietary: empty map
        bytes.push(0x00); // output.cmx: None
        bytes.extend_from_slice(&[0x33; 32]); // output.ephemeral_key
        bytes.extend_from_slice(&[0x01, 0x00]); // enc_ciphertext: empty MemoPlaintext
        bytes.push(0x00); // output.out_ciphertext: empty
        bytes.extend_from_slice(&[0x00; 6]); // remaining output Options: None
        bytes.push(0x00); // output.proprietary: empty map
        bytes.push(0x00); // rcv: None
        bytes
    }

    /// Headerless v2 PCZT body: minimal global, empty transparent and Sapling
    /// slots, an Orchard bundle holding `actions` plus an optional zkproof pad
    /// (arbitrary bytes that round-trip verbatim, letting size-targeted
    /// fixtures stay canonical), and an empty Ironwood slot.
    #[cfg(feature = "cypherpunk")]
    fn v2_pczt_body_bytes(actions: &[Vec<u8>], zkproof_pad: usize) -> Vec<u8> {
        let mut bytes = test_global_bytes();
        bytes.push(0x00); // transparent: None
        bytes.push(0x00); // sapling: None
        bytes.push(0x01); // orchard: Some
        put_postcard_varint(&mut bytes, actions.len() as u64);
        for action in actions {
            bytes.extend_from_slice(action);
        }
        bytes.push(0x03); // flags: spends + outputs enabled
        bytes.extend_from_slice(&[0x00, 0x00]); // value_sum: (0, false)
        bytes.push(0x00); // anchor: None
        bytes.push(0x00); // note_version: V2
        if zkproof_pad == 0 {
            bytes.push(0x00); // zkproof: None
        } else {
            bytes.push(0x01); // zkproof: Some
            put_postcard_varint(&mut bytes, zkproof_pad as u64);
            bytes.extend(core::iter::repeat(0x5a).take(zkproof_pad));
        }
        bytes.push(0x00); // bsk: None
        bytes.push(0x00); // ironwood: None
        bytes
    }

    /// `BatchSignRequest` wire bytes: the 12-byte header (magic, batch
    /// version, shared PCZT version) plus the Postcard body (PCZT count and
    /// headerless per-version PCZT bodies).
    #[cfg(feature = "cypherpunk")]
    fn batch_request_bytes(pczt_version: u32, bodies: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = b"PCZB".to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&pczt_version.to_le_bytes());
        put_postcard_varint(&mut bytes, bodies.len() as u64);
        for body in bodies {
            bytes.extend_from_slice(body);
        }
        bytes
    }

    /// Builds a v2 batch whose `spread` entries give each PCZT's action
    /// count, with globally unique nullifiers and per-PCZT zkproof padding.
    #[cfg(feature = "cypherpunk")]
    fn v2_batch_bytes(spread: &[usize], zkproof_pad: usize) -> Vec<u8> {
        let mut next_index = 0u32;
        let bodies = spread
            .iter()
            .map(|&count| {
                let actions = (0..count)
                    .map(|_| {
                        let action = v2_min_action_bytes(next_index);
                        next_index += 1;
                        action
                    })
                    .collect::<Vec<_>>();
                v2_pczt_body_bytes(&actions, zkproof_pad)
            })
            .collect::<Vec<_>>();
        batch_request_bytes(2, &bodies)
    }

    /// Minimal v1 Orchard action (181 bytes): v1 stores cv_net, nullifier,
    /// rk, cmx, and the ciphertexts as mandatory raw fields, so v1 wire
    /// cannot elide them - its re-encoding growth is the fixed +5 structural
    /// tag bytes per action rather than resolve growth.
    #[cfg(feature = "cypherpunk")]
    fn v1_min_action_bytes(index: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x44; 32]); // cv_net (raw)
        bytes.extend_from_slice(&test_nullifier(index)); // spend.nullifier (raw)
        bytes.extend_from_slice(&[0x22; 32]); // spend.rk (raw)
        bytes.extend_from_slice(&[0x00; 10]); // optional spend fields: None
        bytes.push(0x00); // spend.proprietary: empty map
        bytes.extend_from_slice(&[0x55; 32]); // output.cmx (raw)
        bytes.extend_from_slice(&[0x33; 32]); // output.ephemeral_key
        bytes.push(0x00); // output.enc_ciphertext: empty vec
        bytes.push(0x00); // output.out_ciphertext: empty vec
        bytes.extend_from_slice(&[0x00; 6]); // optional output fields: None
        bytes.push(0x00); // output.proprietary: empty map
        bytes.push(0x00); // rcv: None
        bytes
    }

    /// Headerless v1 PCZT body carrying every fixed v1-to-v2 growth term:
    /// one minimal transparent output (defeats the v2 empty-bundle omission),
    /// an anchored-but-empty Sapling bundle (zero extra v1 wire cost - the v1
    /// anchor is a mandatory `[u8; 32]` either way - but non-default, so v2
    /// keeps the bundle), and a v1 Orchard bundle with `actions` plus an
    /// optional zkproof pad.
    #[cfg(feature = "cypherpunk")]
    fn v1_pczt_body_bytes(actions: &[Vec<u8>], zkproof_pad: usize) -> Vec<u8> {
        let mut bytes = test_global_bytes();
        bytes.push(0x00); // transparent.inputs: empty
        put_postcard_varint(&mut bytes, 1); // transparent.outputs: one entry
        put_postcard_varint(&mut bytes, 0); // output.value
        bytes.push(0x00); // output.script_pubkey: empty
        bytes.push(0x00); // output.redeem_script: None
        bytes.push(0x00); // output.bip32_derivation: empty map
        bytes.push(0x00); // output.user_address: None
        bytes.push(0x00); // output.proprietary: empty map
        bytes.push(0x00); // sapling.spends: empty
        bytes.push(0x00); // sapling.outputs: empty
        bytes.push(0x00); // sapling.value_sum: 0
        bytes.extend_from_slice(&[0x77; 32]); // sapling.anchor (raw, non-default)
        bytes.push(0x00); // sapling.bsk: None
        put_postcard_varint(&mut bytes, actions.len() as u64);
        for action in actions {
            bytes.extend_from_slice(action);
        }
        bytes.push(0x03); // orchard.flags
        bytes.extend_from_slice(&[0x00, 0x00]); // orchard.value_sum: (0, false)
        bytes.extend_from_slice(&[0x66; 32]); // orchard.anchor (raw)
        if zkproof_pad == 0 {
            bytes.push(0x00); // zkproof: None
        } else {
            bytes.push(0x01); // zkproof: Some
            put_postcard_varint(&mut bytes, zkproof_pad as u64);
            bytes.extend(core::iter::repeat(0x5a).take(zkproof_pad));
        }
        bytes.push(0x00); // orchard.bsk: None
        bytes
    }

    /// Sums shielded (Orchard + Ironwood) actions over a parsed batch.
    #[cfg(feature = "cypherpunk")]
    fn count_batch_actions(batch: &BatchSignRequest) -> usize {
        batch
            .pczts()
            .iter()
            .map(|pczt| pczt.orchard().actions().len() + pczt.ironwood().actions().len())
            .sum()
    }

    /// Pins `ZCASH_BATCH_MAX_RESOLVED_ACTION_GROWTH` to the pinned pczt
    /// crate's measured behavior, and pins that `resolve_fields` never
    /// changes the action count.
    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_resolved_action_growth_is_bounded() {
        let mut pczt = Pczt::parse(&ELIDED_ONE_ACTION_PCZT).unwrap();
        assert_eq!(pczt.orchard().actions().len(), 1);

        pczt.resolve_fields().unwrap();
        assert_eq!(pczt.orchard().actions().len(), 1);

        let normalized = serialize_batch_pczt(&pczt).unwrap();
        assert_eq!(
            normalized.len() - ELIDED_ONE_ACTION_PCZT.len(),
            ZCASH_BATCH_MAX_RESOLVED_ACTION_GROWTH
        );
    }

    /// CI-checked size theorem (with `test_resolved_action_growth_is_bounded`):
    /// any batch within the sender-facing wire, PCZT, and action caps fits the
    /// normalized retention cap, and its canonical payload sum fits the
    /// canonical cap - so wire-legal batches are never size-rejected.
    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_normalized_cap_covers_wire_contract() {
        assert!(
            ZCASH_BATCH_MAX_WIRE_BYTES
                + ZCASH_BATCH_MAX_TOTAL_ACTIONS * ZCASH_BATCH_MAX_RESOLVED_ACTION_GROWTH
                <= ZCASH_BATCH_MAX_NORMALIZED_BYTES
        );
        // 15 per PCZT = 8 (standalone header) + 7 (fixed v1-to-v2 growth:
        // transparent Option wrap +1, sapling Option tag + anchor Option +2,
        // orchard Option tag + anchor Option + note_version +3, ironwood None
        // tag +1); 5 per action = the v1-to-v2 Option/enum tags.
        assert!(
            ZCASH_BATCH_MAX_CANONICAL_PAYLOAD_BYTES
                >= ZCASH_BATCH_MAX_WIRE_BYTES
                    + 15 * ZCASH_BATCH_MAX_PCZTS
                    + 5 * ZCASH_BATCH_MAX_TOTAL_ACTIONS
        );

        // Empirical v1 witness: a wire-legal v1 batch whose canonical payload
        // sum lands ABOVE the wire cap must still be accepted. Two 16-action
        // PCZTs carry every fixed growth term; the zkproof pad sizes the
        // request just under the wire cap.
        let first_actions: Vec<Vec<u8>> = (0..16).map(v1_min_action_bytes).collect();
        let second_actions: Vec<Vec<u8>> = (16..32).map(v1_min_action_bytes).collect();
        let unpadded = batch_request_bytes(
            1,
            &[
                v1_pczt_body_bytes(&first_actions, 0),
                v1_pczt_body_bytes(&second_actions, 0),
            ],
        );
        // Room for the 1-byte request id, minus the 3-byte zkproof length
        // varint replacing the elided None tag.
        let target_wire = ZCASH_BATCH_MAX_WIRE_BYTES - 9;
        let pad = target_wire - unpadded.len() - 3;
        let request = batch_request_bytes(
            1,
            &[
                v1_pczt_body_bytes(&first_actions, pad),
                v1_pczt_body_bytes(&second_actions, 0),
            ],
        );
        assert_eq!(request.len(), target_wire);

        let registry = ZcashSignBatch::new(vec![0xaa], request.clone());
        let batch = parse_zcash_batch_registry(&registry, ZCASH_BATCH_MAX_WIRE_BYTES).unwrap();
        let payloads = validate_zcash_batch(&batch).unwrap();
        let canonical_total: usize = payloads.iter().map(|payload| payload.len()).sum();

        // 13-byte batch header amortized away; +15 fixed bytes per PCZT and
        // +5 per action, exactly the canonical cap's slack terms.
        assert_eq!(canonical_total, request.len() - 13 + 15 * 2 + 5 * 32);
        assert!(canonical_total > ZCASH_BATCH_MAX_WIRE_BYTES);
        assert!(canonical_total <= ZCASH_BATCH_MAX_CANONICAL_PAYLOAD_BYTES);
    }

    /// The action cap rejects one action past the limit and accepts the
    /// limit, counting across every PCZT in the batch.
    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_validate_zcash_batch_action_count_rejects_excess() {
        let over = v2_batch_bytes(&[192, 193], 0);
        let registry = ZcashSignBatch::new(vec![0xaa], over);
        assert_eq!(
            parse_zcash_batch_registry(&registry, ZCASH_BATCH_MAX_WIRE_BYTES).unwrap_err(),
            RustCError::UnsupportedTransaction(format!(
                "Zcash batch exceeds {ZCASH_BATCH_MAX_TOTAL_ACTIONS} shielded actions"
            ))
        );

        let at_cap = v2_batch_bytes(&[192, 192], 0);
        let registry = ZcashSignBatch::new(vec![0xaa], at_cap);
        let batch = parse_zcash_batch_registry(&registry, ZCASH_BATCH_MAX_WIRE_BYTES).unwrap();
        assert_eq!(batch.pczts().len(), 2);
        assert_eq!(count_batch_actions(&batch), ZCASH_BATCH_MAX_TOTAL_ACTIONS);
    }

    /// Regression for the field failure: a batch envelope larger than the
    /// wire cap but within the normalized cap is retained and reopened
    /// intact, with its action count preserved across the round-trip. The
    /// fixture sits in the size class only normalized batches reach (at the
    /// PCZT and action caps, near the theorem's 378,752-byte maximum), which
    /// the retention envelope had never traversed before this change.
    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_encode_checked_zcash_batch_allows_resolved_growth() {
        let mut spread = vec![10usize; 24];
        spread.extend_from_slice(&[9; 16]); // 24 * 10 + 16 * 9 = 384 actions
        assert_eq!(spread.len(), ZCASH_BATCH_MAX_PCZTS);
        let data = v2_batch_bytes(&spread, 8_100);
        assert!(data.len() > ZCASH_BATCH_MAX_WIRE_BYTES);
        assert!(data.len() > 360_000);
        assert!(data.len() <= ZCASH_BATCH_MAX_NORMALIZED_BYTES);

        let before = BatchSignRequest::parse(&data).unwrap();
        assert_eq!(count_batch_actions(&before), ZCASH_BATCH_MAX_TOTAL_ACTIONS);

        let request_id = vec![0xaa, 0xbb];
        let checked = encode_checked_zcash_batch(&request_id, data).unwrap();
        let (decoded_request_id, batch) = parse_checked_zcash_batch(&checked).unwrap();

        assert_eq!(decoded_request_id, request_id);
        assert_eq!(count_batch_actions(&batch), ZCASH_BATCH_MAX_TOTAL_ACTIONS);
    }

    /// The retention path still fails closed above the normalized cap.
    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_encode_checked_zcash_batch_rejects_above_normalized_cap() {
        let oversized = vec![0x00; ZCASH_BATCH_MAX_NORMALIZED_BYTES];
        assert!(matches!(
            encode_checked_zcash_batch(&[0xaa], oversized),
            Err(RustCError::UnsupportedTransaction(message))
                if message.contains(&format!("exceeds {ZCASH_BATCH_MAX_NORMALIZED_BYTES} bytes"))
        ));
    }

    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_encode_zcash_batch_sig_result_wraps_response_with_firmware_version() {
        use zcash_vendor::{orchard::ValuePool, pczt::roles::signer::SpendAuthSignature};

        let request_id = vec![0xaa, 0xbb];
        let response = BatchSignResponse::new(vec![
            vec![SpendAuthSignature::from_parts(
                ValuePool::Orchard,
                0,
                [0x11; 64],
            )],
            vec![SpendAuthSignature::from_parts(
                ValuePool::Ironwood,
                3,
                [0x22; 64],
            )],
        ]);
        let response_bytes = response.serialize().unwrap();

        let cbor =
            encode_zcash_batch_sig_result(request_id.clone(), response_bytes.clone()).unwrap();
        let decoded = ZcashBatchSigResult::try_from(cbor).unwrap();

        assert_eq!(decoded.get_request_id(), request_id);
        assert_eq!(decoded.get_data(), response_bytes);
        assert_eq!(
            decoded.get_firmware_version(),
            &KEYSTONE_FW_VERSION.encode()
        );
        assert_eq!(
            BatchSignResponse::parse(decoded.get_data()).unwrap(),
            response
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

    /// A minimal display row; the real content parity is covered by the app-level
    /// tests, so this only exercises the rust_c cache plumbing.
    #[cfg(feature = "cypherpunk")]
    fn sample_parsed_pczt() -> ParsedPczt {
        ParsedPczt::new(
            None,
            None,
            None,
            "1 ZEC".to_string(),
            "0.0001 ZEC".to_string(),
            false,
        )
    }

    /// The batch parse FFI reads the display cache the check stored and returns one
    /// display per cached row without re-deriving anything. The item count is
    /// asserted through the conversion helper (`TransactionParseResult::data` is
    /// private), then the full FFI is driven end-to-end for the no-crash path.
    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_parse_zcash_batch_reads_display_cache() {
        let items = batch_display_items(&BatchDisplayCache::new(
            vec![
                sample_parsed_pczt(),
                sample_parsed_pczt(),
                sample_parsed_pczt(),
            ],
            Vec::new(),
            [0; 32],
            0,
        ));
        assert_eq!(
            items.len(),
            3,
            "the cache must yield one display per review row"
        );
        for item in &items {
            unsafe { item.free() };
        }

        let cache = BatchDisplayCache::new(
            vec![sample_parsed_pczt(), sample_parsed_pczt()],
            Vec::new(),
            [0; 32],
            0,
        );
        let checked_ptr =
            ZcashCheckedPczt::new_with_display(b"normalized-batch-bytes".to_vec(), cache).c_ptr();
        let result = unsafe {
            parse_zcash_batch_tx_cypherpunk(
                checked_ptr,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                false,
            )
        };
        assert!(
            !result.is_null(),
            "parse must produce a result for a cache-bearing container"
        );
        unsafe {
            Box::from_raw(result).free();
            free_zcash_checked_pczt(checked_ptr);
        }
    }

    /// Freeing a checked container that carries a display cache must free both the
    /// bytes and the cache exactly once (reaching the end without an allocator
    /// abort is the assertion).
    #[cfg(feature = "cypherpunk")]
    #[test]
    fn test_free_cache_bearing_container_is_clean() {
        let cache = BatchDisplayCache::new(
            vec![sample_parsed_pczt(), sample_parsed_pczt()],
            Vec::new(),
            [0; 32],
            0,
        );
        let checked_ptr =
            ZcashCheckedPczt::new_with_display(b"normalized-batch-bytes".to_vec(), cache).c_ptr();
        unsafe { free_zcash_checked_pczt(checked_ptr) };
    }
}
