## Keystone Zcash UR Registries

This protocol is based on the [Uniform Resources](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md). It describes the data schemas (UR Registries) used in Zcash integrations.

### Introduction

Keystone's QR workflow involves two main steps: linking the wallet and signing data, broken down into three sub-steps:

1. **Wallet Linking:** Keystone generates a QR code with public key info for the Watch-Only wallet to scan and import.
2. **Transaction Creation:** The Watch-Only wallet creates a transaction and generates a QR code for Keystone to scan, parse, and display.
3. **Signing Authorization:** Keystone signs the transaction, displays the result as a QR code for the Watch-Only wallet to scan and broadcast.

Two UR Registries are needed for these steps, utilizing the Partially Created Zcash Transaction structure.

### Zcash Accounts

#### Unified Full Viewing Key (UFVK)

UFVK is a standard account expression format in Zcash as per [ZIP-316](https://zips.z.cash/zip-0316). It consists of:

1. Transparent
2. Sprout
3. Sapling
4. Orchard

This protocol focuses on the Transparent, Orchard, and Ironwood components.

#### CDDL for Zcash Accounts

The specification uses CDDL;

```cddl
zcash-accounts = {
    seed-fingerprint: bytes.32, ; the seed fingerprint specified by ZIP-32 to identify the wallet
    accounts: [+ zcash-ufvk],
}

zcash-ufvk = {
    ufvk: text, ; the standard UFVK expression, it may includes transparent, orchard and sapling FVK or not;
    index: uint32, ; the account index
    ? name: text,
}

```

`zcash-ufvk` describes the UFVK of a Zcash account. Each seed has multiple accounts with different indexes. For index 0, `zcash-ufvk` should contain a BIP32 extended public key with path `M/44'/133'/0'` (transparent) and an Orchard FVK with path `M_orchard/32'/133'/0'` (Orchard).

#### CDDL for Zcash PCZT

```cddl
zcash-pczt {
    data: bytes, ; Zcash PCZT, signatures inserted after signing.
}
```

### Zcash Batch Signing

`zcash-sign-batch` wraps multiple signing messages into one Keystone approval.
The outer UR registry envelope carries a request id for response correlation and
an opaque `data` field containing the PCZT-owned batch message. The matching
compact response uses `zcash-batch-sig-result`, echoes the request id, and
carries the PCZT-owned response in its own opaque `data` field.

Version 1 is supported by cypherpunk firmware and currently accepts up to 80
PCZT messages with at most 2 MiB of PCZT payload data in total. The operation is
atomic. If any message is invalid or cannot be signed, Keystone returns an error
instead of a partial result. Batch PCZT entries must be fully Keystone-owned
spends from supported shielded pools, currently Orchard or Ironwood.
Transparent inputs and Sapling spends or outputs are rejected.

#### Outer UR/CBOR envelopes

Both registry types use the same integer keys. Firmware requires `request-id` to
be non-empty. Key `1` follows `zcash-pczt` by carrying opaque transaction data,
and key `2` follows `zcash-sign-result` by carrying the request id.

```cddl
zcash-sign-batch = {
    1: bytes, ; BatchSignRequest::serialize output
    2: bytes, ; request-id
}

zcash-batch-sig-result = {
    1: bytes, ; BatchSignResponse::serialize output
    2: bytes, ; echoed request-id
}
```

#### PCZT batch request

The request `data` encoding is
`"PCZB" || batch_version_le || pczt_version_le || postcard_body`. Its Postcard
body contains the PCZTs in request order.

```rust
const VERSION: u32 = 1;

struct BatchSignRequest {
    pczts: Vec<Pczt>,
}
```

PCZT entries are correlated by position. PCZT payloads must be unique within the
request.

#### PCZT batch signature response

The response `data` encoding is `"PCZS" || batch_version_le || postcard_body`.
Entry `i` contains the signatures produced for PCZT `i` in the request.

```rust
struct BatchSignResponse {
    signatures: Vec<Vec<SpendAuthSignature>>,
}

struct SpendAuthSignature {
    value_pool: u8,          // Orchard = 0, Ironwood = 1
    action_index: u32,
    signature: [u8; 64],
}
```

The outer response echoes the request id. Each signature is correlated to an
action by its Orchard-protocol value pool and action index, so the client can
apply it to the corresponding unsigned PCZT without transporting a second copy
of the full PCZT.
