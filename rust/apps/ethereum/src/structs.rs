use crate::address::generate_address;
use crate::eip1559_transaction::ParsedEIP1559Transaction;
use crate::eip712::eip712::TypedData as Eip712TypedData;
use crate::errors::Result;
use crate::{Bytes, ParsedLegacyTransaction};
use alloc::string::{String, ToString};
use alloc::{format, vec};

use alloc::vec::Vec;
use bitcoin::secp256k1::PublicKey;
use cryptoxide::hashing::keccak256;
use ethabi::{encode, Address, Token};
use ethereum_types::{H160, U256};
use hex;
use rlp::{Decodable, DecoderError, Encodable, Rlp};
use serde_json::Value;

#[derive(Clone)]
pub enum TransactionAction {
    Call(H160),
    Create,
}

impl Decodable for TransactionAction {
    fn decode(rlp: &Rlp) -> core::result::Result<Self, DecoderError> {
        if rlp.is_empty() {
            if rlp.is_data() {
                Ok(TransactionAction::Create)
            } else {
                Err(DecoderError::RlpExpectedToBeData)
            }
        } else {
            Ok(TransactionAction::Call(rlp.as_val()?))
        }
    }
}

impl Encodable for TransactionAction {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        match self {
            TransactionAction::Call(address) => {
                s.append(address);
            }
            TransactionAction::Create => {
                s.append_empty_data();
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ParsedEthereumTransaction {
    pub nonce: String,
    pub chain_id: u64,
    pub from: Option<String>,
    pub to: String,
    pub value: String,
    pub input: String,

    pub gas_price: Option<String>,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub max_fee: Option<String>,
    pub max_priority: Option<String>,

    pub gas_limit: String,
    pub max_txn_fee: String,
    pub replay_protected: bool,
}

impl ParsedEthereumTransaction {
    pub(crate) fn from_legacy(
        tx: ParsedLegacyTransaction,
        from: Option<PublicKey>,
    ) -> Result<Self> {
        Ok(Self {
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            gas_price: Some(tx.gas_price),
            from: from.map(|key| generate_address(key).unwrap_or_default()),
            to: tx.to,
            value: tx.value,
            chain_id: tx.chain_id,
            input: tx.input,
            max_txn_fee: tx.max_txn_fee,

            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            max_fee: None,
            max_priority: None,
            replay_protected: tx.replay_protected,
        })
    }

    pub(crate) fn from_eip1559(
        tx: ParsedEIP1559Transaction,
        from: Option<PublicKey>,
    ) -> Result<Self> {
        Ok(Self {
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            from: from.map(|key| generate_address(key).unwrap_or_default()),
            to: tx.to,
            value: tx.value,
            chain_id: tx.chain_id,
            input: tx.input,
            max_fee_per_gas: Some(tx.max_fee_per_gas),
            max_priority_fee_per_gas: Some(tx.max_priority_fee_per_gas),
            max_txn_fee: tx.max_txn_fee,
            max_fee: Some(tx.max_fee),
            max_priority: Some(tx.max_priority),
            gas_price: None,
            replay_protected: true,
        })
    }
}

pub struct EthereumSignature(pub u64, pub [u8; 64]);

impl EthereumSignature {
    pub fn serialize(&self) -> Bytes {
        let mut s = Vec::from(self.1);
        let v_bytes = self.0.to_be_bytes();
        let mut index = 0;
        for x in v_bytes {
            if x == 0 {
                index += 1
            } else {
                break;
            }
        }
        let stripped_v = &v_bytes[index..];
        if stripped_v.is_empty() {
            s.push(0)
        } else {
            s.extend(stripped_v)
        }
        s
    }
}

#[derive(Clone, Debug)]
pub struct PersonalMessage {
    pub raw_message: String,
    pub utf8_message: String,
    pub from: Option<String>,
}

impl PersonalMessage {
    pub fn from(
        raw_message: String,
        utf8_message: String,
        from: Option<PublicKey>,
    ) -> Result<Self> {
        Ok(Self {
            raw_message,
            utf8_message,
            from: from.map(|key| generate_address(key).unwrap_or_default()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct TypedData {
    pub name: String,
    pub version: String,
    pub chain_id: String,
    pub verifying_contract: String,
    pub salt: String,
    pub primary_type: String,
    pub message: String,
    pub from: Option<String>,
    pub domain_separator: String,
    pub message_hash: String,
    pub safe_tx_hash: String,
}

impl TypedData {
    pub fn from(data: TypedData, from: Option<PublicKey>) -> Result<Self> {
        Ok(Self {
            from: from.map(|key| generate_address(key).unwrap_or_default()),
            ..data
        })
    }

    pub fn from_raw(data: Eip712TypedData, from: Option<PublicKey>) -> Result<Self> {
        let mut data = Self::try_from(data)
            .map_err(|e| crate::errors::EthereumError::HashTypedDataError(e.to_string()))?;
        data.safe_tx_hash = data.get_safe_tx_hash()?;
        Self::from(data, from)
    }

    pub fn get_safe_tx_hash(&self) -> Result<String> {
        // bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;
        // bytes32 safeTxHash = keccak256(
        //     abi.encode(SAFE_TX_TYPEHASH, to, value, keccak256(data), operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce)
        // );
        if self.primary_type != "SafeTx" {
            return Ok("".to_string());
        }

        fn error(field: &str) -> crate::errors::EthereumError {
            crate::errors::EthereumError::HashTypedDataError(format!(
                "invalid SafeTx field: {field}"
            ))
        }

        fn parse_u256(message: &Value, field: &str) -> Result<U256> {
            let value = message.get(field).ok_or_else(|| error(field))?;
            if let Some(value) = value.as_str() {
                return U256::from_dec_str(value).map_err(|_| error(field));
            }
            value.as_u64().map(U256::from).ok_or_else(|| error(field))
        }

        fn parse_address(message: &Value, field: &str) -> Result<Address> {
            let value = message
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| error(field))?;
            let bytes = hex::decode(
                value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                    .unwrap_or(value),
            )
            .map_err(|_| error(field))?;
            if bytes.len() != 20 {
                return Err(error(field));
            }
            Ok(Address::from_slice(&bytes))
        }

        fn parse_bytes(message: &Value, field: &str) -> Result<Vec<u8>> {
            let value = message
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| error(field))?;
            hex::decode(
                value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                    .unwrap_or(value),
            )
            .map_err(|_| error(field))
        }

        let message = serde_json::from_str::<Value>(&self.message).map_err(|_| error("message"))?;
        if !message.is_object() {
            return Err(error("message"));
        }

        let safe_tx_typehash =
            hex::decode("bb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8")
                .map_err(|_| error("typehash"))?;
        let value = parse_u256(&message, "value")?;
        let data = parse_bytes(&message, "data")?;
        let data_hash = keccak256(&data);
        let to_token = Token::Address(parse_address(&message, "to")?);
        let operation = parse_u256(&message, "operation")?;
        if operation > U256::from(1u8) {
            return Err(error("operation"));
        }
        let safe_tx_gas = parse_u256(&message, "safeTxGas")?;
        let base_gas = parse_u256(&message, "baseGas")?;
        let gas_price = parse_u256(&message, "gasPrice")?;
        let nonce = parse_u256(&message, "nonce")?;
        let gas_token_token = Token::Address(parse_address(&message, "gasToken")?);
        let refund_receiver_token = Token::Address(parse_address(&message, "refundReceiver")?);

        let tokens = vec![
            Token::FixedBytes(safe_tx_typehash),
            to_token,
            Token::Uint(value),
            Token::FixedBytes(data_hash.to_vec()),
            Token::Uint(operation),
            Token::Uint(safe_tx_gas),
            Token::Uint(base_gas),
            Token::Uint(gas_price),
            gas_token_token,
            refund_receiver_token,
            Token::Uint(nonce),
        ];

        // Calculate final hash
        let encoded = encode(&tokens);
        let safe_tx_hash = keccak256(&encoded);

        // Convert to hex string with 0x prefix
        // return abi.encodePacked(byte(0x19), byte(0x01), domainSeparator, safeTxHash);
        let domain_separator = hex::decode(
            self.domain_separator
                .strip_prefix("0x")
                .or_else(|| self.domain_separator.strip_prefix("0X"))
                .unwrap_or(&self.domain_separator),
        )
        .map_err(|_| error("domainSeparator"))?;
        if domain_separator.len() != 32 {
            return Err(error("domainSeparator"));
        }
        let mut transaction_data = Vec::new();
        transaction_data.push(0x19);
        transaction_data.push(0x01);
        transaction_data.extend_from_slice(&domain_separator);
        transaction_data.extend_from_slice(&safe_tx_hash);
        let transaction_hash = keccak256(&transaction_data);
        Ok(format!("0x{}", hex::encode(transaction_hash)))
    }
}

#[cfg(test)]
pub mod tests {
    use crate::structs::EthereumSignature;
    use hex;

    extern crate std;
    use crate::structs::TypedData;
    use serde_json::Value;
    use std::string::ToString;
    #[test]
    fn test_signature() {
        {
            let signature = EthereumSignature(1440123, [0u8; 64]);
            assert_eq!("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000015f97b", hex::encode(signature.serialize()))
        }
        {
            let signature = EthereumSignature(0, [0u8; 64]);
            assert_eq!("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", hex::encode(signature.serialize()))
        }
        {
            let signature = EthereumSignature(1, [0u8; 64]);
            assert_eq!("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", hex::encode(signature.serialize()))
        }
    }

    #[test]
    fn test_decoder_error_conversion() {
        let error: crate::errors::EthereumError =
            rlp::DecoderError::Custom("invalid test rlp").into();
        assert!(matches!(
            error,
            crate::errors::EthereumError::RlpDecodingError(message)
                if message.contains("invalid test rlp")
        ));
    }

    #[test]
    fn test_generate_safe_tx_hash() {
        let message = serde_json::json!({
            "baseGas": "0",
            "data": "0x",
            "gasPrice": "0",
            "gasToken": "0x0000000000000000000000000000000000000000",
            "nonce": "0",
            "operation": "0",
            "refundReceiver": "0x0000000000000000000000000000000000000000",
            "safeTxGas": "0",
            "to": "0x88a8315f60bfc348af1740c0418a2e2fef2222a7",
            "value": "100000000000000"
        });
        let chain_id = "1";
        let verifying_contract = "0x28bb1ba844129cc339a47ad84d41edb0f475b2c6";
        let typed_data = TypedData {
            name: "".to_string(),
            version: "".to_string(),
            chain_id: chain_id.to_string(),
            verifying_contract: verifying_contract.to_string(),
            salt: "".to_string(),
            primary_type: "SafeTx".to_string(),
            message: message.to_string(),
            from: Some("".to_string()),
            domain_separator: "0x1c9fbcac173da0e989115be1cf7e8c85442bac869e1de9f72ea59ec6c4e1b43d"
                .to_string(),
            message_hash: "0x2760e0669e7dbd5a2a9f695bac8db1432400df52a9895d8eae50d94dcb82976b"
                .to_string(),
            safe_tx_hash: "".to_string(),
        };
        assert_eq!(
            typed_data.get_safe_tx_hash().unwrap(),
            "0x2f31649e0f48e410b00643088c8f209b1ab33871aae7150c9d7a008dda243c0a"
        );

        let mut invalid_address = typed_data.clone();
        invalid_address.message = message
            .as_object()
            .map(|message| {
                let mut message = message.clone();
                message.insert("to".to_string(), serde_json::json!("0x1234"));
                Value::Object(message).to_string()
            })
            .unwrap();
        assert!(invalid_address.get_safe_tx_hash().is_err());

        let mut invalid_operation = typed_data.clone();
        invalid_operation.message = message
            .as_object()
            .map(|message| {
                let mut message = message.clone();
                message.insert("operation".to_string(), serde_json::json!("2"));
                Value::Object(message).to_string()
            })
            .unwrap();
        assert!(invalid_operation.get_safe_tx_hash().is_err());

        let mut missing_nonce = typed_data;
        missing_nonce.message = message
            .as_object()
            .map(|message| {
                let mut message = message.clone();
                message.remove("nonce");
                Value::Object(message).to_string()
            })
            .unwrap();
        assert!(missing_nonce.get_safe_tx_hash().is_err());
    }
}
