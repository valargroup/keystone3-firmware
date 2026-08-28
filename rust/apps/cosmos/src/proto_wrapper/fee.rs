use crate::cosmos_sdk_proto as proto;
use crate::errors::{CosmosError, Result};
use crate::proto_wrapper::msg::base::Coin;
use crate::transaction::structs::FeeDetail;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::Serialize;

pub const ATOM_DECIMALS: usize = 6;
pub const DYM_DECIMALS: usize = 18;
pub const INJ_DECIMALS: usize = 18;

#[derive(Debug, Serialize)]
pub struct Fee {
    /// amount is the amount of coins to be paid as a fee
    pub amount: Vec<Coin>,
    /// gas_limit is the maximum gas that can be used in transaction processing
    /// before an out of gas error occurs
    #[serde(rename = "gas")]
    pub gas_limit: u64,
    /// if unset, the first signer is responsible for paying the fees. If set, the specified account must pay the fees.
    /// the payer must be a tx signer (and thus have signed this field in AuthInfo).
    /// setting this field does *not* change the ordering of required signers for the transaction.
    pub payer: String,
    /// if set, the fee payer (either the first signer or the value of the payer field) requests that a fee grant be used
    /// to pay fees instead of the fee payer's own balance. If an appropriate fee grant does not exist or the chain does
    /// not support fee grants, this will fail
    pub granter: String,
}

impl TryFrom<&proto::cosmos::tx::v1beta1::Fee> for Fee {
    type Error = CosmosError;

    fn try_from(proto: &proto::cosmos::tx::v1beta1::Fee) -> Result<Fee> {
        Ok(Fee {
            amount: proto
                .amount
                .iter()
                .map(TryFrom::try_from)
                .collect::<Result<_>>()?,
            gas_limit: proto.gas_limit,
            payer: proto.payer.clone(),
            granter: proto.granter.clone(),
        })
    }
}

pub fn format_amount(amounts: Vec<Coin>) -> String {
    let mut result = vec![];
    amounts.into_iter().for_each(|coin| {
        let amount = format_coin(coin);
        if amount.is_some() {
            result.push(amount.unwrap_or("".to_string()));
        }
    });
    result.join(",")
}

pub fn format_coin(coin: Coin) -> Option<String> {
    if coin.denom.to_lowercase().eq("uatom") {
        return format_decimal_amount(&coin.amount, ATOM_DECIMALS)
            .map(|value| format!("{value} ATOM"));
    } else if coin.denom.to_lowercase().eq("adym") {
        return format_decimal_amount(&coin.amount, DYM_DECIMALS)
            .map(|value| format!("{value} DYM"));
    } else if coin.denom.eq("inj") {
        return format_decimal_amount(&coin.amount, INJ_DECIMALS)
            .map(|value| format!("{value} INJ"));
    } else {
        return Some(format!("{} {}", coin.amount, coin.denom));
    }
}

fn format_decimal_amount(amount: &str, decimals: usize) -> Option<String> {
    if amount.is_empty() || !amount.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let normalized = amount.trim_start_matches('0');
    let digits = if normalized.is_empty() {
        "0"
    } else {
        normalized
    };
    if decimals == 0 {
        return Some(digits.to_string());
    }

    let (integer, fraction) = if digits.len() > decimals {
        let split = digits.len() - decimals;
        (digits[..split].to_string(), digits[split..].to_string())
    } else {
        (
            "0".to_string(),
            format!("{}{}", "0".repeat(decimals - digits.len()), digits),
        )
    };
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        Some(integer)
    } else {
        Some(format!("{integer}.{fraction}"))
    }
}

pub fn parse_gas_limit(gas: &serde_json::Value) -> Result<String> {
    if let Some(gas_limit) = gas.as_str() {
        if gas_limit.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(gas_limit.to_string());
        }
    }
    if let Some(gas_limit) = gas.as_u64() {
        return Ok(gas_limit.to_string());
    }
    Err(CosmosError::InvalidData(format!(
        "failed to parse gas {gas:?}"
    )))
}

pub fn format_fee_from_value(data: serde_json::Value) -> Result<FeeDetail> {
    let gas_limit = parse_gas_limit(&data["gas"])?;
    let mut fee: Vec<String> = Vec::new();
    if let Some(amounts) = data["amount"].as_array() {
        for each in amounts {
            if let (Some(amount), Some(denom)) = (each["amount"].as_str(), each["denom"].as_str()) {
                if let Some(value) = format_coin(Coin {
                    amount: amount.to_string(),
                    denom: denom.to_string(),
                }) {
                    fee.push(value);
                }
            }
        }
        let formatted_fee = fee.join(",");
        return Ok(FeeDetail {
            fee: formatted_fee,
            gas_limit,
        });
    }
    Err(CosmosError::InvalidData("can not parse fee".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fee_amount_is_total_fee_not_gas_price() {
        let fee = format_fee_from_value(json!({
            "amount": [{"amount": "2583", "denom": "uatom"}],
            "gas": "103301"
        }))
        .unwrap();
        assert_eq!("0.002583 ATOM", fee.fee);
        assert_eq!("103301", fee.gas_limit);
    }

    #[test]
    fn fee_formatting_preserves_large_integer_precision() {
        let fee = format_fee_from_value(json!({
            "amount": [{
                "amount": "115792089237316195423570985008687907853269984665640564039457",
                "denom": "uatom"
            }],
            "gas": "18446744073709551615"
        }))
        .unwrap();
        assert_eq!(
            "115792089237316195423570985008687907853269984665640564.039457 ATOM",
            fee.fee
        );
        assert_eq!("18446744073709551615", fee.gas_limit);
    }
}
