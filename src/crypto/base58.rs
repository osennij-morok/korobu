use num_bigint::BigUint;
use num_traits::{FromPrimitive, ToPrimitive};

static CHARSET: [char; 58] = [
    '1', '2', '3', '4', '5', '6', '7', '8', '9', 
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 
    'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 
    'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 
    'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r', 's', 
    't', 'u', 'v', 'w', 'x', 'y', 'z'];

#[test]
fn main_test() {
    let bytes_to_encode: Vec<u8> = hex::decode(
        "abf13ad0bd2eb21d6c71b1670784f4a1de72bb4e3510123e2f55b35c0a6363ba").unwrap();
    let bytes_base58 = encode(&bytes_to_encode);
    println!("Bytes base58: {}", bytes_base58);

    let decoded_bytes: Vec<u8> = decode(&bytes_base58);
    let decoded_bytes_hex: String = hex::encode(&decoded_bytes);
    println!("Decoded bytes: {}", decoded_bytes_hex);
}

pub fn encode(bytes: &[u8]) -> String {
    let mut bytes_as_int: BigUint = BigUint::from_bytes_be(bytes);
    let mut remainder: BigUint;
    let mut output: Vec<char> = Vec::new();
    let zero: BigUint = num_traits::zero();
    let base: BigUint = BigUint::from_i128(58).unwrap();
    while bytes_as_int > zero {
        remainder = &bytes_as_int % &base;
        output.push(CHARSET[remainder.to_usize().unwrap()]);
        bytes_as_int /= &base;
    }
    output.reverse();
    output.iter().collect()
}

pub fn _is_base58(data: &str) -> bool {
    for ch in data.chars() {
        if !CHARSET.contains(&ch) {
            return false;
        }
    }
    return true;
}

pub fn decode(text: &str) -> Vec<u8> {
    let base: BigUint = BigUint::from_u8(58).unwrap();
    let mut result: BigUint = num_traits::zero();
    for (i, ch) in text.chars().rev().enumerate() {
        let charset_i: usize = CHARSET.iter()
            .position(|c: &char| *c == ch)
            .unwrap();
        result += charset_i * base.pow(i as u32);
    }
    result.to_bytes_be()
}
