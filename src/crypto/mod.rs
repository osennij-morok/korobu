use std::error::Error;

use orion::{
    hazardous::{
        stream::xchacha20::SecretKey, 
        aead::xchacha20poly1305
    }, 
    aead::streaming::Nonce
};
use rand_core::{RngCore, OsRng};

use self::key_derivation::DERIVED_HASH_LEN;

#[cfg(test)]
mod tests;
mod key_derivation;
mod base58;
pub mod file;

fn gen_rand(out: &mut [u8]) {
    OsRng.fill_bytes(out);
}

const PROTOCOL_VERION: u8 = 1;
const PROTOCOL_VERION_LEN: usize = 1;
const CIPHER_NONCE_LEN: usize = 24;
const KDF_SALT_LEN: usize = key_derivation::SALT_LEN;
const CONTROL_BYTES_LEN: usize = 32;
const HEADER_LEN: usize = PROTOCOL_VERION_LEN + CIPHER_NONCE_LEN 
                                              + KDF_SALT_LEN 
                                              + CONTROL_BYTES_LEN;
const MAC_LEN: usize = 16;

#[derive(Debug, zeroize::ZeroizeOnDrop)]
struct Header {
    #[zeroize(skip)]
    version: u8,
    #[zeroize(skip)]
    cipher_nonce: [u8; CIPHER_NONCE_LEN],
    #[zeroize(skip)]
    kdf_salt: [u8; KDF_SALT_LEN],
    control_bytes: [u8; CONTROL_BYTES_LEN],
}

impl Header {
    fn new(nonce: [u8; CIPHER_NONCE_LEN], 
           kdf_salt: [u8; KDF_SALT_LEN], 
           control_bytes: [u8; CONTROL_BYTES_LEN]) -> Result<Self, Box<dyn Error>> {
        Ok(Header {
            version: PROTOCOL_VERION,
            cipher_nonce: nonce,
            kdf_salt,
            control_bytes: control_bytes.to_owned(),
        })
    }
}

impl Into<[u8; HEADER_LEN]> for Header {
    fn into(self) -> [u8; HEADER_LEN] {

        let mut header_bs = [0u8; HEADER_LEN]; // 73 bytes
        header_bs[0] = self.version;

        header_bs[PROTOCOL_VERION_LEN..PROTOCOL_VERION_LEN + CIPHER_NONCE_LEN]
            .copy_from_slice(&self.cipher_nonce);

        header_bs[PROTOCOL_VERION_LEN + CIPHER_NONCE_LEN
                  ..PROTOCOL_VERION_LEN + CIPHER_NONCE_LEN + KDF_SALT_LEN]
            .copy_from_slice(&self.kdf_salt);

        header_bs[PROTOCOL_VERION_LEN + CIPHER_NONCE_LEN + KDF_SALT_LEN
                  ..PROTOCOL_VERION_LEN + CIPHER_NONCE_LEN + KDF_SALT_LEN + CONTROL_BYTES_LEN]
            .copy_from_slice(&self.control_bytes);

        header_bs
    }
}

impl TryFrom<[u8; HEADER_LEN]> for Header {
    type Error = String;

    fn try_from(value: [u8; HEADER_LEN]) -> Result<Self, Self::Error> {
        let version: u8 = value[0];
        if version != 1 {
            Err(format!("The version {} is not supported", version))?
        }
        let mut offset: usize = PROTOCOL_VERION_LEN;

        let mut cipher_nonce = [0u8; CIPHER_NONCE_LEN];
        cipher_nonce.clone_from_slice(&value[offset..offset + CIPHER_NONCE_LEN]);
        offset += CIPHER_NONCE_LEN;

        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        kdf_salt.clone_from_slice(&value[offset..offset + KDF_SALT_LEN]);
        offset += KDF_SALT_LEN;

        let mut control_bytes = [0u8; CONTROL_BYTES_LEN];
        control_bytes.clone_from_slice(&value[offset..offset + CONTROL_BYTES_LEN]);
        
        Ok(Self {
            version,
            cipher_nonce,
            kdf_salt,
            control_bytes
        })
    }
}

pub fn crypto_box(text: &str, password: &str) -> Result<String, Box<dyn Error>> {
    use zeroize::Zeroize;
    let nonce: [u8; CIPHER_NONCE_LEN] = cipher_nonce();
    let kdf_salt: [u8; KDF_SALT_LEN] = key_derivation::gen_salt();
    let mut hash: [u8; DERIVED_HASH_LEN] = key_derivation::derive_with(
        &kdf_salt, password.as_bytes());
    let (key, control_bytes): (&[u8; DERIVED_HASH_LEN / 2], &[u8; DERIVED_HASH_LEN / 2]) 
        = key_derivation::split_hash(&hash)?;
    let header = Header::new(nonce, kdf_salt, *control_bytes)?;

    let mut ciphertext = vec![0u8; text.len() + MAC_LEN];
    xchacha20poly1305::seal(&SecretKey::from_slice(key)?, 
                            &xchacha20poly1305::Nonce::from_slice(&header.cipher_nonce)?, 
                            text.as_bytes(), None, &mut ciphertext)?;
    hash.zeroize();
    let header_bs: [u8; HEADER_LEN] = header.into();
    
    Ok(pack_box_v2(&header_bs, &ciphertext))
}

fn _pack_hex_box(header: &[u8; HEADER_LEN], ciphertext_with_tag: &[u8]) -> String {
    format!("{}.{}", hex::encode_upper(header), hex::encode_upper(ciphertext_with_tag))
}

pub fn _pack_compact_box(header: &[u8; HEADER_LEN], ciphertext_with_tag: &[u8]) -> String {
    format!("{}.{}", base58::encode(header), base58::encode(ciphertext_with_tag))
}
// https://www.youtube.com/shorts/-rkq42STfy8

fn _unpack_hex_box(data: &str) -> Result<([u8; HEADER_LEN], Vec<u8>), Box<dyn Error>> {
    let (header_hex, ciphertext_with_tag_hex) = data.split_once(".")
        .ok_or("Incorrect box format".to_owned())?;


    let mut header_bytes = [0u8; HEADER_LEN];
    hex::decode_to_slice(header_hex, &mut header_bytes)?;
    if header_bytes.len() < HEADER_LEN {
        return Err(format!(
            "Incorrect box size: it is {} bytes, but it cannot be less than {}",
            header_bytes.len(), HEADER_LEN).into())
    }

    let ciphertext_with_tag: Vec<u8> = hex::decode(ciphertext_with_tag_hex)?;
    
    Ok((header_bytes, ciphertext_with_tag))
}

pub fn _unpack_compact_box(data: &str) -> Result<([u8; HEADER_LEN], Vec<u8>), Box<dyn Error>> {
    let (header_compact, ciphertext_with_tag_compact) = data.split_once(".")
        .ok_or("Incorrect box format".to_owned())?;

    let header_bytes: Vec<u8> = base58::decode(header_compact);
    if header_bytes.len() < HEADER_LEN {
        Err(format!(
            "Incorrect box size: it is {} bytes, but it cannot be less than {}",
            header_bytes.len(), HEADER_LEN))?
    }

    let ciphertext_with_tag: Vec<u8> = base58::decode(ciphertext_with_tag_compact);
    
    Ok((header_bytes.as_slice().try_into()?, ciphertext_with_tag))
}

pub fn pack_box_v2(header: &[u8; HEADER_LEN], ciphertext_with_tag: &[u8]) -> String {
    let mut result = vec![0u8; header.len() + ciphertext_with_tag.len()];
    result[0..header.len()]
        .copy_from_slice(header);
    result[header.len()..header.len() + ciphertext_with_tag.len()]
        .copy_from_slice(ciphertext_with_tag);
    return to_bricks_view(&result)
}

pub fn unpack_box_v2(data: impl Into<String>) -> Result<([u8; HEADER_LEN], Vec<u8>), 
                                                        Box<dyn Error>> {
    let header_and_data: Vec<u8> = from_bricks_view(data);
    if header_and_data.len() < HEADER_LEN + 1 {
        Err(format!(
            "Incorrect box size: it is {} bytes, but it cannot be less than {}",
            header_and_data.len(), HEADER_LEN + 1))?
    }

    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&header_and_data[0..HEADER_LEN]);

    Ok((header, header_and_data[HEADER_LEN..].to_vec()))
}

pub fn to_bricks_view(data: &[u8]) -> String {
    const CHUNK_LEN: usize = 15;
    const CHUNK_LEN_FLOAT: f32 = 15.;

    let result_base58: String = base58::encode(&data);
    let chunks_count: usize = (result_base58.len() as f32 / CHUNK_LEN_FLOAT).ceil() as usize;
    let whitespaces_count: usize = chunks_count - 1;
    let mut result = String::with_capacity(result_base58.len() + whitespaces_count);
    let mut array_chunks_iter 
        = result_base58.chars().array_chunks();
    let mut chunk_i: usize = 0;
    // for e in array_chunks_iter {
    while let Some(chunk) = array_chunks_iter.next() {
        // let (chunk_i, chunk): (usize, [char; CHUNK_LEN]) = e;
        let chunk: [char; CHUNK_LEN] = chunk;
        for symbol_i in 0..chunk.len() {
            result.push(chunk[symbol_i]);
        }
        if chunk_i != chunks_count - 1 {
            result.push(' ');
        }
        chunk_i += 1;
    }
    if let Some(remainder_iter) = array_chunks_iter.into_remainder() {
        println!("REMAINDER IS PRESENT");
        println!();
        for ch in remainder_iter {
            result.push(ch);
        }
    }
    return result
}

pub fn from_bricks_view(data: impl Into<String>) -> Vec<u8> {
    let mut data: String = data.into();
    data.retain(|c| !c.is_whitespace());
    base58::decode(&data)
}

fn cipher_nonce() -> [u8; CIPHER_NONCE_LEN] {
    let mut nonce = [0u8; CIPHER_NONCE_LEN];
    gen_rand(&mut nonce);
    return nonce
}

pub fn crypto_box_open(data: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let (header_bytes, ciphertext_with_tag) = unpack_box_v2(data)?;
    let header = Header::try_from(header_bytes)?;

    let hash: [u8; DERIVED_HASH_LEN] = key_derivation::derive_with(&header.kdf_salt, 
                                                                   password.as_bytes());
    let (key, control_bytes) = key_derivation::split_hash(&hash)?;
    if &header.control_bytes != control_bytes {
        Err("Control bytes do not match".to_owned())?
    }

    let mut out = vec![0u8; ciphertext_with_tag.len() - MAC_LEN]; 
    let nonce = Nonce::from_slice(&header.cipher_nonce)?;
    xchacha20poly1305::open(&SecretKey::from_slice(key)?, &nonce, 
                            &ciphertext_with_tag, None, &mut out)?;
                            
    Ok(String::from_utf8(out)?)
}
