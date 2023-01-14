use std::{
    error::Error, 
    ops::Sub, 
    fs::{self, File}, 
    path::{PathBuf, Path}, 
    io::{Read, Write}
};

use chacha20poly1305::XChaCha20Poly1305;
use orion::{hazardous::aead::xchacha20poly1305, hash::Digest};
use rand_core::{OsRng, RngCore};

use crate::crypto::{gen_rand, crypto_box, crypto_box_open, key_derivation, unpack_box_v2};

use super::{base58, pack_box_v2, HEADER_LEN, to_bricks_view};

// Result form:
// tag: 1 -- protocol version + 24 -- cipher nonce + 16 -- kdf salt + 32 -- control bytes = 73
#[test]
fn t_chacha() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = xchacha20poly1305::Nonce::from_slice(
        &hex::decode("89D15225B8D1CB42E27E1BF6F28783986879A10E1E681AA0")?)?;
    let key = xchacha20poly1305::SecretKey::from_slice(
        &hex::decode("F6EE922A4B53A96D4EABD9526DBB4B8A50AE7AB3506C355E5F65D45BAD30DD26")?)?;
    let plaintext_str: &str = "Hello, World!";
    println!("Input text: {}", plaintext_str);
    let plaintext: &[u8] = plaintext_str.as_bytes();

    const SIG_SIZE: usize = 16;
    let mut ciphertext_buff = vec![0_u8; plaintext_str.len() + SIG_SIZE];
    xchacha20poly1305::seal(&key, &nonce, plaintext, None, &mut ciphertext_buff)?;
    println!("CIPHERTEXT:");
    println!("{}", &hex::encode_upper(&ciphertext_buff));
    Ok(())
}

#[test]
fn t_rand() {
    const LEN: usize = 16;
    let mut bs = [0u8; LEN];
    gen_rand(&mut bs);
    println!("RAND BYTES IN HEX:");
    println!("{}", hex::encode_upper(&bs));
}

#[test]
fn t_crypto_box() -> Result<(), Box<dyn Error>> {
    let plain_text = "Пробный текст для шифрования";
    let ciphertext = crypto_box(plain_text, "s3crEt")?;
    dbg!(&ciphertext);
    Ok(())
}

#[test]
fn t_open_box() -> Result<(), Box<dyn Error>> {
    let box_text =         "018EA69D325DA4E3BB0CC9C742D52B592E3EEE2DEB55EFFC3317B1E3C4937597CE01CA17D5DA49B03487A920EEE756E980E1E840C28D962206ADA30945693759A39B85F59223D84737.6FD6CBDFF64C0581C318677171B16F297AA1B9FFE6692A3678EF10357B09CA21C86D666FBAC1F450238D0D816B4F43DCA2B58BFE6223B01FF46B8BFFA14E46256A79096F4F";
    // let (_header, _ciphertext_with_tag) = unpack_hex_box(box_text)?;
    // let compact_box_text: String = pack_compact_box(&header, &ciphertext_with_tag);

    let compact_box_text = "7qQfszP4Zx4MUD1tKpVdGBimBLbTJGUJMfaMN3wwatYNrWUeov1QDJH7njFEiG4MyanEYk6zSdg3g9tuWMd7XbALvz2PzrU7iM1.85oZ4ePzN3GDW15xjk8vonHVv6cwmMaCowmsajNoWGWVhFDfjbMS6MX6ni1aa2AwP3hUZNWuUvqgWnHVKTTyLWNFFHeA75";
    // dbg!(&compact_box_text);
    
    println!("BOX TEXT:");
    println!("{}", box_text);
    println!();
    println!("COMPACT BOX TEXT:");
    println!("{}", compact_box_text);

    let plain_text = crypto_box_open(compact_box_text, "s3crEt")?;
    dbg!(&plain_text);
    Ok(())
}

#[test]
fn t_base58() -> Result<(), Box<dyn Error>> {
    let some_bs = b"Eto nekyi trudno raspoznavajemyi macsinami tekst";
    println!("Source:");
    println!("{}", hex::encode_upper(some_bs));

    let some_bs_base58: String = base58::encode(some_bs);
    dbg!(&some_bs_base58);

    let some_bs_decoded: Vec<u8> = base58::decode(&some_bs_base58);
    println!("Decoded:");
    println!("{}", hex::encode_upper(&some_bs_decoded));
    dbg!(String::from_utf8(some_bs_decoded)?);
    Ok(())
}

#[test]
fn get_normal_hashing_time_manually() -> Result<(), Box<dyn Error>> {
    let mut salt = [0u8; key_derivation::SALT_LEN];
    hex::decode_to_slice("AFE42B3BA547C20E946ECFC1DE530AE1", &mut salt)?;

    let start = std::time::Instant::now();
    
    let hash = key_derivation::derive_with(&salt, b"Sample message for hashing");

    let duration: std::time::Duration = std::time::Instant::now().sub(start);
    println!("Duration: {}", duration.as_millis());

    let derived_key: &[u8] = &hash[0..key_derivation::DERIVED_HASH_LEN / 2];
    let control_bytes: &[u8] = &hash[key_derivation::DERIVED_HASH_LEN / 2..];
    println!("Hash:");
    println!("{}", hex::encode_upper(&derived_key));
    println!("Control bytes:");
    println!("{}", hex::encode_upper(&control_bytes));

    Ok(())
}

#[test]
fn t_pack_hex_hox_v2() -> Result<(), Box<dyn Error>> {
    let mut header = [0u8; HEADER_LEN];
    OsRng.fill_bytes(&mut header);
    let ciphertext_with_tag = "Некоторый текст".as_bytes();
    // OsRng.fill_bytes(&mut ciphertext_with_tag);

    let result: String = pack_box_v2(&header, &ciphertext_with_tag);
    println!("{}", result);
    
    let (_, data): ([u8; HEADER_LEN], Vec<u8>) = unpack_box_v2(result)?;
    let text = String::from_utf8(data)?;
    println!("DECODED TEXT:");
    println!("{}", text);
    Ok(())
}

#[test]
fn t_to_bricks_view() {
    let mut data = [0u8; 19];
    OsRng.fill_bytes(&mut data);
    let result: String = to_bricks_view(&data);
    println!("AS BASE58: ");
    println!("{}", base58::encode(&data));
    println!();
    println!("RESULT:");
    println!("{}", result);
}

#[test]
fn t_from_bricks_view() {
    let mut input: String = r#"25gWpmSeDcvVZEF ZAU9j9eKLQ13KEn 89Y2Rw1axHkjB5j M3f7d3iDxWtx3Hm a6aXntideVar5Db FwEo61DrRbBBKAE ECMYH8GhJyQ3kXZ ErvcvJFr4nXFyRF MWwbsHHGvhr9YDb pt9zFzY8fNm7ry6 H3uo9HDm1SjTGMm XpqhpXyhro8GTiY
    "#.into();
    input.retain(|c| !c.is_whitespace());
    println!("OUT:");
    println!("[{}]", input);
}

#[test]
fn t_chacha_lib() -> Result<(), Box<dyn Error>> {
    // use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, AeadMut};
    // use chacha20poly1305::XNonce;

    use chacha20poly1305::{
        aead::{Aead, KeyInit, OsRng},
        ChaCha20Poly1305, Nonce
    };

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    println!("KEY:");
    println!("{}", hex::encode_upper(&key));
    let _xchch 
        = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    let chch 
        = ChaCha20Poly1305::new_from_slice(&key).unwrap();

    let nonce = Nonce::from_slice(&nonce);
    let _result = Aead::encrypt(&chch, nonce, "Некоторый текст для шифрования".as_bytes()).unwrap();
    
    Ok(())
}

#[test]
fn t_files() -> Result<(), Box<dyn Error>> {
    let current_dir_path: PathBuf = fs::canonicalize(".")?;
    let current_dir_abs_path: &str = current_dir_path.as_os_str()
        .to_str()
        .ok_or("Cannot resolve path".to_owned())?;
    println!("CURRENT DIR PATH:");
    println!("{}", current_dir_abs_path);
    println!();

    let file_path = "./sandbox/slovo-o-polku-igoreve_Jekaterinskaja-kopija.djvu";
    let mut file = File::open(file_path)?;

    let file_copy_path = "./sandbox/slovo-o-polku-igoreve_Jekaterinskaja-kopija.djvu.bak";
    let mut file_copy = File::create(file_copy_path)?;

    let mut buffer = [0u8; 1 * 1024 * 1024]; // 1 Mb buffer
    loop {
        let bs_len: usize = file.read(&mut buffer)?;
        if bs_len == 0 {
            break;
        }
        file_copy.write(&buffer[0..bs_len])?;
    }
    Ok(())
}

#[test]
fn t_hash() -> Result<(), Box<dyn Error>> {
    let orig_file_path = "./sandbox/slovo-o-polku-igoreve_Jekaterinskaja-kopija.djvu.base";
    let file_copy_path = "./sandbox/slovo-o-polku-igoreve_Jekaterinskaja-kopija.djvu.enc";

    let orig_file_hash_hex: String = hash_file(orig_file_path)?;
    dbg!(orig_file_hash_hex);

    let file_copy_hash_hex: String = hash_file(file_copy_path)?;
    dbg!(file_copy_hash_hex);

    Ok(())
}

fn hash_file(path: impl AsRef<Path>) -> Result<String, Box<dyn Error>> {
    let file = File::open(path)?;
    let file_hash: Digest = orion::hash::digest_from_reader(file)?;
    let file_hash_bytes: &[u8] = file_hash.as_ref();
    Ok(hex::encode_upper(file_hash_bytes))
}