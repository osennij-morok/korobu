use std::{
    path::Path, 
    error::Error, 
    fs::{File, self}, 
    io::{Read, Write}, mem
};

use orion::hazardous::aead::{
    xchacha20poly1305::SecretKey, 
    streaming::{StreamXChaCha20Poly1305, self, StreamTag}
};
use orion::hazardous::aead::streaming::TAG_SIZE as ORION_TAG_SIZE;
use orion::hazardous::mac::poly1305::POLY1305_OUTSIZE as MAC_SIZE;

use crate::crypto::HEADER_LEN;

use super::{
    CIPHER_NONCE_LEN, 
    KDF_SALT_LEN, 
    key_derivation::{DERIVED_HASH_LEN, self}, 
    cipher_nonce, 
    Header
};

const CHUNK_SIZE: usize = 1 * 1024 * 1024; // 1 MiB
const ENCRYPTED_FILE_SUFFIX: &str = ".krb";
const DECRYPTED_FILE_SUFFIX: &str = ".dec";
// const TMP_FILE_PREFIX: &str = ".";
const TMP_FILE_SUFFIX: &str = ".proc";

#[derive(Default)]
pub struct ProgressMonitor {
    subscribers: Vec<Box<dyn Fn(Msg) + Send>>,
}

impl ProgressMonitor {

    pub fn subscribe(&mut self, on_progress_func: impl Fn(Msg) + 'static + Send) {
        self.subscribers.push(box on_progress_func)
    }

    fn on_message(&self, message: Msg) {
        for handle_progress_func in &self.subscribers {
            handle_progress_func(message)
        }
    }

    fn on_progress(&self, progress: f32) {
        self.on_message(Msg::Progress(progress));
    }
    
    fn on_encryption_started(&self) {
        self.on_message(Msg::EncryptionStarted);
    }

    fn on_decryption_started(&self) {
        self.on_message(Msg::DecryptionStarted);
    }

    fn on_key_derivation_started(&self) {
        self.on_message(Msg::KeyDerivationStarted);
    }
}

type Msg = ProgressMonitorMessage;

#[derive(Debug, Clone, Copy)]
pub enum ProgressMonitorMessage {
    KeyDerivationStarted,
    EncryptionStarted,
    DecryptionStarted,
    Progress(f32),
}

pub fn encrypt_file(path: impl AsRef<Path>, 
                    password: &str, 
                    monitor: &mut ProgressMonitor) -> Result<(), Box<dyn Error>> {
    // todo: replace with struct
    let nonce: [u8; CIPHER_NONCE_LEN] = cipher_nonce();
    let kdf_salt: [u8; KDF_SALT_LEN] = key_derivation::gen_salt();
    monitor.on_key_derivation_started();
    let hash: [u8; DERIVED_HASH_LEN] = key_derivation::derive_with(
        &kdf_salt, password.as_bytes());
    let (key, control_bytes): (&[u8; DERIVED_HASH_LEN / 2], &[u8; DERIVED_HASH_LEN / 2]) 
        = key_derivation::split_hash(&hash)?;
    let header = Header::new(nonce, kdf_salt, *control_bytes)?;
    let header_bytes: [u8; HEADER_LEN] = header.into();

    let secret_key = SecretKey::from_slice(key)?;
    let stream_nonce = streaming::Nonce::from_slice(&nonce)?;
    let mut cipher_stream = StreamXChaCha20Poly1305::new(&secret_key, &stream_nonce);
    
    let out_path: &str = path.as_ref().to_str().ok_or("Invalid path format".to_owned())?;
    let out_path: String = out_path.to_owned() + ENCRYPTED_FILE_SUFFIX + TMP_FILE_SUFFIX;
    let mut out_file = File::create(&out_path)?;

    monitor.on_encryption_started();
    out_file.write(&header_bytes)?;

    let mut input_file = File::open(path)?;
    let input_file_size: u64 = input_file.metadata()?.len();
    let mut loaded_bytes_size: u64 = 0;
    let mut chunk = vec![0u8; CHUNK_SIZE];
    let mut out_chunk = vec![0u8; ORION_TAG_SIZE + CHUNK_SIZE + MAC_SIZE];
    loop {
        let bytes_count: usize = input_file.read(&mut chunk)?;
        if bytes_count == 0 {
            break;
        }
        loaded_bytes_size += bytes_count as u64;
        println!("LOADED BYTES SIZE: {}", loaded_bytes_size); ////
        let progress: f32 = (loaded_bytes_size as f64 / input_file_size as f64) as f32;
        monitor.on_progress(progress);
        println!("PROGRESS IN FILE.RS: {}", (loaded_bytes_size as f64 / input_file_size as f64) as f32); ////
        let chunk_is_last: bool = bytes_count < CHUNK_SIZE;
        let tag = if chunk_is_last {
            StreamTag::Finish
        } else {
            StreamTag::Message
        };
        cipher_stream.seal_chunk(&chunk[0..bytes_count], None, &mut out_chunk, &tag)?;
        let chunk_with_adata_size: usize = ORION_TAG_SIZE + bytes_count + MAC_SIZE;
        out_file.write(&out_chunk[0..chunk_with_adata_size])?;
    }
    mem::drop(out_file);
    if let Some(err) = out_path
        .strip_suffix(TMP_FILE_SUFFIX)
        .and_then(|out_path_without_suffix| fs::rename(&out_path, out_path_without_suffix).err()) 
    {
        dbg!(err);
    }
    Ok(())
}

pub fn decrypt_file(path: impl AsRef<Path>, 
                    password: &str, 
                    monitor: &mut ProgressMonitor) -> Result<(), Box<dyn Error>> {
    const MIN_FILE_SIZE: u64 = (HEADER_LEN + ORION_TAG_SIZE + CHUNK_SIZE + MAC_SIZE + 1) as u64;
    let in_path: &str = path.as_ref().to_str().ok_or("Invalid path format".to_owned())?;
    let mut out_path: String = if let Some(out_without_suffix) = in_path.strip_suffix(ENCRYPTED_FILE_SUFFIX) {
        out_without_suffix.to_string()
    } else {
        in_path.to_owned() + DECRYPTED_FILE_SUFFIX
    };
    out_path += TMP_FILE_SUFFIX;
    let mut out_file = File::create(&out_path)?;

    let mut input_file = File::open(path)?;
    if input_file.metadata()?.len() < MIN_FILE_SIZE {
        Err("File does not exist".to_owned())?;
    }

    let mut header_bytes = [0u8; HEADER_LEN];
    input_file.read(&mut header_bytes)?;
    let input_file_size: u64 = input_file.metadata()?.len();
    let header = Header::try_from(header_bytes)?;

    monitor.on_key_derivation_started();
    let hash: [u8; DERIVED_HASH_LEN] = key_derivation::derive_with(&header.kdf_salt, 
                                                                   password.as_bytes());
    monitor.on_decryption_started();
    let (key, control_bytes) = key_derivation::split_hash(&hash)?;
    if &header.control_bytes != control_bytes {
        Err("Control bytes do not match".to_owned())?
    }

    let secret_key = SecretKey::from_slice(key)?;
    let stream_nonce = streaming::Nonce::from_slice(&header.cipher_nonce)?;
    let mut stream = StreamXChaCha20Poly1305::new(&secret_key, &stream_nonce);

    let mut chunk_with_adata = vec![0u8; ORION_TAG_SIZE + CHUNK_SIZE + MAC_SIZE];
    let mut out_chunk = vec![0u8; CHUNK_SIZE];
    let mut loaded_bytes_size: u64 = 0;
    loop {
        let bytes_count: usize = input_file.read(&mut chunk_with_adata)?;
        if bytes_count == 0 {
            break;
        }
        loaded_bytes_size += bytes_count as u64;
        println!("LOADED BYTES SIZE: {}", loaded_bytes_size); ////
        monitor.on_progress((loaded_bytes_size as f64 / input_file_size as f64) as f32);
        println!("PROGRESS IN FILE.RS: {}", (loaded_bytes_size as f64 / input_file_size as f64) as f32); ////
        stream.open_chunk(&chunk_with_adata[0..bytes_count], None, &mut out_chunk)?;
        let decrypted_chunk_size: usize = bytes_count - ORION_TAG_SIZE - MAC_SIZE;
        out_file.write(&out_chunk[0..decrypted_chunk_size])?;
    }
    mem::drop(out_file);
    if let Some(err) = out_path
        .strip_suffix(TMP_FILE_SUFFIX)
        .and_then(|out_path_without_suffix| fs::rename(&out_path, out_path_without_suffix).err()) 
    {
        dbg!(err);
    }
    Ok(())
}

#[test]
fn t_encrypt_file() -> Result<(), Box<dyn Error>> {
    let path = "sandbox/slovo-o-polku-igoreve_Jekaterinskaja-kopija.djvu";
    let mut monitor = ProgressMonitor::default();
    encrypt_file(path, "standard-password", &mut monitor)?;
    Ok(())
}

#[test]
fn t_decrypt_file() -> Result<(), Box<dyn Error>> {
    let path = "sandbox/slovo-o-polku-igoreve_Jekaterinskaja-kopija.djvu.enc";
    let mut monitor = ProgressMonitor::default();
    decrypt_file(path, "standard-password", &mut monitor)?;
    Ok(())
}
