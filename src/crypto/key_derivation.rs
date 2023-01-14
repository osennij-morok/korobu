use std::{error::Error, time::Instant};

use argon2::{Algorithm, Version, Params, Argon2};

use super::gen_rand;

pub const DERIVED_HASH_LEN: usize = 64;
pub const SALT_LEN: usize = 16;

pub fn _derive(password: &[u8]) -> ([u8; DERIVED_HASH_LEN], [u8; SALT_LEN]) {
    let hasher: Argon2 = hasher();

    let mut salt = [0u8; SALT_LEN];
    let mut hash = [0u8; DERIVED_HASH_LEN];

    gen_rand(&mut salt);
    hasher.hash_password_into(password, &salt, &mut hash).unwrap();

    (hash, salt)
}

pub fn derive_with(salt: &[u8; SALT_LEN], password: &[u8]) -> [u8; DERIVED_HASH_LEN] {
    let hasher: Argon2 = hasher();
    let mut hash = [0u8; DERIVED_HASH_LEN];
    println!("HASHING...");
    let before = Instant::now();
    hasher.hash_password_into(password, salt, &mut hash).unwrap();
    println!("TOOK {} ms", (Instant::now() - before).as_millis());
    hash
}

pub(super) type Hash<'a> = (&'a[u8; DERIVED_HASH_LEN / 2], &'a[u8; DERIVED_HASH_LEN / 2]);

pub fn split_hash(hash: &[u8; DERIVED_HASH_LEN]) -> Result<Hash, Box<dyn Error>> {
    let (key, control_bytes) = hash.split_at(DERIVED_HASH_LEN / 2);
    Ok((key.try_into()?, control_bytes.try_into()?))
}

pub fn gen_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    gen_rand(&mut salt);
    salt
}

fn hasher() -> Argon2<'static> {
    // 3300 ms
    // Params::DEFAULT_M_COST
    const MEMORY: u32 = 500_000; // 500 Mb
    // const MEMORY: u32 = 10_000; // 10 Mb
    const ITERATIONS: u32 = 6;
    const PARALLELISM: u32 = 8;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, 
                Params::new(MEMORY, 
                            ITERATIONS, 
                            PARALLELISM, 
                            Some(DERIVED_HASH_LEN)).unwrap())
}
