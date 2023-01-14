# Korobu

A tool for encryption and decryption written in Rust using [egui](https://github.com/emilk/egui) library for GUI. It works both for text and files.

## Features

This program uses state of the art encryption technologies:

* Argon2 as KDF (key derivation function) for brute-force resistance
* XChaCha20-Poly1305 algorithm for AEAD encryption

## Requirements

* Rust compiler. You can install it with [rustup](https://rustup.rs).

## Compile

```bash
cargo build --release
```
or
```bash
cargo b -r
```

## Run

```bash
cargo run --release
```
or
```bash
cargo r -r
```
