#![windows_subsystem = "windows"]
#![feature(iter_array_chunks)]
#![feature(box_syntax)]

use log::info;

mod gui;
mod crypto;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    gui::run().await
}
