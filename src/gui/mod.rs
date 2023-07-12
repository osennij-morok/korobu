use std::{time::Duration, path::PathBuf, io::Cursor};

use eframe::{
    egui::{self, Ui, RichText}, 
    epaint::FontId, 
    CreationContext, IconData
};
use image::ImageFormat;
use tokio::sync::mpsc::{Sender, Receiver, self};

use crate::crypto::{
    self, file::{ProgressMonitor, ProgressMonitorMessage}
};

use self::{files_mode::FilesMode, text_mode::TextMode};

const FONT_SIZE: f32 = 25.;
const APP_NAME: &str = "Korobu";

mod files_mode;
mod text_mode;

#[derive(Debug)]
enum UiMessage {
    EncryptText {
        plaintext: String,
        password: String
    },
    DecryptText {
        ciphertext: String,
        password: String
    },
    EncryptFile {
        path: PathBuf,
        password: String
    },
    DecryptFile {
        path: PathBuf,
        password: String
    }
}

#[derive(Debug)]
enum TextHandlerMessage {
    Loading,
    Result(String),
}

#[derive(Debug)]
enum FilesHandlerMessage {
    ComputingKey,
    StartEncryption,
    StartDecryption,
    Progress(f32),
    Finish,
    EncryptionFailure,
    DecryptionFailure
}

#[derive(Debug, Default)]
enum Mode {
    #[default]
    Text,
    Files
}

struct Application {
    input_text: String,
    result_text: String,
    password: String,
    is_loading: bool,
    sending_is_locked: bool,
    mode: Mode,
    files_mode: files_mode::FilesModeData,
    tx: Sender<UiMessage>,
    text_mode_rx: Receiver<TextHandlerMessage>,
    files_mode_rx: Receiver<FilesHandlerMessage>,
}

impl eframe::App for Application {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            let screen_height: f32 = ui.available_height();
            ui.set_height(screen_height);

            //egui::menu::bar(ui, |ui| {
            //    menu_btn("File", ui, |_ui| {
            //        // nothing happens
            //    });
            //    menu_btn("Help", ui, |_ui| {
            //        // nothing happens
            //    });
            //});
            match &self.mode {
                Mode::Text => self.render_text_mode(ui),
                Mode::Files { .. } => self.render_files_mode(ui),
            }   
        });
        ctx.request_repaint();
    }
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let (text_mode_tx, text_mode_rx): (Sender<TextHandlerMessage>, Receiver<_>) 
        = mpsc::channel(2);
    let (files_mode_tx, files_mode_rx): (Sender<FilesHandlerMessage>, Receiver<_>) 
        = mpsc::channel(1000);
    let (ui_tx, mut ui_rx): (Sender<UiMessage>, Receiver<_>) 
        = mpsc::channel(1);

    // handler thread
    tokio::spawn(async move {
        loop {
            if let Some(message) = ui_rx.recv().await {
                on_ui_message(message, &text_mode_tx, &files_mode_tx).await;
            } else {
                break;
            }
        }
    });

    let options = eframe::NativeOptions {
        maximized: true,
        icon_data: Some(load_icon()),
        ..Default::default()
    };

    eframe::run_native(APP_NAME, 
                       options, 
                       Box::new(move |cc: &CreationContext| 
                                Box::new(
                                    Application::new(
                                        cc, ui_tx, text_mode_rx, files_mode_rx))));
    Ok(())
}

impl Application {
    fn new(_cc: &eframe::CreationContext<'_>, 
           tx: Sender<UiMessage>, 
           text_mode_rx: Receiver<TextHandlerMessage>,
           files_mode_rx: Receiver<FilesHandlerMessage>) -> Self {
        Self {
            input_text:        Default::default(),
            result_text:       Default::default(),
            password:          Default::default(),
            mode:              Default::default(),
            files_mode:        Default::default(),
            is_loading:        false,
            sending_is_locked: false,
            tx,
            text_mode_rx,
            files_mode_rx,
        }
    }

    fn on_encrypt_text_btn_clicked(&mut self) {
        self.sending_is_locked = true;
        if let Err(err) = self.tx
            .try_send(UiMessage::EncryptText {
                plaintext: self.input_text.clone(),
                password: self.password.clone()
            }) 
        {
            dbg!(err);
        }
    }

    fn on_decrypt_text_btn_clicked(&mut self) {
        self.sending_is_locked = true;
        if let Err(err) = self.tx
            .try_send(UiMessage::DecryptText {
                ciphertext: self.input_text.clone(),
                password: self.password.clone()
            }) 
        {
            dbg!(err);
        }
    }

    fn on_encrypt_file_btn_clicked(&mut self) {
        self.sending_is_locked = true;
        let path: PathBuf = if let Some(path) = self.files_mode.chosen_file() {
            path.to_owned()
        } else {
            return
        };
        if let Err(err) = self.tx
            .try_send(UiMessage::EncryptFile {
                path,
                password: self.password.clone()
            }) 
        {
            dbg!(err);
        }
    }

    fn on_decrypt_btn_file_clicked(&mut self) {
        self.sending_is_locked = true;
        let path: PathBuf = if let Some(path) = self.files_mode.chosen_file() {
            path.to_owned()
        } else {
            return
        };
        if let Err(err) = self.tx
            .try_send(UiMessage::DecryptFile {
                path,
                password: self.password.clone()
            }) 
        {
            dbg!(err);
        }
    }

    fn to_files_mode(&mut self) {
        self.mode = Mode::Files;
    }

    fn to_text_mode(&mut self) {
        self.mode = Mode::Text;
    }
}

async fn on_ui_message(message: UiMessage, text_mode_tx: &Sender<TextHandlerMessage>,
                                           files_mode_tx: &Sender<FilesHandlerMessage>) {
    match message {
        UiMessage::EncryptText { plaintext, password } => {
            if let Err(_) = text_mode_tx.try_send(TextHandlerMessage::Loading) {};
            let result: String = match crypto::crypto_box(&plaintext, &password) {
                Ok(result) => result,
                Err(err) => {
                    println!("ERROR:");
                    println!("{}", err);
                    println!();
                    "<<Ошибка шифрования>>".into()
                },
            };
            if let Err(err) = text_mode_tx.send_timeout(
                TextHandlerMessage::Result(result), Duration::from_secs(15)).await 
            {
                dbg!(err);
            };
        },
        UiMessage::DecryptText { ciphertext, password } => {
            if let Err(_) = text_mode_tx.try_send(TextHandlerMessage::Loading) {};
            let result: String = match crypto::crypto_box_open(&ciphertext, &password) {
                Ok(result) => result,
                Err(err) => {
                    println!("ERROR:");
                    println!("{}", err);
                    println!();
                    "<<Ошибка расшифровки>>".into()
                },
            }; 
            if let Err(err) = text_mode_tx.send_timeout(
                TextHandlerMessage::Result(result), Duration::from_secs(15)).await 
            {
                dbg!(err);
            };
        },
        UiMessage::EncryptFile { path, password } => {
            let mut monitor = ProgressMonitor::default();
            let subscriber_tx: Sender<FilesHandlerMessage> = files_mode_tx.clone();
            monitor.subscribe(move |message: ProgressMonitorMessage| {
                let message: FilesHandlerMessage = map_message(message);
                if let Err(err) = subscriber_tx.try_send(message) {
                    dbg!(err);
                };
            });
            if crypto::file::encrypt_file(path, &password, &mut monitor).is_err() {
                if let Err(_) = files_mode_tx.send(FilesHandlerMessage::EncryptionFailure).await {};
            } else {
                if let Err(_) = files_mode_tx.send(FilesHandlerMessage::Finish).await {};
            }
        },
        UiMessage::DecryptFile { path, password } => {
            let mut monitor = ProgressMonitor::default();
            let subscriber_tx: Sender<FilesHandlerMessage> = files_mode_tx.clone();
            monitor.subscribe(move |message: ProgressMonitorMessage| {
                let message: FilesHandlerMessage = map_message(message);
                if let Err(err) = subscriber_tx.try_send(message) {
                    dbg!(err);
                };
            });
            //if let Err(e) = crypto::file::decrypt_file(path, &password, &mut monitor) {
            if crypto::file::decrypt_file(path, &password, &mut monitor).is_err() {
                //println!("Error:");
                //dbg!(&e);
                if let Err(_) = files_mode_tx.send(FilesHandlerMessage::DecryptionFailure).await {};                            
            } else {
                println!("SUCCESSFULLY DECRYPTED");
                if let Err(_) = files_mode_tx.send(FilesHandlerMessage::Finish).await {};
            }
        },

    };
}

fn map_message(message: ProgressMonitorMessage) -> FilesHandlerMessage {
    use FilesHandlerMessage::*;
    match message {
        ProgressMonitorMessage::KeyDerivationStarted => ComputingKey,
        ProgressMonitorMessage::EncryptionStarted => StartEncryption,
        ProgressMonitorMessage::DecryptionStarted => StartDecryption,
        ProgressMonitorMessage::Progress(progress) => Progress(progress),
    }
}

fn btn(text: &str, ui: &mut Ui) -> egui::Response {
    ui.button(RichText::new(text)
        .font(FontId::proportional(20.)))
}

fn menu_btn<R, F>(text: &str, ui: &mut Ui, add_contents: F) -> egui::InnerResponse<Option<R>> 
where 
    F: FnOnce(&mut Ui) -> R 
{
    let text = RichText::new(text)
        .font(FontId::proportional(15.));
    ui.menu_button(text, add_contents)
}

fn load_icon() -> IconData {
    let icon_bytes: &[u8] = include_bytes!("../../icons/icon-32.png");
    let icon_reader = Cursor::new(icon_bytes);
    let img: image::DynamicImage = image::load(icon_reader, ImageFormat::Png)
        .expect("Icon cannot be loaded");
    let rgba: image::RgbaImage = img.into_rgba8();
    IconData {
        rgba: rgba.to_vec(), 
        width: rgba.width(), 
        height: rgba.height() 
    }
}
